// SPDX-License-Identifier: GPL-2.0-only

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{DnsName, DnsWireError, TxtValue};

const CLASS_ANY: u16 = 255;
const CLASS_IN: u16 = 1;
const CLASS_NONE: u16 = 254;
const MAXIMUM_DNS_MESSAGE_BYTES: usize = 65_535;
const MAXIMUM_FUDGE_SECONDS: u16 = 3_600;
const MAXIMUM_SECRET_BYTES: usize = 2_048;
const MAXIMUM_TTL_SECONDS: u32 = 86_400;
const TYPE_SOA: u16 = 6;
const TYPE_TSIG: u16 = 250;
const TYPE_TXT: u16 = 16;
const UPDATE_OPCODE: u16 = 5 << 11;

/// Supported modern TSIG algorithms for authenticated DNS updates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TsigAlgorithm {
    /// Full-length HMAC-SHA-256.
    HmacSha256,
    /// Full-length HMAC-SHA-512.
    HmacSha512,
}

impl TsigAlgorithm {
    pub(crate) fn name(self) -> Result<DnsName, DnsWireError> {
        DnsName::new(match self {
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha512 => "hmac-sha512",
        })
    }

    fn sign(self, secret: &[u8], message: &[u8]) -> Result<Vec<u8>, Rfc2136RequestError> {
        match self {
            Self::HmacSha256 => {
                let mut hmac = Hmac::<Sha256>::new_from_slice(secret)
                    .map_err(|_| Rfc2136RequestError::Signing)?;
                hmac.update(message);
                Ok(hmac.finalize().into_bytes().to_vec())
            }
            Self::HmacSha512 => {
                let mut hmac = Hmac::<Sha512>::new_from_slice(secret)
                    .map_err(|_| Rfc2136RequestError::Signing)?;
                hmac.update(message);
                Ok(hmac.finalize().into_bytes().to_vec())
            }
        }
    }

    pub(crate) fn verify(
        self,
        secret: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Rfc2136RequestError> {
        match self {
            Self::HmacSha256 => {
                let mut hmac = Hmac::<Sha256>::new_from_slice(secret)
                    .map_err(|_| Rfc2136RequestError::Signing)?;
                hmac.update(message);
                hmac.verify_slice(signature)
                    .map_err(|_| Rfc2136RequestError::Signing)
            }
            Self::HmacSha512 => {
                let mut hmac = Hmac::<Sha512>::new_from_slice(secret)
                    .map_err(|_| Rfc2136RequestError::Signing)?;
                hmac.update(message);
                hmac.verify_slice(signature)
                    .map_err(|_| Rfc2136RequestError::Signing)
            }
        }
    }
}

/// Non-clonable, zeroising TSIG key material.
pub struct Rfc2136TsigKey {
    name: DnsName,
    algorithm: TsigAlgorithm,
    secret: Zeroizing<Vec<u8>>,
}

impl Rfc2136TsigKey {
    /// Creates one bounded TSIG key.
    ///
    /// # Errors
    ///
    /// Rejects malformed key names and secrets outside the supported bound.
    pub fn new(
        name: &str,
        algorithm: TsigAlgorithm,
        secret: Vec<u8>,
    ) -> Result<Self, Rfc2136RequestError> {
        if !(16..=MAXIMUM_SECRET_BYTES).contains(&secret.len()) {
            return Err(Rfc2136RequestError::InvalidKey);
        }
        Ok(Self {
            name: DnsName::new(name)?,
            algorithm,
            secret: Zeroizing::new(secret),
        })
    }

    pub(crate) fn name(&self) -> &DnsName {
        &self.name
    }

    pub(crate) const fn algorithm(&self) -> TsigAlgorithm {
        self.algorithm
    }

    pub(crate) fn secret(&self) -> &[u8] {
        &self.secret
    }
}

/// Exact idempotent TXT mutation represented by one RFC 2136 update RR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxtUpdate {
    /// Add an exact TXT RR; an existing duplicate is ignored by the primary server.
    Publish {
        /// Cache lifetime for the published challenge value.
        ttl_seconds: u32,
    },
    /// Delete only the exact TXT RR supplied in this request.
    Remove,
}

/// Validated RFC 2136 TXT request awaiting TSIG authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rfc2136Request {
    id: u16,
    zone: DnsName,
    owner: DnsName,
    value: TxtValue,
    update: TxtUpdate,
    signed_at_seconds: u64,
    fudge_seconds: u16,
}

impl Rfc2136Request {
    /// Creates one bounded update using an explicit trusted time value.
    ///
    /// # Errors
    ///
    /// Rejects zero identities, out-of-zone owners, invalid TTLs, excessive time values and
    /// malformed DNS names or TXT values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u16,
        zone: &str,
        owner: &str,
        value: &[u8],
        update: TxtUpdate,
        signed_at_seconds: u64,
        fudge_seconds: u16,
    ) -> Result<Self, Rfc2136RequestError> {
        let zone = DnsName::new(zone)?;
        let owner = DnsName::new(owner)?;
        let owner_in_zone = owner == zone
            || owner
                .as_str()
                .strip_suffix(zone.as_str())
                .is_some_and(|prefix| prefix.ends_with('.'));
        let ttl_valid = match update {
            TxtUpdate::Publish { ttl_seconds } => (1..=MAXIMUM_TTL_SECONDS).contains(&ttl_seconds),
            TxtUpdate::Remove => true,
        };
        if id == 0
            || !owner_in_zone
            || !ttl_valid
            || signed_at_seconds > 0x0000_ffff_ffff_ffff
            || !(1..=MAXIMUM_FUDGE_SECONDS).contains(&fudge_seconds)
        {
            return Err(Rfc2136RequestError::InvalidRequest);
        }
        Ok(Self {
            id,
            zone,
            owner,
            value: TxtValue::new(value)?,
            update,
            signed_at_seconds,
            fudge_seconds,
        })
    }

    /// Signs and encodes the complete request without copying key material into the result.
    ///
    /// # Errors
    ///
    /// Fails if a bounded field cannot be represented or the HMAC implementation rejects the key.
    pub fn sign(&self, key: &Rfc2136TsigKey) -> Result<SignedRfc2136Request, Rfc2136RequestError> {
        let unsigned = self.unsigned_message()?;
        let variables = self.tsig_variables(key, 0, &[])?;
        let mut authenticated = Vec::with_capacity(unsigned.len() + variables.len());
        authenticated.extend_from_slice(&unsigned);
        authenticated.extend_from_slice(&variables);
        let mac = key.algorithm.sign(&key.secret, &authenticated)?;
        let mut message = unsigned;
        message[10..12].copy_from_slice(&1_u16.to_be_bytes());
        append_tsig_record(&mut message, self, key, &mac)?;
        if message.len() > MAXIMUM_DNS_MESSAGE_BYTES {
            return Err(Rfc2136RequestError::Capacity);
        }
        Ok(SignedRfc2136Request {
            message,
            request_mac: mac,
            id: self.id,
        })
    }

    fn unsigned_message(&self) -> Result<Vec<u8>, Rfc2136RequestError> {
        let mut output = Vec::with_capacity(512);
        output.extend_from_slice(&self.id.to_be_bytes());
        output.extend_from_slice(&UPDATE_OPCODE.to_be_bytes());
        output.extend_from_slice(&1_u16.to_be_bytes());
        output.extend_from_slice(&0_u16.to_be_bytes());
        output.extend_from_slice(&1_u16.to_be_bytes());
        output.extend_from_slice(&0_u16.to_be_bytes());
        self.zone.encode(&mut output)?;
        output.extend_from_slice(&TYPE_SOA.to_be_bytes());
        output.extend_from_slice(&CLASS_IN.to_be_bytes());
        self.owner.encode(&mut output)?;
        output.extend_from_slice(&TYPE_TXT.to_be_bytes());
        match self.update {
            TxtUpdate::Publish { ttl_seconds } => {
                output.extend_from_slice(&CLASS_IN.to_be_bytes());
                output.extend_from_slice(&ttl_seconds.to_be_bytes());
            }
            TxtUpdate::Remove => {
                output.extend_from_slice(&CLASS_NONE.to_be_bytes());
                output.extend_from_slice(&0_u32.to_be_bytes());
            }
        }
        let value_length = u16::try_from(self.value.as_bytes().len() + 1)
            .map_err(|_| Rfc2136RequestError::Capacity)?;
        output.extend_from_slice(&value_length.to_be_bytes());
        output.push(
            u8::try_from(self.value.as_bytes().len()).map_err(|_| Rfc2136RequestError::Capacity)?,
        );
        output.extend_from_slice(self.value.as_bytes());
        Ok(output)
    }

    fn tsig_variables(
        &self,
        key: &Rfc2136TsigKey,
        error: u16,
        other: &[u8],
    ) -> Result<Vec<u8>, Rfc2136RequestError> {
        let mut output = Vec::with_capacity(128);
        key.name.encode(&mut output)?;
        output.extend_from_slice(&CLASS_ANY.to_be_bytes());
        output.extend_from_slice(&0_u32.to_be_bytes());
        key.algorithm.name()?.encode(&mut output)?;
        append_time(&mut output, self.signed_at_seconds);
        output.extend_from_slice(&self.fudge_seconds.to_be_bytes());
        output.extend_from_slice(&error.to_be_bytes());
        output.extend_from_slice(
            &u16::try_from(other.len())
                .map_err(|_| Rfc2136RequestError::Capacity)?
                .to_be_bytes(),
        );
        output.extend_from_slice(other);
        Ok(output)
    }
}

/// Complete signed update plus retained non-secret transaction authentication state.
pub struct SignedRfc2136Request {
    message: Vec<u8>,
    request_mac: Vec<u8>,
    id: u16,
}

impl SignedRfc2136Request {
    /// Returns the complete TCP payload, excluding its two-byte frame length.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.message
    }

    /// Returns the non-secret request MAC required to authenticate the matching response.
    #[must_use]
    pub fn request_mac(&self) -> &[u8] {
        &self.request_mac
    }

    /// Returns the original DNS transaction identity.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }
}

fn append_tsig_record(
    output: &mut Vec<u8>,
    request: &Rfc2136Request,
    key: &Rfc2136TsigKey,
    mac: &[u8],
) -> Result<(), Rfc2136RequestError> {
    key.name.encode(output)?;
    output.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    output.extend_from_slice(&CLASS_ANY.to_be_bytes());
    output.extend_from_slice(&0_u32.to_be_bytes());
    let algorithm = key.algorithm.name()?;
    let rdata_length = encoded_name_length(&algorithm)
        .checked_add(16)
        .and_then(|length| length.checked_add(mac.len()))
        .ok_or(Rfc2136RequestError::Capacity)?;
    output.extend_from_slice(
        &u16::try_from(rdata_length)
            .map_err(|_| Rfc2136RequestError::Capacity)?
            .to_be_bytes(),
    );
    algorithm.encode(output)?;
    append_time(output, request.signed_at_seconds);
    output.extend_from_slice(&request.fudge_seconds.to_be_bytes());
    output.extend_from_slice(
        &u16::try_from(mac.len())
            .map_err(|_| Rfc2136RequestError::Capacity)?
            .to_be_bytes(),
    );
    output.extend_from_slice(mac);
    output.extend_from_slice(&request.id.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    Ok(())
}

fn encoded_name_length(name: &DnsName) -> usize {
    name.as_str().len() + 2
}

fn append_time(output: &mut Vec<u8>, seconds: u64) {
    output.extend_from_slice(&seconds.to_be_bytes()[2..]);
}

/// Closed request construction failure that never contains key material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum Rfc2136RequestError {
    /// TSIG key name or secret is invalid.
    #[error("RFC 2136 TSIG key is invalid")]
    InvalidKey,
    /// Update identity, owner, time, TTL or fudge is invalid.
    #[error("RFC 2136 request is invalid")]
    InvalidRequest,
    /// Encoded request exceeds a protocol bound.
    #[error("RFC 2136 request exceeds its capacity")]
    Capacity,
    /// HMAC construction failed closed.
    #[error("RFC 2136 request signing failed")]
    Signing,
    /// A shared DNS wire value was invalid.
    #[error("RFC 2136 DNS value is invalid")]
    Wire(#[from] DnsWireError),
}
