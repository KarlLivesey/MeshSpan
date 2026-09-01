// SPDX-License-Identifier: GPL-2.0-only

//! Canonical self-contained node join invitations.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::secret_text::SECRET_BYTES;
use crate::{JoinGrantId, MeshId, OperationId, PrincipalId, RandomSource};

const PREFIX: &str = "meshspan-join-v2.";
const MAXIMUM_ENDPOINT_BYTES: usize = 512;
const CERTIFICATE_FINGERPRINT_BYTES: usize = 32;
const SECRET_DIGEST_DOMAIN: &[u8] = b"meshspan.join-grant-secret.v2\0";
const ISSUED_GRANT_ID_DOMAIN: &[u8] = b"meshspan.enrolment.issued-join-grant-id.v2\0";
const ISSUED_SECRET_DOMAIN: &[u8] = b"meshspan.enrolment.issued-join-grant-secret.v2\0";

/// Maximum byte length of one canonical encoded join invitation.
pub const MAXIMUM_ENCODED_JOIN_GRANT_LENGTH: usize = PREFIX.len()
    + (16 * 2)
    + 1
    + (16 * 2)
    + 1
    + (SECRET_BYTES * 2)
    + 1
    + (CERTIFICATE_FINGERPRINT_BYTES * 2)
    + 1
    + (MAXIMUM_ENDPOINT_BYTES * 2);

/// Secret-bearing administrator-issued node join invitation.
///
/// The invitation carries the target mesh, one HTTPS origin and the exact issuing gateway leaf
/// fingerprint so a headless daemon needs no separate discovery or unsafe TLS override. It
/// deliberately implements neither `Debug` nor `Display`.
pub struct JoinGrantBundle {
    mesh_id: MeshId,
    join_grant_id: JoinGrantId,
    secret: Zeroizing<[u8; SECRET_BYTES]>,
    enrolment_endpoint: String,
    gateway_certificate_fingerprint: [u8; CERTIFICATE_FINGERPRINT_BYTES],
}

impl JoinGrantBundle {
    /// Generates an independent mesh-bound join invitation from cryptographic entropy.
    ///
    /// # Errors
    ///
    /// Rejects unavailable entropy, invalid endpoint/pin input, a nil identifier or an all-zero
    /// secret.
    pub fn generate(
        mesh_id: MeshId,
        enrolment_endpoint: &str,
        gateway_certificate_fingerprint: [u8; CERTIFICATE_FINGERPRINT_BYTES],
        random: &mut impl RandomSource,
    ) -> Result<Self, JoinGrantBundleError> {
        let mut join_grant_id = [0_u8; 16];
        let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
        random
            .fill_bytes(&mut join_grant_id)
            .map_err(|_| JoinGrantBundleError::EntropyUnavailable)?;
        random
            .fill_bytes(secret.as_mut())
            .map_err(|_| JoinGrantBundleError::EntropyUnavailable)?;
        Self::from_parts(
            mesh_id.as_bytes(),
            join_grant_id,
            secret,
            enrolment_endpoint,
            gateway_certificate_fingerprint,
        )
    }

    /// Derives one exact lost-response-replayable invitation without persisting its plaintext.
    ///
    /// # Errors
    ///
    /// Rejects invalid derived identity, secret, mesh, endpoint or certificate-pin material.
    pub fn derive_issued(
        issuance_key: &JoinGrantIssuanceKey,
        mesh_id: MeshId,
        principal_id: PrincipalId,
        operation_id: OperationId,
        enrolment_endpoint: &str,
        gateway_certificate_fingerprint: [u8; CERTIFICATE_FINGERPRINT_BYTES],
    ) -> Result<Self, JoinGrantBundleError> {
        let mut join_grant_id = issuance_key.derive(
            ISSUED_GRANT_ID_DOMAIN,
            mesh_id,
            principal_id,
            operation_id,
            enrolment_endpoint,
            gateway_certificate_fingerprint,
        )?;
        join_grant_id[6] = (join_grant_id[6] & 0x0f) | 0x40;
        join_grant_id[8] = (join_grant_id[8] & 0x3f) | 0x80;
        let secret = Zeroizing::new(issuance_key.derive(
            ISSUED_SECRET_DOMAIN,
            mesh_id,
            principal_id,
            operation_id,
            enrolment_endpoint,
            gateway_certificate_fingerprint,
        )?);
        Self::from_parts(
            mesh_id.as_bytes(),
            join_grant_id[..16]
                .try_into()
                .map_err(|_| JoinGrantBundleError::InvalidEncoding)?,
            secret,
            enrolment_endpoint,
            gateway_certificate_fingerprint,
        )
    }

    /// Parses one exact lowercase canonical join invitation.
    ///
    /// # Errors
    ///
    /// Rejects another version, non-canonical hex, zero values, an invalid HTTPS origin, extra
    /// fields and input beyond the compiled bound.
    pub fn parse(value: &str) -> Result<Self, JoinGrantBundleError> {
        if value.len() > MAXIMUM_ENCODED_JOIN_GRANT_LENGTH {
            return Err(JoinGrantBundleError::InvalidEncoding);
        }
        let payload = value
            .strip_prefix(PREFIX)
            .ok_or(JoinGrantBundleError::InvalidEncoding)?;
        let mut fields = payload.split('.');
        let mesh_id = decode_fixed::<16>(next_field(&mut fields)?)?;
        let join_grant_id = decode_fixed::<16>(next_field(&mut fields)?)?;
        let secret = Zeroizing::new(decode_fixed::<SECRET_BYTES>(next_field(&mut fields)?)?);
        let certificate = decode_fixed::<CERTIFICATE_FINGERPRINT_BYTES>(next_field(&mut fields)?)?;
        let endpoint = decode_variable(next_field(&mut fields)?, MAXIMUM_ENDPOINT_BYTES)?;
        if fields.next().is_some() {
            return Err(JoinGrantBundleError::InvalidEncoding);
        }
        let endpoint =
            String::from_utf8(endpoint).map_err(|_| JoinGrantBundleError::InvalidEncoding)?;
        Self::from_parts(mesh_id, join_grant_id, secret, &endpoint, certificate)
    }

    /// Returns the exact target mesh identity.
    #[must_use]
    pub const fn mesh_id(&self) -> MeshId {
        self.mesh_id
    }

    /// Returns the stable public grant identity included in the encoded value.
    #[must_use]
    pub const fn join_grant_id(&self) -> JoinGrantId {
        self.join_grant_id
    }

    /// Returns the canonical HTTPS origin contacted for initial enrolment.
    #[must_use]
    pub fn enrolment_endpoint(&self) -> &str {
        &self.enrolment_endpoint
    }

    /// Returns the exact issuing gateway leaf-certificate fingerprint.
    #[must_use]
    pub const fn gateway_certificate_fingerprint(&self) -> [u8; 32] {
        self.gateway_certificate_fingerprint
    }

    /// Returns the mesh- and grant-bound verifier persisted in replicated metadata.
    #[must_use]
    pub fn secret_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(SECRET_DIGEST_DOMAIN);
        digest.update(self.mesh_id.as_bytes());
        digest.update(self.join_grant_id.as_bytes());
        digest.update(self.secret.as_ref());
        digest.finalize().into()
    }

    /// Explicitly exposes the secret-bearing text for its one-time output or enrolment boundary.
    #[must_use]
    pub fn expose_encoded(&self) -> Zeroizing<String> {
        let endpoint = self.enrolment_endpoint.as_bytes();
        let capacity = PREFIX.len()
            + 4
            + ((16 + 16 + SECRET_BYTES + CERTIFICATE_FINGERPRINT_BYTES + endpoint.len()) * 2);
        let mut encoded = Zeroizing::new(String::with_capacity(capacity));
        encoded.push_str(PREFIX);
        append_hex(&mut encoded, &self.mesh_id.as_bytes());
        encoded.push('.');
        append_hex(&mut encoded, &self.join_grant_id.as_bytes());
        encoded.push('.');
        append_hex(&mut encoded, self.secret.as_ref());
        encoded.push('.');
        append_hex(&mut encoded, &self.gateway_certificate_fingerprint);
        encoded.push('.');
        append_hex(&mut encoded, endpoint);
        encoded
    }

    fn from_parts(
        mesh_id: [u8; 16],
        join_grant_id: [u8; 16],
        secret: Zeroizing<[u8; SECRET_BYTES]>,
        enrolment_endpoint: &str,
        gateway_certificate_fingerprint: [u8; CERTIFICATE_FINGERPRINT_BYTES],
    ) -> Result<Self, JoinGrantBundleError> {
        let mesh_id =
            MeshId::from_bytes(mesh_id).map_err(|_| JoinGrantBundleError::InvalidEncoding)?;
        let join_grant_id = JoinGrantId::from_bytes(join_grant_id)
            .map_err(|_| JoinGrantBundleError::InvalidEncoding)?;
        if secret.as_ref() == [0; SECRET_BYTES]
            || gateway_certificate_fingerprint == [0; CERTIFICATE_FINGERPRINT_BYTES]
            || !valid_https_origin(enrolment_endpoint)
        {
            return Err(JoinGrantBundleError::InvalidEncoding);
        }
        Ok(Self {
            mesh_id,
            join_grant_id,
            secret,
            enrolment_endpoint: enrolment_endpoint.to_owned(),
            gateway_certificate_fingerprint,
        })
    }
}

/// Mesh-wide non-exportable key for exactly replayable join-grant issuance.
///
/// It implements neither `Clone`, `Copy`, `Debug` nor `Display` and clears its bytes on drop.
pub struct JoinGrantIssuanceKey(Zeroizing<[u8; 32]>);

impl JoinGrantIssuanceKey {
    /// Takes ownership of one loaded non-zero issuance key.
    ///
    /// # Errors
    ///
    /// Rejects the reserved all-zero value.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, JoinGrantIssuanceKeyError> {
        if bytes == [0; 32] {
            Err(JoinGrantIssuanceKeyError)
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }

    fn derive(
        &self,
        domain: &[u8],
        mesh_id: MeshId,
        principal_id: PrincipalId,
        operation_id: OperationId,
        enrolment_endpoint: &str,
        gateway_certificate_fingerprint: [u8; CERTIFICATE_FINGERPRINT_BYTES],
    ) -> Result<[u8; 32], JoinGrantBundleError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref())
            .map_err(|_| JoinGrantBundleError::InvalidEncoding)?;
        mac.update(domain);
        mac.update(&mesh_id.as_bytes());
        mac.update(&principal_id.as_bytes());
        mac.update(&operation_id.as_bytes());
        mac.update(
            &u64::try_from(enrolment_endpoint.len())
                .map_err(|_| JoinGrantBundleError::InvalidEncoding)?
                .to_be_bytes(),
        );
        mac.update(enrolment_endpoint.as_bytes());
        mac.update(&gateway_certificate_fingerprint);
        let output: [u8; 32] = mac.finalize().into_bytes().into();
        if output == [0; 32] {
            Err(JoinGrantBundleError::InvalidEncoding)
        } else {
            Ok(output)
        }
    }
}

/// Invalid non-exportable join-grant issuance key.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("join-grant issuance key is invalid")]
pub struct JoinGrantIssuanceKeyError;

fn next_field<'a>(
    fields: &mut impl Iterator<Item = &'a str>,
) -> Result<&'a str, JoinGrantBundleError> {
    fields.next().ok_or(JoinGrantBundleError::InvalidEncoding)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], JoinGrantBundleError> {
    let decoded = decode_variable(value, N)?;
    decoded
        .try_into()
        .map_err(|_| JoinGrantBundleError::InvalidEncoding)
}

fn decode_variable(value: &str, maximum: usize) -> Result<Vec<u8>, JoinGrantBundleError> {
    if value.is_empty() || !value.len().is_multiple_of(2) || value.len() > maximum.saturating_mul(2)
    {
        return Err(JoinGrantBundleError::InvalidEncoding);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = decode_nibble(pair[0]).ok_or(JoinGrantBundleError::InvalidEncoding)?;
            let low = decode_nibble(pair[1]).ok_or(JoinGrantBundleError::InvalidEncoding)?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn append_hex(destination: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        destination.push(char::from(HEX[usize::from(byte >> 4)]));
        destination.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

fn valid_https_origin(value: &str) -> bool {
    if value.len() > MAXIMUM_ENDPOINT_BYTES
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return false;
    }
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if authority.is_empty()
        || authority
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@'))
    {
        return false;
    }
    if authority.starts_with('[') {
        return valid_bracketed_address(authority);
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    valid_host(host) && port.is_none_or(valid_port)
}

fn valid_bracketed_address(authority: &str) -> bool {
    let Some(close) = authority.find(']') else {
        return false;
    };
    let host = &authority[1..close];
    let suffix = &authority[close + 1..];
    !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.'))
        && (suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port))
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|value| value != 0)
}

/// Failure to construct or parse node join material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JoinGrantBundleError {
    /// Cryptographic entropy was unavailable.
    #[error("join-grant entropy is unavailable")]
    EntropyUnavailable,
    /// The invitation encoding, mesh, endpoint or pin is invalid.
    #[error("join-grant encoding is invalid")]
    InvalidEncoding,
}

#[cfg(test)]
mod tests {
    use super::{
        JoinGrantBundle, JoinGrantBundleError, JoinGrantIssuanceKey,
        MAXIMUM_ENCODED_JOIN_GRANT_LENGTH,
    };
    use crate::{EntropyError, MeshId, OperationId, PrincipalId, RandomSource};

    #[test]
    fn derived_invitation_replays_exactly_and_separates_operations()
    -> Result<(), JoinGrantBundleError> {
        let issuance_key = JoinGrantIssuanceKey::from_bytes([7; 32])
            .map_err(|_| JoinGrantBundleError::InvalidEncoding)?;
        let mesh_id =
            MeshId::from_bytes([9; 16]).map_err(|_| JoinGrantBundleError::InvalidEncoding)?;
        let principal_id =
            PrincipalId::from_bytes([11; 16]).map_err(|_| JoinGrantBundleError::InvalidEncoding)?;
        let first_operation =
            OperationId::from_bytes([13; 16]).map_err(|_| JoinGrantBundleError::InvalidEncoding)?;
        let second_operation =
            OperationId::from_bytes([14; 16]).map_err(|_| JoinGrantBundleError::InvalidEncoding)?;

        let first = JoinGrantBundle::derive_issued(
            &issuance_key,
            mesh_id,
            principal_id,
            first_operation,
            "https://node-1.meshspan.local:8443",
            [10; 32],
        )?;
        let replay = JoinGrantBundle::derive_issued(
            &issuance_key,
            mesh_id,
            principal_id,
            first_operation,
            "https://node-1.meshspan.local:8443",
            [10; 32],
        )?;
        let second = JoinGrantBundle::derive_issued(
            &issuance_key,
            mesh_id,
            principal_id,
            second_operation,
            "https://node-1.meshspan.local:8443",
            [10; 32],
        )?;

        assert_eq!(
            first.expose_encoded().as_str(),
            replay.expose_encoded().as_str()
        );
        assert_ne!(
            first.expose_encoded().as_str(),
            second.expose_encoded().as_str()
        );
        Ok(())
    }

    #[test]
    fn invitation_round_trips_every_mesh_endpoint_pin_and_secret_field()
    -> Result<(), JoinGrantBundleError> {
        let mesh_id =
            MeshId::from_bytes([9; 16]).map_err(|_| JoinGrantBundleError::InvalidEncoding)?;
        let generated = JoinGrantBundle::generate(
            mesh_id,
            "https://node-1.meshspan.local:8443",
            [10; 32],
            &mut SequentialRandom(1),
        )?;
        let encoded = generated.expose_encoded();
        assert!(encoded.len() <= MAXIMUM_ENCODED_JOIN_GRANT_LENGTH);
        let parsed = JoinGrantBundle::parse(&encoded)?;
        assert_eq!(parsed.mesh_id(), mesh_id);
        assert_eq!(parsed.join_grant_id(), generated.join_grant_id());
        assert_eq!(parsed.secret_digest(), generated.secret_digest());
        assert_eq!(
            parsed.enrolment_endpoint(),
            "https://node-1.meshspan.local:8443"
        );
        assert_eq!(parsed.gateway_certificate_fingerprint(), [10; 32]);
        assert_eq!(parsed.expose_encoded().as_str(), encoded.as_str());
        Ok(())
    }

    #[test]
    fn parser_rejects_changed_fields_and_unsafe_origins() -> Result<(), JoinGrantBundleError> {
        let mesh_id =
            MeshId::from_bytes([9; 16]).map_err(|_| JoinGrantBundleError::InvalidEncoding)?;
        for endpoint in [
            "",
            "http://node-1.meshspan.local",
            "https://NODE-1.meshspan.local",
            "https://user@node-1.meshspan.local",
            "https://node-1.meshspan.local/path",
            "https://node-1.meshspan.local:0",
        ] {
            assert_eq!(
                JoinGrantBundle::generate(mesh_id, endpoint, [10; 32], &mut SequentialRandom(1))
                    .err(),
                Some(JoinGrantBundleError::InvalidEncoding)
            );
        }
        let valid = JoinGrantBundle::generate(
            mesh_id,
            "https://127.0.0.1:8443",
            [10; 32],
            &mut SequentialRandom(1),
        )?;
        for changed in [
            String::new(),
            valid.expose_encoded().to_uppercase(),
            format!("{}.", valid.expose_encoded().as_str()),
            valid
                .expose_encoded()
                .replace("meshspan-join-v2", "meshspan-join-v1"),
        ] {
            assert_eq!(
                JoinGrantBundle::parse(&changed).err(),
                Some(JoinGrantBundleError::InvalidEncoding)
            );
        }
        Ok(())
    }

    #[test]
    fn generation_rejects_failed_zero_or_unpinned_material() -> Result<(), JoinGrantBundleError> {
        let mesh_id =
            MeshId::from_bytes([9; 16]).map_err(|_| JoinGrantBundleError::InvalidEncoding)?;
        assert_eq!(
            JoinGrantBundle::generate(mesh_id, "https://node", [10; 32], &mut FailingRandom).err(),
            Some(JoinGrantBundleError::EntropyUnavailable)
        );
        assert_eq!(
            JoinGrantBundle::generate(mesh_id, "https://node", [10; 32], &mut ZeroRandom).err(),
            Some(JoinGrantBundleError::InvalidEncoding)
        );
        assert_eq!(
            JoinGrantBundle::generate(mesh_id, "https://node", [0; 32], &mut SequentialRandom(1))
                .err(),
            Some(JoinGrantBundleError::InvalidEncoding)
        );
        Ok(())
    }

    struct SequentialRandom(u8);

    impl RandomSource for SequentialRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            for byte in destination {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    struct FailingRandom;

    impl RandomSource for FailingRandom {
        fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError)
        }
    }

    struct ZeroRandom;

    impl RandomSource for ZeroRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(0);
            Ok(())
        }
    }
}
