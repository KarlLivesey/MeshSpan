// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated node-local state for restart-safe TOTP registration.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshspan_domain::{
    AuthenticationChallengeId, AuthenticationMethodId, OperationId, PrincipalId, RandomSource,
    Revision, SessionId, UnixMicros,
};
use meshspan_metadata::ProtectedAuthenticationState;
use thiserror::Error;
use zeroize::Zeroizing;

const FORMAT_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const SECRET_BYTES: usize = 20;
const MAXIMUM_TEXT_BYTES: usize = 512;
const MAXIMUM_ENVELOPE_BYTES: usize = 4_096;
const AAD_DOMAIN: &[u8] = b"meshspan.authentication.totp-registration.v1\0";

/// Node-local key protecting unfinished TOTP registration ceremonies.
///
/// This key is deliberately separate from the mesh-wide envelope key. It implements neither
/// `Clone`, `Copy`, `Debug` nor `Display`, and clears its bytes on drop.
pub struct TotpCeremonyKey(Zeroizing<[u8; 32]>);

impl TotpCeremonyKey {
    /// Takes ownership of one non-zero key loaded from protected daemon state.
    ///
    /// # Errors
    ///
    /// Rejects the reserved all-zero value.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, TotpRegistrationStateError> {
        if bytes == [0; 32] {
            Err(TotpRegistrationStateError::InvalidKey)
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }
}

pub(crate) struct FrozenTotpRegistrationState {
    pub(crate) secret: Zeroizing<[u8; SECRET_BYTES]>,
    pub(crate) secret_ciphertext: Vec<u8>,
    pub(crate) method_id: AuthenticationMethodId,
    pub(crate) principal_id: PrincipalId,
    pub(crate) session_id: SessionId,
    pub(crate) identity_revision: Revision,
    pub(crate) capability_digest: [u8; 32],
    pub(crate) label: String,
    pub(crate) account_name: String,
    pub(crate) issuer: String,
    pub(crate) algorithm: u8,
    pub(crate) digits: u8,
    pub(crate) period_seconds: u16,
    pub(crate) accepted_step_window: u8,
}

impl FrozenTotpRegistrationState {
    pub(crate) fn validate(&self) -> Result<(), TotpRegistrationStateError> {
        if self.secret.as_ref() == [0; SECRET_BYTES]
            || !(32..=MAXIMUM_ENVELOPE_BYTES).contains(&self.secret_ciphertext.len())
            || self.identity_revision == Revision::ZERO
            || self.capability_digest == [0; 32]
            || !valid_text(&self.label)
            || !valid_text(&self.account_name)
            || !valid_text(&self.issuer)
            || self.algorithm != 1
            || self.digits != 6
            || self.period_seconds != 30
            || self.accepted_step_window > 1
        {
            Err(TotpRegistrationStateError::Invalid)
        } else {
            Ok(())
        }
    }
}

pub(crate) struct TotpRegistrationProtector {
    key: TotpCeremonyKey,
}

impl TotpRegistrationProtector {
    pub(crate) const fn new(key: TotpCeremonyKey) -> Self {
        Self { key }
    }

    pub(crate) fn protect(
        &self,
        binding: TotpRegistrationBinding,
        state: &FrozenTotpRegistrationState,
        random: &mut impl RandomSource,
    ) -> Result<ProtectedAuthenticationState, TotpRegistrationStateError> {
        state.validate()?;
        let plaintext = Zeroizing::new(encode_state(state)?);
        let mut nonce = [0_u8; NONCE_BYTES];
        random
            .fill_bytes(&mut nonce)
            .map_err(|_| TotpRegistrationStateError::Unavailable)?;
        if nonce == [0; NONCE_BYTES] {
            return Err(TotpRegistrationStateError::Unavailable);
        }
        let encrypted = self
            .cipher()?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &binding.associated_data(),
                },
            )
            .map_err(|_| TotpRegistrationStateError::Unavailable)?;
        let mut protected = Vec::with_capacity(1 + NONCE_BYTES + encrypted.len());
        protected.push(FORMAT_VERSION);
        protected.extend_from_slice(&nonce);
        protected.extend_from_slice(&encrypted);
        ProtectedAuthenticationState::new(protected)
            .map_err(|_| TotpRegistrationStateError::Invalid)
    }

    pub(crate) fn unprotect(
        &self,
        binding: TotpRegistrationBinding,
        protected: &ProtectedAuthenticationState,
    ) -> Result<FrozenTotpRegistrationState, TotpRegistrationStateError> {
        let bytes = protected.as_bytes();
        if bytes.len() <= 1 + NONCE_BYTES || bytes[0] != FORMAT_VERSION {
            return Err(TotpRegistrationStateError::Invalid);
        }
        let nonce = XNonce::try_from(&bytes[1..=NONCE_BYTES])
            .map_err(|_| TotpRegistrationStateError::Invalid)?;
        let plaintext = Zeroizing::new(
            self.cipher()?
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &bytes[1 + NONCE_BYTES..],
                        aad: &binding.associated_data(),
                    },
                )
                .map_err(|_| TotpRegistrationStateError::Invalid)?,
        );
        decode_state(&plaintext)
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, TotpRegistrationStateError> {
        XChaCha20Poly1305::new_from_slice(self.key.0.as_ref())
            .map_err(|_| TotpRegistrationStateError::InvalidKey)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TotpRegistrationBinding {
    pub(crate) challenge_id: AuthenticationChallengeId,
    pub(crate) creation_operation_id: OperationId,
    pub(crate) request_digest: [u8; 32],
    pub(crate) created_at: UnixMicros,
    pub(crate) expires_at: UnixMicros,
}

impl TotpRegistrationBinding {
    fn associated_data(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(AAD_DOMAIN.len() + 80);
        bytes.extend_from_slice(AAD_DOMAIN);
        bytes.extend_from_slice(&self.challenge_id.as_bytes());
        bytes.extend_from_slice(&self.creation_operation_id.as_bytes());
        bytes.extend_from_slice(&self.request_digest);
        bytes.extend_from_slice(&self.created_at.get().to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.get().to_be_bytes());
        bytes
    }
}

/// Closed node-local TOTP ceremony protection failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TotpRegistrationStateError {
    /// Key material is invalid.
    #[error("TOTP ceremony key is invalid")]
    InvalidKey,
    /// Persisted state or its binding is invalid.
    #[error("TOTP registration state is invalid")]
    Invalid,
    /// Entropy or encryption was unavailable.
    #[error("TOTP registration protection is unavailable")]
    Unavailable,
}

fn encode_state(
    state: &FrozenTotpRegistrationState,
) -> Result<Vec<u8>, TotpRegistrationStateError> {
    let mut bytes = Vec::new();
    bytes.push(FORMAT_VERSION);
    bytes.extend_from_slice(state.secret.as_ref());
    encode_bytes(&mut bytes, &state.secret_ciphertext)?;
    bytes.extend_from_slice(&state.method_id.as_bytes());
    bytes.extend_from_slice(&state.principal_id.as_bytes());
    bytes.extend_from_slice(&state.session_id.as_bytes());
    bytes.extend_from_slice(&state.identity_revision.get().to_be_bytes());
    bytes.extend_from_slice(&state.capability_digest);
    encode_text(&mut bytes, &state.label)?;
    encode_text(&mut bytes, &state.account_name)?;
    encode_text(&mut bytes, &state.issuer)?;
    bytes.push(state.algorithm);
    bytes.push(state.digits);
    bytes.extend_from_slice(&state.period_seconds.to_be_bytes());
    bytes.push(state.accepted_step_window);
    Ok(bytes)
}

fn decode_state(bytes: &[u8]) -> Result<FrozenTotpRegistrationState, TotpRegistrationStateError> {
    let mut cursor = StateCursor::new(bytes);
    if cursor.byte()? != FORMAT_VERSION {
        return Err(TotpRegistrationStateError::Invalid);
    }
    let state = FrozenTotpRegistrationState {
        secret: Zeroizing::new(cursor.array()?),
        secret_ciphertext: cursor.bytes(MAXIMUM_ENVELOPE_BYTES)?,
        method_id: AuthenticationMethodId::from_bytes(cursor.array()?)
            .map_err(|_| TotpRegistrationStateError::Invalid)?,
        principal_id: PrincipalId::from_bytes(cursor.array()?)
            .map_err(|_| TotpRegistrationStateError::Invalid)?,
        session_id: SessionId::from_bytes(cursor.array()?)
            .map_err(|_| TotpRegistrationStateError::Invalid)?,
        identity_revision: Revision::new(cursor.u64()?),
        capability_digest: cursor.array()?,
        label: cursor.text()?,
        account_name: cursor.text()?,
        issuer: cursor.text()?,
        algorithm: cursor.byte()?,
        digits: cursor.byte()?,
        period_seconds: cursor.u16()?,
        accepted_step_window: cursor.byte()?,
    };
    if !cursor.finished() {
        return Err(TotpRegistrationStateError::Invalid);
    }
    state.validate()?;
    Ok(state)
}

fn encode_text(output: &mut Vec<u8>, value: &str) -> Result<(), TotpRegistrationStateError> {
    if !valid_text(value) {
        return Err(TotpRegistrationStateError::Invalid);
    }
    encode_bytes(output, value.as_bytes())
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), TotpRegistrationStateError> {
    output.extend_from_slice(
        &u16::try_from(value.len())
            .map_err(|_| TotpRegistrationStateError::Invalid)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_TEXT_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

struct StateCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> StateCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TotpRegistrationStateError> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(TotpRegistrationStateError::Invalid)?;
        self.remaining = remaining;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, TotpRegistrationStateError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TotpRegistrationStateError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, TotpRegistrationStateError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TotpRegistrationStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| TotpRegistrationStateError::Invalid)
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, TotpRegistrationStateError> {
        let length = usize::from(self.u16()?);
        if length > maximum {
            return Err(TotpRegistrationStateError::Invalid);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn text(&mut self) -> Result<String, TotpRegistrationStateError> {
        let bytes = self.bytes(MAXIMUM_TEXT_BYTES)?;
        let value = String::from_utf8(bytes).map_err(|_| TotpRegistrationStateError::Invalid)?;
        if valid_text(&value) {
            Ok(value)
        } else {
            Err(TotpRegistrationStateError::Invalid)
        }
    }

    const fn finished(&self) -> bool {
        self.remaining.is_empty()
    }
}
