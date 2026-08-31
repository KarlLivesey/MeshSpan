// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated node-local state for current-user passkey registration.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshspan_domain::{
    AuthenticationChallengeId, AuthenticationMethodId, OperationId, PrincipalId, RandomSource,
    Revision, SessionId, UnixMicros,
};
use meshspan_metadata::ProtectedAuthenticationState;
use meshspan_passkey::{PasskeyChallenge, encode_credential_id};
use thiserror::Error;

use crate::PasskeyCeremonyKey;

const FORMAT_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const MAXIMUM_ORIGINS: usize = 16;
const MAXIMUM_EXCLUDED_CREDENTIALS: usize = 64;
pub(crate) const MAXIMUM_EXCLUDED_CREDENTIAL_BYTES: usize = 32_768;
const MAXIMUM_RELYING_PARTY_ID_BYTES: usize = 253;
const MAXIMUM_RELYING_PARTY_NAME_BYTES: usize = 512;
const MAXIMUM_ORIGIN_BYTES: usize = 2_048;
const MAXIMUM_USER_NAME_BYTES: usize = 512;
const AAD_DOMAIN: &[u8] = b"meshspan.authentication.passkey-registration.v1\0";

pub(crate) struct FrozenPasskeyRegistrationState {
    pub(crate) challenge: PasskeyChallenge,
    pub(crate) method_id: AuthenticationMethodId,
    pub(crate) principal_id: PrincipalId,
    pub(crate) session_id: SessionId,
    pub(crate) identity_revision: Revision,
    pub(crate) capability_digest: [u8; 32],
    pub(crate) relying_party_id: String,
    pub(crate) relying_party_name: String,
    pub(crate) allowed_origins: Vec<String>,
    pub(crate) user_name: String,
    pub(crate) user_display_name: String,
    pub(crate) exclude_credential_ids: Vec<Vec<u8>>,
}

impl FrozenPasskeyRegistrationState {
    pub(crate) fn validate(&self) -> Result<(), PasskeyRegistrationStateError> {
        if self.identity_revision == Revision::ZERO
            || self.capability_digest == [0; 32]
            || !valid_text(&self.relying_party_id, MAXIMUM_RELYING_PARTY_ID_BYTES)
            || !valid_text(&self.relying_party_name, MAXIMUM_RELYING_PARTY_NAME_BYTES)
            || !valid_text(&self.user_name, MAXIMUM_USER_NAME_BYTES)
            || !valid_text(&self.user_display_name, MAXIMUM_USER_NAME_BYTES)
            || self.allowed_origins.is_empty()
            || self.allowed_origins.len() > MAXIMUM_ORIGINS
            || self
                .allowed_origins
                .iter()
                .any(|origin| !valid_text(origin, MAXIMUM_ORIGIN_BYTES))
            || !valid_exclusions(&self.exclude_credential_ids)
        {
            Err(PasskeyRegistrationStateError::Invalid)
        } else {
            Ok(())
        }
    }
}

pub(crate) struct PasskeyRegistrationProtector {
    key: PasskeyCeremonyKey,
}

impl PasskeyRegistrationProtector {
    pub(crate) const fn new(key: PasskeyCeremonyKey) -> Self {
        Self { key }
    }

    pub(crate) fn protect(
        &self,
        binding: PasskeyRegistrationBinding,
        state: &FrozenPasskeyRegistrationState,
        random: &mut impl RandomSource,
    ) -> Result<ProtectedAuthenticationState, PasskeyRegistrationStateError> {
        state.validate()?;
        let plaintext = encode_state(state)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        random
            .fill_bytes(&mut nonce)
            .map_err(|_| PasskeyRegistrationStateError::Unavailable)?;
        if nonce == [0; NONCE_BYTES] {
            return Err(PasskeyRegistrationStateError::Unavailable);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_bytes())
            .map_err(|_| PasskeyRegistrationStateError::Invalid)?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &binding.associated_data(),
                },
            )
            .map_err(|_| PasskeyRegistrationStateError::Unavailable)?;
        let mut protected = Vec::with_capacity(1 + NONCE_BYTES + ciphertext.len());
        protected.push(FORMAT_VERSION);
        protected.extend_from_slice(&nonce);
        protected.extend_from_slice(&ciphertext);
        ProtectedAuthenticationState::new(protected)
            .map_err(|_| PasskeyRegistrationStateError::Invalid)
    }

    pub(crate) fn unprotect(
        &self,
        binding: PasskeyRegistrationBinding,
        protected: &ProtectedAuthenticationState,
    ) -> Result<FrozenPasskeyRegistrationState, PasskeyRegistrationStateError> {
        let bytes = protected.as_bytes();
        if bytes.len() <= 1 + NONCE_BYTES || bytes[0] != FORMAT_VERSION {
            return Err(PasskeyRegistrationStateError::Invalid);
        }
        let nonce = XNonce::try_from(&bytes[1..=NONCE_BYTES])
            .map_err(|_| PasskeyRegistrationStateError::Invalid)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_bytes())
            .map_err(|_| PasskeyRegistrationStateError::Invalid)?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &bytes[1 + NONCE_BYTES..],
                    aad: &binding.associated_data(),
                },
            )
            .map_err(|_| PasskeyRegistrationStateError::Invalid)?;
        decode_state(&plaintext)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PasskeyRegistrationBinding {
    pub(crate) challenge_id: AuthenticationChallengeId,
    pub(crate) creation_operation_id: OperationId,
    pub(crate) request_digest: [u8; 32],
    pub(crate) created_at: UnixMicros,
    pub(crate) expires_at: UnixMicros,
}

impl PasskeyRegistrationBinding {
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

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum PasskeyRegistrationStateError {
    #[error("passkey registration state is invalid")]
    Invalid,
    #[error("passkey registration protection is unavailable")]
    Unavailable,
}

fn encode_state(
    state: &FrozenPasskeyRegistrationState,
) -> Result<Vec<u8>, PasskeyRegistrationStateError> {
    let mut bytes = Vec::new();
    bytes.push(FORMAT_VERSION);
    bytes.extend_from_slice(state.challenge.as_bytes());
    bytes.extend_from_slice(&state.method_id.as_bytes());
    bytes.extend_from_slice(&state.principal_id.as_bytes());
    bytes.extend_from_slice(&state.session_id.as_bytes());
    bytes.extend_from_slice(&state.identity_revision.get().to_be_bytes());
    bytes.extend_from_slice(&state.capability_digest);
    encode_text(&mut bytes, &state.relying_party_id)?;
    encode_text(&mut bytes, &state.relying_party_name)?;
    encode_texts(&mut bytes, &state.allowed_origins)?;
    encode_text(&mut bytes, &state.user_name)?;
    encode_text(&mut bytes, &state.user_display_name)?;
    bytes.push(
        u8::try_from(state.exclude_credential_ids.len())
            .map_err(|_| PasskeyRegistrationStateError::Invalid)?,
    );
    for credential_id in &state.exclude_credential_ids {
        encode_bytes(&mut bytes, credential_id)?;
    }
    Ok(bytes)
}

fn decode_state(
    bytes: &[u8],
) -> Result<FrozenPasskeyRegistrationState, PasskeyRegistrationStateError> {
    let mut cursor = StateCursor::new(bytes);
    if cursor.byte()? != FORMAT_VERSION {
        return Err(PasskeyRegistrationStateError::Invalid);
    }
    let state = FrozenPasskeyRegistrationState {
        challenge: PasskeyChallenge::from_bytes(cursor.array()?)
            .map_err(|_| PasskeyRegistrationStateError::Invalid)?,
        method_id: AuthenticationMethodId::from_bytes(cursor.array()?)
            .map_err(|_| PasskeyRegistrationStateError::Invalid)?,
        principal_id: PrincipalId::from_bytes(cursor.array()?)
            .map_err(|_| PasskeyRegistrationStateError::Invalid)?,
        session_id: SessionId::from_bytes(cursor.array()?)
            .map_err(|_| PasskeyRegistrationStateError::Invalid)?,
        identity_revision: Revision::new(cursor.u64()?),
        capability_digest: cursor.array()?,
        relying_party_id: cursor.text(MAXIMUM_RELYING_PARTY_ID_BYTES)?,
        relying_party_name: cursor.text(MAXIMUM_RELYING_PARTY_NAME_BYTES)?,
        allowed_origins: cursor.texts(MAXIMUM_ORIGINS, MAXIMUM_ORIGIN_BYTES)?,
        user_name: cursor.text(MAXIMUM_USER_NAME_BYTES)?,
        user_display_name: cursor.text(MAXIMUM_USER_NAME_BYTES)?,
        exclude_credential_ids: cursor.byte_vectors(
            MAXIMUM_EXCLUDED_CREDENTIALS,
            MAXIMUM_EXCLUDED_CREDENTIAL_BYTES,
        )?,
    };
    if !cursor.is_complete() {
        return Err(PasskeyRegistrationStateError::Invalid);
    }
    state.validate()?;
    Ok(state)
}

fn encode_texts(
    output: &mut Vec<u8>,
    values: &[String],
) -> Result<(), PasskeyRegistrationStateError> {
    output.push(u8::try_from(values.len()).map_err(|_| PasskeyRegistrationStateError::Invalid)?);
    for value in values {
        encode_text(output, value)?;
    }
    Ok(())
}

fn encode_text(output: &mut Vec<u8>, value: &str) -> Result<(), PasskeyRegistrationStateError> {
    encode_bytes(output, value.as_bytes())
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), PasskeyRegistrationStateError> {
    output.extend_from_slice(
        &u16::try_from(value.len())
            .map_err(|_| PasskeyRegistrationStateError::Invalid)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn valid_exclusions(values: &[Vec<u8>]) -> bool {
    values.len() <= MAXIMUM_EXCLUDED_CREDENTIALS
        && values
            .iter()
            .try_fold(0_usize, |total, value| {
                encode_credential_id(value).ok()?;
                total.checked_add(value.len())
            })
            .is_some_and(|total| total <= MAXIMUM_EXCLUDED_CREDENTIAL_BYTES)
}

fn valid_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

struct StateCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> StateCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, PasskeyRegistrationStateError> {
        let value = *self
            .bytes
            .get(self.offset)
            .ok_or(PasskeyRegistrationStateError::Invalid)?;
        self.offset += 1;
        Ok(value)
    }

    fn u64(&mut self) -> Result<u64, PasskeyRegistrationStateError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PasskeyRegistrationStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| PasskeyRegistrationStateError::Invalid)
    }

    fn text(&mut self, maximum_bytes: usize) -> Result<String, PasskeyRegistrationStateError> {
        let bytes = self.bytes(maximum_bytes)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| PasskeyRegistrationStateError::Invalid)
    }

    fn texts(
        &mut self,
        maximum_items: usize,
        maximum_bytes: usize,
    ) -> Result<Vec<String>, PasskeyRegistrationStateError> {
        let count = usize::from(self.byte()?);
        if count == 0 || count > maximum_items {
            return Err(PasskeyRegistrationStateError::Invalid);
        }
        (0..count).map(|_| self.text(maximum_bytes)).collect()
    }

    fn byte_vectors(
        &mut self,
        maximum_items: usize,
        maximum_total_bytes: usize,
    ) -> Result<Vec<Vec<u8>>, PasskeyRegistrationStateError> {
        let count = usize::from(self.byte()?);
        if count > maximum_items {
            return Err(PasskeyRegistrationStateError::Invalid);
        }
        let mut values = Vec::with_capacity(count);
        let mut total = 0_usize;
        for _ in 0..count {
            let value = self.bytes(1_024)?.to_vec();
            total = total
                .checked_add(value.len())
                .filter(|value| *value <= maximum_total_bytes)
                .ok_or(PasskeyRegistrationStateError::Invalid)?;
            values.push(value);
        }
        Ok(values)
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], PasskeyRegistrationStateError> {
        let length = usize::from(u16::from_be_bytes(self.array()?));
        if length == 0 || length > maximum {
            return Err(PasskeyRegistrationStateError::Invalid);
        }
        self.take(length)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PasskeyRegistrationStateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PasskeyRegistrationStateError::Invalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PasskeyRegistrationStateError::Invalid)?;
        self.offset = end;
        Ok(value)
    }

    const fn is_complete(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
