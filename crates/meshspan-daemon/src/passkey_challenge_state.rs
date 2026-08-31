// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated node-local state for restart-safe passkey challenges.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshspan_domain::{
    AuthenticationChallengeId, EntropyError, OperationId, RandomSource, UnixMicros,
};
use meshspan_metadata::ProtectedAuthenticationState;
use meshspan_passkey::PasskeyChallenge;
use thiserror::Error;
use zeroize::Zeroizing;

const FORMAT_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const SESSION_SEED_BYTES: usize = 32;
const MAXIMUM_ORIGINS: usize = 16;
const MAXIMUM_RELYING_PARTY_BYTES: usize = 253;
const MAXIMUM_ORIGIN_BYTES: usize = 2_048;
const AAD_DOMAIN: &[u8] = b"meshspan.authentication.passkey-ceremony.v1\0";

/// Non-exportable node-local key protecting restart-safe authentication ceremonies.
///
/// The daemon owns persistence and file permissions for this key. It implements neither
/// `Clone`, `Copy`, `Debug` nor `Display`, and clears its bytes on drop.
pub struct PasskeyCeremonyKey(Zeroizing<[u8; 32]>);

impl PasskeyCeremonyKey {
    /// Takes ownership of one non-zero key loaded from protected daemon state.
    ///
    /// # Errors
    ///
    /// Rejects the reserved all-zero value.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PasskeyChallengeStateError> {
        if bytes == [0; 32] {
            Err(PasskeyChallengeStateError::Invalid)
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }

    /// Generates a fresh key from the daemon's cryptographic entropy boundary.
    ///
    /// # Errors
    ///
    /// Rejects unavailable entropy and the reserved all-zero value.
    pub fn generate(random: &mut impl RandomSource) -> Result<Self, PasskeyChallengeStateError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        random.fill_bytes(&mut bytes[..])?;
        Self::from_bytes(*bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) struct FrozenPasskeyChallengeState {
    challenge: PasskeyChallenge,
    session_seed: Zeroizing<[u8; SESSION_SEED_BYTES]>,
    relying_party_id: String,
    allowed_origins: Vec<String>,
}

impl FrozenPasskeyChallengeState {
    pub(crate) fn new(
        challenge: PasskeyChallenge,
        session_seed: [u8; SESSION_SEED_BYTES],
        relying_party_id: String,
        allowed_origins: Vec<String>,
    ) -> Result<Self, PasskeyChallengeStateError> {
        if session_seed == [0; SESSION_SEED_BYTES]
            || !valid_text(&relying_party_id, MAXIMUM_RELYING_PARTY_BYTES)
            || allowed_origins.is_empty()
            || allowed_origins.len() > MAXIMUM_ORIGINS
            || allowed_origins
                .iter()
                .any(|origin| !valid_text(origin, MAXIMUM_ORIGIN_BYTES))
        {
            return Err(PasskeyChallengeStateError::Invalid);
        }
        Ok(Self {
            challenge,
            session_seed: Zeroizing::new(session_seed),
            relying_party_id,
            allowed_origins,
        })
    }

    pub(crate) const fn challenge(&self) -> &PasskeyChallenge {
        &self.challenge
    }

    pub(crate) fn relying_party_id(&self) -> &str {
        &self.relying_party_id
    }

    pub(crate) fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    pub(crate) fn session_seed(&self) -> &[u8; SESSION_SEED_BYTES] {
        &self.session_seed
    }
}

pub(crate) struct PasskeyChallengeProtector {
    key: PasskeyCeremonyKey,
}

impl PasskeyChallengeProtector {
    pub(crate) const fn new(key: PasskeyCeremonyKey) -> Self {
        Self { key }
    }

    pub(crate) fn protect(
        &self,
        binding: PasskeyChallengeBinding,
        state: &FrozenPasskeyChallengeState,
        random: &mut impl RandomSource,
    ) -> Result<ProtectedAuthenticationState, PasskeyChallengeStateError> {
        let plaintext = encode_state(state)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        random.fill_bytes(&mut nonce)?;
        if nonce == [0; NONCE_BYTES] {
            return Err(PasskeyChallengeStateError::Invalid);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.0.as_ref())
            .map_err(|_| PasskeyChallengeStateError::Invalid)?;
        let nonce_ref = XNonce::from(nonce);
        let aad = binding.associated_data();
        let ciphertext = cipher
            .encrypt(
                &nonce_ref,
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| PasskeyChallengeStateError::Unavailable)?;
        let mut protected = Vec::with_capacity(1 + NONCE_BYTES + ciphertext.len());
        protected.push(FORMAT_VERSION);
        protected.extend_from_slice(&nonce);
        protected.extend_from_slice(&ciphertext);
        ProtectedAuthenticationState::new(protected)
            .map_err(|_| PasskeyChallengeStateError::Invalid)
    }

    pub(crate) fn unprotect(
        &self,
        binding: PasskeyChallengeBinding,
        protected: &ProtectedAuthenticationState,
    ) -> Result<FrozenPasskeyChallengeState, PasskeyChallengeStateError> {
        let bytes = protected.as_bytes();
        if bytes.len() <= 1 + NONCE_BYTES || bytes[0] != FORMAT_VERSION {
            return Err(PasskeyChallengeStateError::Invalid);
        }
        let nonce = XNonce::try_from(&bytes[1..=NONCE_BYTES])
            .map_err(|_| PasskeyChallengeStateError::Invalid)?;
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.0.as_ref())
            .map_err(|_| PasskeyChallengeStateError::Invalid)?;
        let aad = binding.associated_data();
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &bytes[1 + NONCE_BYTES..],
                    aad: &aad,
                },
            )
            .map_err(|_| PasskeyChallengeStateError::Invalid)?;
        decode_state(&plaintext)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PasskeyChallengeBinding {
    pub(crate) challenge_id: AuthenticationChallengeId,
    pub(crate) operation_id: OperationId,
    pub(crate) request_digest: [u8; 32],
    pub(crate) created_at: UnixMicros,
    pub(crate) expires_at: UnixMicros,
}

impl PasskeyChallengeBinding {
    fn associated_data(self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 80);
        aad.extend_from_slice(AAD_DOMAIN);
        aad.extend_from_slice(&self.challenge_id.as_bytes());
        aad.extend_from_slice(&self.operation_id.as_bytes());
        aad.extend_from_slice(&self.request_digest);
        aad.extend_from_slice(&self.created_at.get().to_be_bytes());
        aad.extend_from_slice(&self.expires_at.get().to_be_bytes());
        aad
    }
}

/// Closed protected-state failure without key, challenge or plaintext detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PasskeyChallengeStateError {
    /// State, key material or authenticated ciphertext was invalid.
    #[error("passkey challenge state is invalid")]
    Invalid,
    /// Cryptographic entropy or encryption was unavailable.
    #[error("passkey challenge protection is unavailable")]
    Unavailable,
}

impl From<EntropyError> for PasskeyChallengeStateError {
    fn from(_: EntropyError) -> Self {
        Self::Unavailable
    }
}

fn encode_state(
    state: &FrozenPasskeyChallengeState,
) -> Result<Zeroizing<Vec<u8>>, PasskeyChallengeStateError> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.push(FORMAT_VERSION);
    bytes.extend_from_slice(state.challenge.as_bytes());
    bytes.extend_from_slice(state.session_seed.as_ref());
    encode_text(&mut bytes, &state.relying_party_id)?;
    bytes.push(
        u8::try_from(state.allowed_origins.len())
            .map_err(|_| PasskeyChallengeStateError::Invalid)?,
    );
    for origin in &state.allowed_origins {
        encode_text(&mut bytes, origin)?;
    }
    Ok(bytes)
}

fn encode_text(output: &mut Vec<u8>, value: &str) -> Result<(), PasskeyChallengeStateError> {
    let length = u16::try_from(value.len()).map_err(|_| PasskeyChallengeStateError::Invalid)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn decode_state(bytes: &[u8]) -> Result<FrozenPasskeyChallengeState, PasskeyChallengeStateError> {
    let mut cursor = StateCursor::new(bytes);
    if cursor.byte()? != FORMAT_VERSION {
        return Err(PasskeyChallengeStateError::Invalid);
    }
    let challenge = PasskeyChallenge::from_bytes(cursor.array()?)
        .map_err(|_| PasskeyChallengeStateError::Invalid)?;
    let session_seed = cursor.array()?;
    let relying_party_id = cursor.text(MAXIMUM_RELYING_PARTY_BYTES)?;
    let origin_count = usize::from(cursor.byte()?);
    if origin_count == 0 || origin_count > MAXIMUM_ORIGINS {
        return Err(PasskeyChallengeStateError::Invalid);
    }
    let mut allowed_origins = Vec::with_capacity(origin_count);
    for _ in 0..origin_count {
        allowed_origins.push(cursor.text(MAXIMUM_ORIGIN_BYTES)?);
    }
    if !cursor.is_complete() {
        return Err(PasskeyChallengeStateError::Invalid);
    }
    FrozenPasskeyChallengeState::new(challenge, session_seed, relying_party_id, allowed_origins)
}

fn valid_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

struct StateCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> StateCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, PasskeyChallengeStateError> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or(PasskeyChallengeStateError::Invalid)?;
        self.offset += 1;
        Ok(byte)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PasskeyChallengeStateError> {
        self.take(N)?
            .try_into()
            .map_err(|_| PasskeyChallengeStateError::Invalid)
    }

    fn text(&mut self, maximum_bytes: usize) -> Result<String, PasskeyChallengeStateError> {
        let length = usize::from(u16::from_be_bytes(self.array()?));
        if length == 0 || length > maximum_bytes {
            return Err(PasskeyChallengeStateError::Invalid);
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| PasskeyChallengeStateError::Invalid)?;
        if !valid_text(value, maximum_bytes) {
            return Err(PasskeyChallengeStateError::Invalid);
        }
        Ok(value.to_owned())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PasskeyChallengeStateError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PasskeyChallengeStateError::Invalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PasskeyChallengeStateError::Invalid)?;
        self.offset = end;
        Ok(value)
    }

    const fn is_complete(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
