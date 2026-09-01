// SPDX-License-Identifier: GPL-2.0-only

//! Mesh-wide authenticated encryption for replicated TOTP seeds.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use meshspan_domain::{AuthenticationMethodId, PrincipalId, RandomSource};
use thiserror::Error;
use zeroize::Zeroizing;

const FORMAT_VERSION: u8 = 1;
const NONCE_BYTES: usize = 24;
const MINIMUM_SECRET_BYTES: usize = 16;
const MAXIMUM_SECRET_BYTES: usize = 128;
const AUTHENTICATION_TAG_BYTES: usize = 16;
const AAD_DOMAIN: &[u8] = b"meshspan.authentication.totp-secret.v1\0";

/// Mesh-wide key protecting TOTP seeds stored in replicated metadata.
///
/// The daemon's protected key lifecycle owns distribution and rotation. This type deliberately
/// implements neither `Clone`, `Copy`, `Debug` nor `Display`, and clears its bytes on drop.
pub struct TotpEnvelopeKey(Zeroizing<[u8; 32]>);

impl TotpEnvelopeKey {
    /// Takes ownership of one non-zero key loaded from protected daemon state.
    ///
    /// # Errors
    ///
    /// Rejects the reserved all-zero value.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, TotpSecretError> {
        if bytes == [0; 32] {
            Err(TotpSecretError::InvalidKey)
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }

    /// Generates a fresh key from the daemon's cryptographic entropy boundary.
    ///
    /// # Errors
    ///
    /// Rejects unavailable entropy and the reserved all-zero value.
    pub fn generate(random: &mut impl RandomSource) -> Result<Self, TotpSecretError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        random
            .fill_bytes(bytes.as_mut())
            .map_err(|_| TotpSecretError::EntropyUnavailable)?;
        Self::from_bytes(*bytes)
    }
}

/// Immutable authority and parameter binding authenticated with one TOTP seed envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TotpSecretBinding {
    /// Authentication method which owns the seed.
    pub method_id: AuthenticationMethodId,
    /// User principal which owns the method.
    pub principal_id: PrincipalId,
    /// Metadata algorithm code: SHA-1 1, SHA-256 2 or SHA-512 3.
    pub algorithm: u8,
    /// Decimal code width.
    pub digits: u8,
    /// Timestep length.
    pub period_seconds: u16,
    /// Accepted adjacent-step window.
    pub accepted_step_window: u8,
}

impl TotpSecretBinding {
    fn associated_data(self) -> Result<Vec<u8>, TotpSecretError> {
        if !(1..=3).contains(&self.algorithm)
            || !(6..=8).contains(&self.digits)
            || !(15..=300).contains(&self.period_seconds)
            || self.accepted_step_window > 10
        {
            return Err(TotpSecretError::InvalidBinding);
        }
        let mut bytes = Vec::with_capacity(AAD_DOMAIN.len() + 37);
        bytes.extend_from_slice(AAD_DOMAIN);
        bytes.extend_from_slice(&self.method_id.as_bytes());
        bytes.extend_from_slice(&self.principal_id.as_bytes());
        bytes.push(self.algorithm);
        bytes.push(self.digits);
        bytes.extend_from_slice(&self.period_seconds.to_be_bytes());
        bytes.push(self.accepted_step_window);
        Ok(bytes)
    }
}

/// Authenticated TOTP-seed envelope cipher shared by authorised gateways.
pub struct TotpSecretCipher {
    key: TotpEnvelopeKey,
}

impl TotpSecretCipher {
    /// Creates a cipher from the current mesh-wide TOTP envelope-key generation.
    #[must_use]
    pub const fn new(key: TotpEnvelopeKey) -> Self {
        Self { key }
    }

    /// Encrypts one seed with a fresh nonce and exact method/parameter binding.
    ///
    /// # Errors
    ///
    /// Rejects invalid seed length, invalid binding, unavailable entropy or cryptographic failure.
    pub fn encrypt(
        &self,
        binding: TotpSecretBinding,
        secret: &[u8],
        random: &mut (impl RandomSource + ?Sized),
    ) -> Result<Vec<u8>, TotpSecretError> {
        validate_secret(secret)?;
        let aad = binding.associated_data()?;
        let mut nonce = [0_u8; NONCE_BYTES];
        random
            .fill_bytes(&mut nonce)
            .map_err(|_| TotpSecretError::EntropyUnavailable)?;
        if nonce == [0; NONCE_BYTES] {
            return Err(TotpSecretError::EntropyUnavailable);
        }
        let cipher = self.cipher()?;
        let encrypted = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|_| TotpSecretError::Cryptographic)?;
        let mut envelope = Vec::with_capacity(1 + NONCE_BYTES + encrypted.len());
        envelope.push(FORMAT_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        Ok(envelope)
    }

    /// Decrypts and authenticates one seed against its exact method/parameter binding.
    ///
    /// # Errors
    ///
    /// Rejects malformed, substituted, tampered or wrong-key envelopes and invalid plaintext.
    pub fn decrypt(
        &self,
        binding: TotpSecretBinding,
        envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, TotpSecretError> {
        let minimum = 1 + NONCE_BYTES + MINIMUM_SECRET_BYTES + AUTHENTICATION_TAG_BYTES;
        let maximum = 1 + NONCE_BYTES + MAXIMUM_SECRET_BYTES + AUTHENTICATION_TAG_BYTES;
        if !(minimum..=maximum).contains(&envelope.len()) || envelope[0] != FORMAT_VERSION {
            return Err(TotpSecretError::InvalidEnvelope);
        }
        let nonce = XNonce::try_from(&envelope[1..=NONCE_BYTES])
            .map_err(|_| TotpSecretError::InvalidEnvelope)?;
        let aad = binding.associated_data()?;
        let secret = self
            .cipher()?
            .decrypt(
                &nonce,
                Payload {
                    msg: &envelope[1 + NONCE_BYTES..],
                    aad: &aad,
                },
            )
            .map_err(|_| TotpSecretError::InvalidEnvelope)?;
        validate_secret(&secret)?;
        Ok(Zeroizing::new(secret))
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, TotpSecretError> {
        XChaCha20Poly1305::new_from_slice(self.key.0.as_ref())
            .map_err(|_| TotpSecretError::InvalidKey)
    }
}

impl crate::TotpRegistrationSecretProtector for TotpSecretCipher {
    fn protect_secret(
        &self,
        binding: TotpSecretBinding,
        secret: &[u8],
        random: &mut dyn RandomSource,
    ) -> Result<Vec<u8>, crate::TotpRegistrationError> {
        self.encrypt(binding, secret, random).map_err(Into::into)
    }
}

/// Closed TOTP envelope failure which contains no seed material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TotpSecretError {
    /// Key material is the reserved value or cannot initialise the cipher.
    #[error("TOTP envelope key is invalid")]
    InvalidKey,
    /// Seed authority or verification parameters are invalid.
    #[error("TOTP seed binding is invalid")]
    InvalidBinding,
    /// Seed length is outside the bounded interoperability profile.
    #[error("TOTP seed is invalid")]
    InvalidSecret,
    /// Ciphertext format, tag, key or binding failed validation.
    #[error("TOTP seed envelope is invalid")]
    InvalidEnvelope,
    /// Cryptographic entropy was unavailable or returned a reserved value.
    #[error("TOTP seed protection entropy is unavailable")]
    EntropyUnavailable,
    /// The maintained cryptographic primitive failed closed.
    #[error("TOTP seed protection failed closed")]
    Cryptographic,
}

fn validate_secret(secret: &[u8]) -> Result<(), TotpSecretError> {
    if (MINIMUM_SECRET_BYTES..=MAXIMUM_SECRET_BYTES).contains(&secret.len()) {
        Ok(())
    } else {
        Err(TotpSecretError::InvalidSecret)
    }
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{AuthenticationMethodId, EntropyError, PrincipalId, RandomSource};

    use crate::passkey_test_support::CountingRandom;

    use super::{TotpEnvelopeKey, TotpSecretBinding, TotpSecretCipher, TotpSecretError};

    #[test]
    fn envelope_round_trips_and_binds_every_authoritative_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let cipher = TotpSecretCipher::new(TotpEnvelopeKey::from_bytes([7; 32])?);
        let binding = valid_binding()?;
        let envelope = cipher.encrypt(binding, &[9; 20], &mut CountingRandom::default())?;
        assert_eq!(cipher.decrypt(binding, &envelope)?.as_slice(), &[9; 20]);

        let changed = TotpSecretBinding {
            digits: 8,
            ..binding
        };
        assert_eq!(
            cipher.decrypt(changed, &envelope),
            Err(TotpSecretError::InvalidEnvelope)
        );
        let mut tampered = envelope;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            cipher.decrypt(binding, &tampered),
            Err(TotpSecretError::InvalidEnvelope)
        );
        Ok(())
    }

    #[test]
    fn key_binding_secret_and_entropy_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            TotpEnvelopeKey::from_bytes([0; 32]),
            Err(TotpSecretError::InvalidKey)
        ));
        assert!(matches!(
            TotpEnvelopeKey::generate(&mut UnavailableRandom),
            Err(TotpSecretError::EntropyUnavailable)
        ));
        let cipher = TotpSecretCipher::new(TotpEnvelopeKey::from_bytes([7; 32])?);
        let mut invalid = valid_binding()?;
        invalid.period_seconds = 14;
        assert_eq!(
            cipher.encrypt(invalid, &[9; 20], &mut CountingRandom::default()),
            Err(TotpSecretError::InvalidBinding)
        );
        assert_eq!(
            cipher.encrypt(valid_binding()?, &[9; 15], &mut CountingRandom::default()),
            Err(TotpSecretError::InvalidSecret)
        );
        Ok(())
    }

    fn valid_binding() -> Result<TotpSecretBinding, meshspan_domain::IdentifierError> {
        Ok(TotpSecretBinding {
            method_id: AuthenticationMethodId::from_bytes([1; 16])?,
            principal_id: PrincipalId::from_bytes([2; 16])?,
            algorithm: 1,
            digits: 6,
            period_seconds: 30,
            accepted_step_window: 1,
        })
    }

    struct UnavailableRandom;

    impl RandomSource for UnavailableRandom {
        fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError)
        }
    }
}
