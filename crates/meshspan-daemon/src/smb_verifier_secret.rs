// SPDX-License-Identifier: GPL-2.0-only

//! Mesh-wide authenticated encryption for API-key-derived SMB verifiers.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use meshspan_domain::{ApiKeyId, AuthenticationMethodId, PrincipalId};
use meshspan_smb::NtlmPasswordVerifier;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

const FORMAT_VERSION: u8 = 2;
const GENERATION_BYTES: usize = 8;
const NONCE_BYTES: usize = 24;
const VERIFIER_BYTES: usize = 16;
const CREDENTIAL_DIGEST_BYTES: usize = 32;
const PLAINTEXT_BYTES: usize = VERIFIER_BYTES + CREDENTIAL_DIGEST_BYTES;
const AUTHENTICATION_TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = 1 + GENERATION_BYTES + NONCE_BYTES;
const ENVELOPE_BYTES: usize = HEADER_BYTES + PLAINTEXT_BYTES + AUTHENTICATION_TAG_BYTES;
const AAD_DOMAIN: &[u8] = b"meshspan.authentication.smb-verifier.v2\0";
const NONCE_DOMAIN: &[u8] = b"meshspan.authentication.smb-verifier-nonce.v2\0";

type HmacSha256 = Hmac<Sha256>;

/// Independently derived encryption and deterministic-nonce keys.
///
/// The type deliberately implements neither `Clone`, `Copy`, `Debug` nor `Display`, and clears
/// both keys on drop.
pub struct SmbVerifierEnvelopeKey {
    encryption: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 32]>,
}

impl SmbVerifierEnvelopeKey {
    /// Takes ownership of two domain-separated, non-zero keys.
    ///
    /// # Errors
    ///
    /// Rejects either reserved all-zero value or equal keys.
    pub fn from_parts(
        encryption: [u8; 32],
        nonce: [u8; 32],
    ) -> Result<Self, SmbVerifierSecretError> {
        if encryption == [0; 32] || nonce == [0; 32] || encryption == nonce {
            return Err(SmbVerifierSecretError::InvalidKey);
        }
        Ok(Self {
            encryption: Zeroizing::new(encryption),
            nonce: Zeroizing::new(nonce),
        })
    }
}

/// Immutable metadata binding authenticated with one persisted verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmbVerifierBinding {
    /// Authentication method which owns the verifier.
    pub method_id: AuthenticationMethodId,
    /// User principal which owns the method.
    pub principal_id: PrincipalId,
    /// Public API-key identity.
    pub key_id: ApiKeyId,
    /// Exact connector compatibility bitset.
    pub service_scope: u8,
    /// Exact API-key capability bitset.
    pub scopes: u64,
}

impl SmbVerifierBinding {
    fn associated_data(self) -> Result<Vec<u8>, SmbVerifierSecretError> {
        let smb_bit = meshspan_domain::AuthenticationService::Smb.scope_bit();
        if self.service_scope == 0
            || self.service_scope & !0b111 != 0
            || self.service_scope & smb_bit == 0
            || self.scopes == 0
            || self.scopes & u64::from(smb_bit) == 0
        {
            return Err(SmbVerifierSecretError::InvalidBinding);
        }
        let mut bytes = Vec::with_capacity(AAD_DOMAIN.len() + 57);
        bytes.extend_from_slice(AAD_DOMAIN);
        bytes.extend_from_slice(&self.method_id.as_bytes());
        bytes.extend_from_slice(&self.principal_id.as_bytes());
        bytes.extend_from_slice(&self.key_id.as_bytes());
        bytes.push(self.service_scope);
        bytes.extend_from_slice(&self.scopes.to_be_bytes());
        Ok(bytes)
    }
}

/// Authenticated verifier cipher shared only by authorised SMB gateways.
pub struct SmbVerifierCipher {
    key: SmbVerifierEnvelopeKey,
    generation: u64,
}

/// Decrypted verifier plus the ordinary API-key digest needed by the common authority boundary.
///
/// The type deliberately omits `Debug`, `Clone` and `Copy`; both values are credential material.
pub struct SmbVerifierMaterial {
    verifier: NtlmPasswordVerifier,
    credential_digest: Zeroizing<[u8; CREDENTIAL_DIGEST_BYTES]>,
}

impl SmbVerifierMaterial {
    /// Returns the NTLM verifier only to the proof checker.
    #[must_use]
    pub const fn verifier(&self) -> &NtlmPasswordVerifier {
        &self.verifier
    }

    /// Copies the digest used by the common operation-time API-key authority.
    #[must_use]
    pub fn credential_digest(&self) -> [u8; CREDENTIAL_DIGEST_BYTES] {
        *self.credential_digest
    }
}

impl SmbVerifierCipher {
    /// Creates a cipher from the current mesh authentication-root generation.
    ///
    /// # Errors
    ///
    /// Rejects the reserved zero generation.
    pub fn new(
        key: SmbVerifierEnvelopeKey,
        generation: u64,
    ) -> Result<Self, SmbVerifierSecretError> {
        if generation == 0 {
            Err(SmbVerifierSecretError::InvalidKey)
        } else {
            Ok(Self { key, generation })
        }
    }

    /// Reads the non-secret root generation needed to select a decryption key.
    ///
    /// The value remains untrusted until `decrypt` authenticates the complete envelope.
    ///
    /// # Errors
    ///
    /// Rejects an invalid version, length or zero generation.
    pub fn envelope_generation(envelope: &[u8]) -> Result<u64, SmbVerifierSecretError> {
        if envelope.len() != ENVELOPE_BYTES || envelope[0] != FORMAT_VERSION {
            return Err(SmbVerifierSecretError::InvalidEnvelope);
        }
        let generation = u64::from_be_bytes(
            envelope[1..=GENERATION_BYTES]
                .try_into()
                .map_err(|_| SmbVerifierSecretError::InvalidEnvelope)?,
        );
        if generation == 0 {
            Err(SmbVerifierSecretError::InvalidEnvelope)
        } else {
            Ok(generation)
        }
    }

    /// Encrypts one verifier deterministically for idempotent replicated command replay.
    ///
    /// Determinism is safe here because the nonce is keyed and the immutable binding contains the
    /// unique API-key and method identities. A changed binding yields a different nonce and tag.
    ///
    /// # Errors
    ///
    /// Rejects invalid authority bindings or cryptographic failure.
    pub fn encrypt(
        &self,
        binding: SmbVerifierBinding,
        verifier: &NtlmPasswordVerifier,
        credential_digest: [u8; CREDENTIAL_DIGEST_BYTES],
    ) -> Result<Vec<u8>, SmbVerifierSecretError> {
        if credential_digest == [0; CREDENTIAL_DIGEST_BYTES] {
            return Err(SmbVerifierSecretError::InvalidCredential);
        }
        let aad = self.associated_data(binding)?;
        let mut plaintext = Zeroizing::new([0_u8; PLAINTEXT_BYTES]);
        plaintext[..VERIFIER_BYTES].copy_from_slice(verifier.expose_for_encryption());
        plaintext[VERIFIER_BYTES..].copy_from_slice(&credential_digest);
        let nonce = self.nonce(&aad, plaintext.as_ref())?;
        let encrypted = self
            .cipher()?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| SmbVerifierSecretError::Cryptographic)?;
        let mut envelope = Vec::with_capacity(ENVELOPE_BYTES);
        envelope.push(FORMAT_VERSION);
        envelope.extend_from_slice(&self.generation.to_be_bytes());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&encrypted);
        Ok(envelope)
    }

    /// Authenticates and restores one verifier against its exact replicated binding.
    ///
    /// # Errors
    ///
    /// Rejects malformed, substituted, tampered or wrong-key envelopes.
    pub fn decrypt(
        &self,
        binding: SmbVerifierBinding,
        envelope: &[u8],
    ) -> Result<SmbVerifierMaterial, SmbVerifierSecretError> {
        if envelope.len() != ENVELOPE_BYTES || envelope[0] != FORMAT_VERSION {
            return Err(SmbVerifierSecretError::InvalidEnvelope);
        }
        if Self::envelope_generation(envelope)? != self.generation {
            return Err(SmbVerifierSecretError::InvalidEnvelope);
        }
        let nonce = XNonce::try_from(&envelope[1 + GENERATION_BYTES..HEADER_BYTES])
            .map_err(|_| SmbVerifierSecretError::InvalidEnvelope)?;
        let aad = self.associated_data(binding)?;
        let plaintext = Zeroizing::new(
            self.cipher()?
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &envelope[HEADER_BYTES..],
                        aad: &aad,
                    },
                )
                .map_err(|_| SmbVerifierSecretError::InvalidEnvelope)?,
        );
        let verifier = <[u8; VERIFIER_BYTES]>::try_from(&plaintext[..VERIFIER_BYTES])
            .map_err(|_| SmbVerifierSecretError::InvalidEnvelope)?;
        let credential_digest =
            <[u8; CREDENTIAL_DIGEST_BYTES]>::try_from(&plaintext[VERIFIER_BYTES..])
                .map_err(|_| SmbVerifierSecretError::InvalidEnvelope)?;
        if credential_digest == [0; CREDENTIAL_DIGEST_BYTES] {
            return Err(SmbVerifierSecretError::InvalidEnvelope);
        }
        Ok(SmbVerifierMaterial {
            verifier: NtlmPasswordVerifier::from_bytes(verifier)
                .map_err(|_| SmbVerifierSecretError::InvalidEnvelope)?,
            credential_digest: Zeroizing::new(credential_digest),
        })
    }

    fn nonce(
        &self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<[u8; NONCE_BYTES], SmbVerifierSecretError> {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(self.key.nonce.as_ref())
            .map_err(|_| SmbVerifierSecretError::InvalidKey)?;
        mac.update(NONCE_DOMAIN);
        mac.update(aad);
        mac.update(plaintext);
        let mut nonce = [0; NONCE_BYTES];
        nonce.copy_from_slice(&mac.finalize().into_bytes()[..NONCE_BYTES]);
        if nonce == [0; NONCE_BYTES] {
            Err(SmbVerifierSecretError::Cryptographic)
        } else {
            Ok(nonce)
        }
    }

    fn associated_data(
        &self,
        binding: SmbVerifierBinding,
    ) -> Result<Vec<u8>, SmbVerifierSecretError> {
        let mut aad = binding.associated_data()?;
        aad.extend_from_slice(&self.generation.to_be_bytes());
        Ok(aad)
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, SmbVerifierSecretError> {
        XChaCha20Poly1305::new_from_slice(self.key.encryption.as_ref())
            .map_err(|_| SmbVerifierSecretError::InvalidKey)
    }
}

/// Closed SMB verifier-envelope failure without secret detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SmbVerifierSecretError {
    /// Derived key material is reserved or cannot initialise the cipher.
    #[error("SMB verifier envelope key is invalid")]
    InvalidKey,
    /// Method, principal, key or scope authority is invalid.
    #[error("SMB verifier binding is invalid")]
    InvalidBinding,
    /// The common API-key digest is reserved or missing.
    #[error("SMB verifier credential evidence is invalid")]
    InvalidCredential,
    /// Ciphertext format, authentication tag, key or binding failed validation.
    #[error("SMB verifier envelope is invalid")]
    InvalidEnvelope,
    /// The maintained cryptographic primitive failed closed.
    #[error("SMB verifier protection failed closed")]
    Cryptographic,
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{ApiKeyId, AuthenticationMethodId, PrincipalId};
    use meshspan_smb::NtlmPasswordVerifier;

    use super::{
        SmbVerifierBinding, SmbVerifierCipher, SmbVerifierEnvelopeKey, SmbVerifierSecretError,
    };

    #[test]
    fn envelope_is_replay_stable_and_binds_every_authoritative_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let cipher = cipher()?;
        let binding = binding()?;
        let verifier = NtlmPasswordVerifier::derive("meshspan_v1_fixture-secret")?;
        let first = cipher.encrypt(binding, &verifier, [8; 32])?;
        assert_eq!(first, cipher.encrypt(binding, &verifier, [8; 32])?);
        assert_eq!(first.len(), 97);
        assert_eq!(SmbVerifierCipher::envelope_generation(&first)?, 7);
        assert!(
            !first
                .windows(16)
                .any(|window| { window == verifier.expose_for_encryption().as_slice() })
        );
        let decrypted = cipher.decrypt(binding, &first)?;
        assert_eq!(
            decrypted.verifier().expose_for_encryption(),
            verifier.expose_for_encryption()
        );
        assert_eq!(decrypted.credential_digest(), [8; 32]);

        let changed = SmbVerifierBinding {
            scopes: 5,
            ..binding
        };
        assert!(matches!(
            cipher.decrypt(changed, &first),
            Err(SmbVerifierSecretError::InvalidEnvelope)
        ));
        let mut tampered = first;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            cipher.decrypt(binding, &tampered),
            Err(SmbVerifierSecretError::InvalidEnvelope)
        ));
        Ok(())
    }

    #[test]
    fn invalid_keys_and_non_smb_bindings_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            SmbVerifierEnvelopeKey::from_parts([0; 32], [2; 32]),
            Err(SmbVerifierSecretError::InvalidKey)
        ));
        let verifier = NtlmPasswordVerifier::derive("meshspan_v1_fixture-secret")?;
        let mut invalid = binding()?;
        invalid.service_scope = 1;
        assert!(matches!(
            cipher()?.encrypt(invalid, &verifier, [8; 32]),
            Err(SmbVerifierSecretError::InvalidBinding)
        ));
        assert_eq!(
            cipher()?.encrypt(binding()?, &verifier, [0; 32]),
            Err(SmbVerifierSecretError::InvalidCredential)
        );
        Ok(())
    }

    fn cipher() -> Result<SmbVerifierCipher, SmbVerifierSecretError> {
        SmbVerifierCipher::new(SmbVerifierEnvelopeKey::from_parts([1; 32], [2; 32])?, 7)
    }

    fn binding() -> Result<SmbVerifierBinding, meshspan_domain::IdentifierError> {
        Ok(SmbVerifierBinding {
            method_id: AuthenticationMethodId::from_bytes([3; 16])?,
            principal_id: PrincipalId::from_bytes([4; 16])?,
            key_id: ApiKeyId::from_bytes([5; 16])?,
            service_scope: 7,
            scopes: 7,
        })
    }
}
