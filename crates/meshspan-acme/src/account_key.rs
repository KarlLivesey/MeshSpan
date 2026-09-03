// SPDX-License-Identifier: GPL-2.0-only

//! RustCrypto-backed ACME account key with no private-key export surface.

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use thiserror::Error;

use crate::{AcmeJwsSigner, AcmeProtocolError, AcmePublicJwk};

const P256_SECRET_BYTES: usize = 32;

/// One decrypted ACME account key confined to the worker which owns the fenced order.
pub struct AcmeAccountKey {
    signing_key: SigningKey,
}

impl AcmeAccountKey {
    /// Loads one exact P-256 scalar from a protected secret envelope.
    ///
    /// # Errors
    ///
    /// Rejects wrong-length, zero, out-of-range or otherwise invalid key material.
    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self, AcmeAccountKeyError> {
        if secret.len() != P256_SECRET_BYTES {
            return Err(AcmeAccountKeyError::InvalidSecret);
        }
        let signing_key =
            SigningKey::from_slice(secret).map_err(|_| AcmeAccountKeyError::InvalidSecret)?;
        Ok(Self { signing_key })
    }
}

impl AcmeJwsSigner for AcmeAccountKey {
    fn public_jwk(&self) -> Result<AcmePublicJwk, AcmeProtocolError> {
        let point = self.signing_key.verifying_key().to_sec1_point(false);
        let x = point.x().ok_or(AcmeProtocolError::InvalidSigner)?;
        let y = point.y().ok_or(AcmeProtocolError::InvalidSigner)?;
        AcmePublicJwk::new(
            crate::wire::encode_base64url(x),
            crate::wire::encode_base64url(y),
        )
    }

    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, AcmeProtocolError> {
        let signature: Signature = self.signing_key.sign(signing_input);
        let signature = signature.normalize_s();
        Ok(signature.to_bytes().to_vec())
    }
}

/// Closed account-key decoding failure without key material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcmeAccountKeyError {
    /// Secret bytes are not one canonical P-256 scalar.
    #[error("ACME account key is invalid")]
    InvalidSecret,
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Verifier as _;

    use super::*;

    #[test]
    fn account_key_signs_raw_low_s_es256_and_rejects_bad_scalars()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            AcmeAccountKey::from_secret_bytes(&[0; P256_SECRET_BYTES]).err(),
            Some(AcmeAccountKeyError::InvalidSecret)
        );
        let mut scalar = [0; P256_SECRET_BYTES];
        scalar[P256_SECRET_BYTES - 1] = 1;
        let key = AcmeAccountKey::from_secret_bytes(&scalar)?;
        let input = b"protected.payload";
        let encoded = key.sign(input)?;
        assert_eq!(encoded.len(), 64);
        let signature = Signature::from_slice(&encoded)?;
        assert_eq!(signature, signature.normalize_s());
        key.signing_key.verifying_key().verify(input, &signature)?;
        assert_eq!(key.public_jwk()?.thumbprint().len(), 43);
        Ok(())
    }
}
