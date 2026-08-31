// SPDX-License-Identifier: GPL-2.0-only

use std::fmt;
use std::sync::Arc;

use aes_gcm::aead::{AeadInOut, KeyInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use quinn_proto::crypto::{AeadKey, CryptoError, HandshakeTokenKey, HmacKey};
use quinn_proto::{EndpointConfig, ServerConfig};
use sha2::Sha256;
use zeroize::Zeroizing;

const HMAC_LENGTH: usize = 32;
const TOKEN_TAG_LENGTH: usize = 16;

/// Failure to obtain operating-system entropy for Quinn endpoint secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointKeyError;

impl fmt::Display for EndpointKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("operating-system entropy for QUIC endpoint keys is unavailable")
    }
}

impl std::error::Error for EndpointKeyError {}

/// Creates Quinn endpoint configuration with a fresh stateless-reset key.
///
/// # Errors
///
/// Fails closed when the operating system cannot provide cryptographic entropy.
pub fn endpoint_config() -> Result<EndpointConfig, EndpointKeyError> {
    let mut secret = Zeroizing::new([0; 64]);
    getrandom::fill(secret.as_mut()).map_err(|_| EndpointKeyError)?;
    Ok(EndpointConfig::new(Arc::new(ResetKey(secret))))
}

/// Creates Quinn server configuration with a fresh handshake-token master key.
///
/// # Errors
///
/// Fails closed when the operating system cannot provide cryptographic entropy.
pub fn server_config(
    crypto: Arc<dyn quinn_proto::crypto::ServerConfig>,
) -> Result<ServerConfig, EndpointKeyError> {
    let mut secret = Zeroizing::new([0; 64]);
    getrandom::fill(secret.as_mut()).map_err(|_| EndpointKeyError)?;
    Ok(ServerConfig::new(crypto, Arc::new(TokenKey(secret))))
}

struct ResetKey(Zeroizing<[u8; 64]>);

impl HmacKey for ResetKey {
    fn sign(&self, data: &[u8], signature: &mut [u8]) {
        if signature.len() != HMAC_LENGTH {
            signature.fill(0);
            return;
        }
        let Ok(mut hmac) = Hmac::<Sha256>::new_from_slice(self.0.as_ref()) else {
            signature.fill(0);
            return;
        };
        hmac.update(data);
        signature.copy_from_slice(hmac.finalize().into_bytes().as_ref());
    }

    fn signature_len(&self) -> usize {
        HMAC_LENGTH
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut hmac = Hmac::<Sha256>::new_from_slice(self.0.as_ref()).map_err(|_| CryptoError)?;
        hmac.update(data);
        hmac.verify_slice(signature).map_err(|_| CryptoError)
    }
}

struct TokenKey(Zeroizing<[u8; 64]>);

impl HandshakeTokenKey for TokenKey {
    fn aead_from_hkdf(&self, context: &[u8]) -> Box<dyn AeadKey> {
        let mut key = Zeroizing::new([0; 32]);
        let derived = Hkdf::<Sha256>::new(None, self.0.as_ref())
            .expand(context, key.as_mut())
            .is_ok();
        let cipher = derived
            .then(|| aes_gcm::Aes256Gcm::new_from_slice(key.as_ref()).ok())
            .flatten()
            .map(Box::new);
        Box::new(TokenAead(cipher))
    }
}

struct TokenAead(Option<Box<aes_gcm::Aes256Gcm>>);

impl AeadKey for TokenAead {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
        let cipher = self.0.as_ref().ok_or(CryptoError)?;
        let tag = cipher
            .encrypt_inout_detached(&[0; 12].into(), additional_data, data.as_mut_slice().into())
            .map_err(|_| CryptoError)?;
        data.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        let cipher = self.0.as_ref().ok_or(CryptoError)?;
        let plaintext_length = data
            .len()
            .checked_sub(TOKEN_TAG_LENGTH)
            .ok_or(CryptoError)?;
        let (ciphertext, tag) = data.split_at_mut(plaintext_length);
        let tag = aes_gcm::Tag::try_from(&*tag).map_err(|_| CryptoError)?;
        cipher
            .decrypt_inout_detached(&[0; 12].into(), additional_data, ciphertext.into(), &tag)
            .map_err(|_| CryptoError)?;
        Ok(ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use quinn_proto::crypto::{HandshakeTokenKey as _, HmacKey as _};
    use zeroize::Zeroizing;

    use super::{ResetKey, TokenKey};

    #[test]
    fn reset_signatures_verify_and_reject_substitution() {
        let key = ResetKey(Zeroizing::new([7; 64]));
        let mut signature = [0; 32];
        key.sign(b"reset binding", &mut signature);
        assert!(key.verify(b"reset binding", &signature).is_ok());
        assert!(key.verify(b"different binding", &signature).is_err());
    }

    #[test]
    fn independently_derived_token_keys_round_trip_and_reject_tampering() -> Result<(), &'static str>
    {
        let key = TokenKey(Zeroizing::new([9; 64]));
        let aead = key.aead_from_hkdf(b"token nonce");
        let mut token = b"bounded token".to_vec();
        assert!(aead.seal(&mut token, b"address binding").is_ok());
        let mut tampered = token.clone();
        let Some(last) = tampered.last_mut() else {
            return Err("sealed token unexpectedly empty");
        };
        *last ^= 1;
        assert!(aead.open(&mut tampered, b"address binding").is_err());
        let Ok(plaintext) = aead.open(&mut token, b"address binding") else {
            return Err("valid sealed token was rejected");
        };
        assert_eq!(plaintext, b"bounded token");
        Ok(())
    }
}
