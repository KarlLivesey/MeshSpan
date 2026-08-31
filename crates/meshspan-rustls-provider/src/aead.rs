// SPDX-License-Identifier: GPL-2.0-only

use std::boxed::Box;

use aes_gcm::aead::{AeadInOut, KeyInit};
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};

const TAG_LENGTH: usize = 16;

#[derive(Debug)]
pub(crate) struct Aes128GcmAlgorithm;

pub(crate) static AES_128_GCM: Aes128GcmAlgorithm = Aes128GcmAlgorithm;

impl Tls13AeadAlgorithm for Aes128GcmAlgorithm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher::aes(&key, iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher::aes(&key, iv))
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }
}

#[derive(Debug)]
pub(crate) struct Chacha20Poly1305Algorithm;

pub(crate) static CHACHA20_POLY1305: Chacha20Poly1305Algorithm = Chacha20Poly1305Algorithm;

impl Tls13AeadAlgorithm for Chacha20Poly1305Algorithm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher::chacha(&key, iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher::chacha(&key, iv))
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

enum Cipher {
    Aes128(Box<aes_gcm::Aes128Gcm>),
    Chacha20(Box<chacha20poly1305::ChaCha20Poly1305>),
    Invalid,
}

struct Tls13Cipher {
    cipher: Cipher,
    iv: Iv,
}

impl Tls13Cipher {
    fn aes(key: &AeadKey, iv: Iv) -> Self {
        Self {
            cipher: aes_gcm::Aes128Gcm::new_from_slice(key.as_ref())
                .map_or(Cipher::Invalid, |cipher| Cipher::Aes128(Box::new(cipher))),
            iv,
        }
    }

    fn chacha(key: &AeadKey, iv: Iv) -> Self {
        Self {
            cipher: chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .map_or(Cipher::Invalid, |cipher| Cipher::Chacha20(Box::new(cipher))),
            iv,
        }
    }

    fn encrypt_detached(
        &self,
        nonce: [u8; 12],
        additional_data: &[u8],
        payload: &mut [u8],
    ) -> Result<[u8; TAG_LENGTH], Error> {
        let tag = match &self.cipher {
            Cipher::Aes128(cipher) => cipher
                .encrypt_inout_detached(&nonce.into(), additional_data, payload.into())
                .map_err(|_| Error::EncryptError)?,
            Cipher::Chacha20(cipher) => cipher
                .encrypt_inout_detached(&nonce.into(), additional_data, payload.into())
                .map_err(|_| Error::EncryptError)?,
            Cipher::Invalid => return Err(Error::EncryptError),
        };
        tag.as_slice().try_into().map_err(|_| Error::EncryptError)
    }

    fn decrypt_detached(
        &self,
        nonce: [u8; 12],
        additional_data: &[u8],
        payload: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        match &self.cipher {
            Cipher::Aes128(cipher) => {
                let tag = aes_gcm::Tag::try_from(tag).map_err(|_| Error::DecryptError)?;
                cipher
                    .decrypt_inout_detached(&nonce.into(), additional_data, payload.into(), &tag)
                    .map_err(|_| Error::DecryptError)
            }
            Cipher::Chacha20(cipher) => {
                let tag = chacha20poly1305::Tag::try_from(tag).map_err(|_| Error::DecryptError)?;
                cipher
                    .decrypt_inout_detached(&nonce.into(), additional_data, payload.into(), &tag)
                    .map_err(|_| Error::DecryptError)
            }
            Cipher::Invalid => Err(Error::DecryptError),
        }
    }
}

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        message: OutboundPlainMessage<'_>,
        sequence: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_length = self.encrypted_payload_len(message.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_length);
        payload.extend_from_chunks(&message.payload);
        payload.extend_from_slice(&message.typ.to_array());
        let nonce = Nonce::new(&self.iv, sequence).0;
        let tag = self.encrypt_detached(nonce, &make_tls13_aad(total_length), payload.as_mut())?;
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_length: usize) -> usize {
        payload_length + 1 + TAG_LENGTH
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut message: InboundOpaqueMessage<'a>,
        sequence: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let encrypted_length = message.payload.len();
        if encrypted_length < TAG_LENGTH {
            return Err(Error::DecryptError);
        }
        let plaintext_length = encrypted_length - TAG_LENGTH;
        let (payload, tag) = message.payload.as_mut().split_at_mut(plaintext_length);
        self.decrypt_detached(
            Nonce::new(&self.iv, sequence).0,
            &make_tls13_aad(encrypted_length),
            payload,
            tag,
        )?;
        message.payload.truncate(plaintext_length);
        message.into_tls13_unpadded_message()
    }
}
