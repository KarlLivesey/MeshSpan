// SPDX-License-Identifier: GPL-2.0-only

use std::boxed::Box;

use aes::cipher::{BlockCipherEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::aead::AeadInOut;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use rustls::Error;
use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic::{Algorithm, HeaderProtectionKey, PacketKey, Tag};

const SAMPLE_LENGTH: usize = 16;
const MASK_LENGTH: usize = 5;
const TAG_LENGTH: usize = 16;

#[derive(Debug)]
pub(crate) struct Aes128GcmQuic;

pub(crate) static AES_128_GCM: Aes128GcmQuic = Aes128GcmQuic;

impl Algorithm for Aes128GcmQuic {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
        Box::new(QuicPacketKey::aes(&key, iv))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        Box::new(AesHeaderKey(aes::Aes128::new_from_slice(key.as_ref()).ok()))
    }

    fn aead_key_len(&self) -> usize {
        16
    }
}

#[derive(Debug)]
pub(crate) struct Chacha20Poly1305Quic;

pub(crate) static CHACHA20_POLY1305: Chacha20Poly1305Quic = Chacha20Poly1305Quic;

impl Algorithm for Chacha20Poly1305Quic {
    fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn PacketKey> {
        Box::new(QuicPacketKey::chacha(&key, iv))
    }

    fn header_protection_key(&self, key: AeadKey) -> Box<dyn HeaderProtectionKey> {
        Box::new(ChachaHeaderKey(key.as_ref().try_into().ok()))
    }

    fn aead_key_len(&self) -> usize {
        32
    }
}

struct AesHeaderKey(Option<aes::Aes128>);

impl HeaderProtectionKey for AesHeaderKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        apply_mask(self.mask(sample)?, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        apply_mask(self.mask(sample)?, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        SAMPLE_LENGTH
    }
}

impl AesHeaderKey {
    fn mask(&self, sample: &[u8]) -> Result<[u8; MASK_LENGTH], Error> {
        let cipher = self.0.as_ref().ok_or_else(invalid_header_key)?;
        let sample: [u8; SAMPLE_LENGTH] = sample.try_into().map_err(|_| invalid_sample())?;
        let mut block = aes::Block::from(sample);
        cipher.encrypt_block(&mut block);
        block.as_slice()[..MASK_LENGTH]
            .try_into()
            .map_err(|_| invalid_sample())
    }
}

struct ChachaHeaderKey(Option<[u8; 32]>);

impl HeaderProtectionKey for ChachaHeaderKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        apply_mask(self.mask(sample)?, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        apply_mask(self.mask(sample)?, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        SAMPLE_LENGTH
    }
}

impl ChachaHeaderKey {
    fn mask(&self, sample: &[u8]) -> Result<[u8; MASK_LENGTH], Error> {
        let key = self.0.as_ref().ok_or_else(invalid_header_key)?;
        let sample: [u8; SAMPLE_LENGTH] = sample.try_into().map_err(|_| invalid_sample())?;
        let counter = u32::from_le_bytes(sample[..4].try_into().map_err(|_| invalid_sample())?);
        let mut cipher =
            chacha20::ChaCha20::new_from_slices(key, &sample[4..]).map_err(|_| invalid_sample())?;
        cipher.seek(u64::from(counter) * 64);
        let mut mask = [0; MASK_LENGTH];
        cipher.apply_keystream(&mut mask);
        Ok(mask)
    }
}

fn apply_mask(
    mask: [u8; MASK_LENGTH],
    first: &mut u8,
    packet_number: &mut [u8],
    removing: bool,
) -> Result<(), Error> {
    if packet_number.len() > MASK_LENGTH - 1 {
        return Err(Error::General("QUIC packet number is too long".into()));
    }
    let header_bits = if *first & 0x80 == 0x80 { 0x0f } else { 0x1f };
    let unmasked_first = if removing {
        *first ^ (mask[0] & header_bits)
    } else {
        *first
    };
    let packet_number_length = usize::from(unmasked_first & 0x03) + 1;
    *first ^= mask[0] & header_bits;
    for (byte, mask_byte) in packet_number
        .iter_mut()
        .zip(mask[1..].iter())
        .take(packet_number_length)
    {
        *byte ^= mask_byte;
    }
    Ok(())
}

enum PacketCipher {
    Aes128(Box<aes_gcm::Aes128Gcm>),
    Chacha20(Box<chacha20poly1305::ChaCha20Poly1305>),
    Invalid,
}

struct QuicPacketKey {
    cipher: PacketCipher,
    iv: Iv,
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl QuicPacketKey {
    fn aes(key: &AeadKey, iv: Iv) -> Self {
        Self {
            cipher: aes_gcm::Aes128Gcm::new_from_slice(key.as_ref())
                .map_or(PacketCipher::Invalid, |cipher| {
                    PacketCipher::Aes128(Box::new(cipher))
                }),
            iv,
            confidentiality_limit: 1 << 23,
            integrity_limit: 1 << 52,
        }
    }

    fn chacha(key: &AeadKey, iv: Iv) -> Self {
        Self {
            cipher: chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .map_or(PacketCipher::Invalid, |cipher| {
                    PacketCipher::Chacha20(Box::new(cipher))
                }),
            iv,
            confidentiality_limit: u64::MAX,
            integrity_limit: 1 << 36,
        }
    }
}

impl PacketKey for QuicPacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<Tag, Error> {
        let nonce = Nonce::new(&self.iv, packet_number).0;
        let tag = match &self.cipher {
            PacketCipher::Aes128(cipher) => cipher
                .encrypt_inout_detached(&nonce.into(), header, payload.into())
                .map_err(|_| Error::EncryptError)?,
            PacketCipher::Chacha20(cipher) => cipher
                .encrypt_inout_detached(&nonce.into(), header, payload.into())
                .map_err(|_| Error::EncryptError)?,
            PacketCipher::Invalid => return Err(Error::EncryptError),
        };
        Ok(Tag::from(tag.as_slice()))
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        if payload.len() < TAG_LENGTH {
            return Err(Error::DecryptError);
        }
        let plaintext_length = payload.len() - TAG_LENGTH;
        let (ciphertext, tag) = payload.split_at_mut(plaintext_length);
        let nonce = Nonce::new(&self.iv, packet_number).0;
        match &self.cipher {
            PacketCipher::Aes128(cipher) => {
                let tag = aes_gcm::Tag::try_from(&*tag).map_err(|_| Error::DecryptError)?;
                cipher
                    .decrypt_inout_detached(&nonce.into(), header, ciphertext.into(), &tag)
                    .map_err(|_| Error::DecryptError)?;
            }
            PacketCipher::Chacha20(cipher) => {
                let tag =
                    chacha20poly1305::Tag::try_from(&*tag).map_err(|_| Error::DecryptError)?;
                cipher
                    .decrypt_inout_detached(&nonce.into(), header, ciphertext.into(), &tag)
                    .map_err(|_| Error::DecryptError)?;
            }
            PacketCipher::Invalid => return Err(Error::DecryptError),
        }
        Ok(&payload[..plaintext_length])
    }

    fn tag_len(&self) -> usize {
        TAG_LENGTH
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

fn invalid_sample() -> Error {
    Error::General("QUIC header protection sample has an invalid length".into())
}

fn invalid_header_key() -> Error {
    Error::General("QUIC header protection key has an invalid length".into())
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;

    use aes::cipher::KeyInit as _;
    use rustls::crypto::cipher::Iv;
    use rustls::quic::{HeaderProtectionKey as _, PacketKey as _};

    use super::{AesHeaderKey, ChachaHeaderKey, PacketCipher, QuicPacketKey};

    #[test]
    fn rfc_9001_aes_header_protection_vector_matches() -> Result<(), Box<dyn StdError>> {
        let key = hex::<16>("9f50449e04a0e810283a1e9933adedd2")?;
        let sample = hex::<16>("d1b1c98dd7689fb8ec11d242b123dc9b")?;
        let key = AesHeaderKey(Some(aes::Aes128::new(&key.into())));
        let mut first = 0xc3;
        let mut packet_number = [0, 0, 0, 2];

        key.encrypt_in_place(&sample, &mut first, &mut packet_number)?;
        assert_eq!(first, 0xc0);
        assert_eq!(packet_number, [0x7b, 0x9a, 0xec, 0x34]);

        key.decrypt_in_place(&sample, &mut first, &mut packet_number)?;
        assert_eq!(first, 0xc3);
        assert_eq!(packet_number, [0, 0, 0, 2]);
        Ok(())
    }

    #[test]
    fn rfc_9001_aes_packet_vector_matches_and_rejects_tampering() -> Result<(), Box<dyn StdError>> {
        let key = hex::<16>("cf3a5331653c364c88f0f379b6067e37")?;
        let iv = hex::<12>("0ac1493ca1905853b0bba03e")?;
        let header = decode_hex("c1000000010008f067a5502a4262b50040750001")?;
        let plaintext = decode_hex(concat!(
            "02000000000600405a020000560303ee",
            "fce7f7b37ba1d1632e96677825ddf739",
            "88cfc79825df566dc5430b9a045a1200",
            "130100002e00330024001d00209d3c94",
            "0d89690b84d08a60993c144eca684d10",
            "81287c834d5311bcf32bb9da1a002b00",
            "020304"
        ))?;
        let expected = decode_hex(concat!(
            "5a482cd0991cd25b0aac406a5816b639",
            "4100f37a1c69797554780bb38cc5a99f",
            "5ede4cf73c3ec2493a1839b3dbcba3f6",
            "ea46c5b7684df3548e7ddeb9c3bf9c73",
            "cc3f3bded74b562bfb19fb84022f8ef4",
            "cdd93795d77d06edbb7aaf2f58891850",
            "abbdca3d20398c276456cbc42158407d",
            "d074ee"
        ))?;
        let packet_key = QuicPacketKey {
            cipher: PacketCipher::Aes128(Box::new(aes_gcm::Aes128Gcm::new(&key.into()))),
            iv: Iv::from(iv),
            confidentiality_limit: 1 << 23,
            integrity_limit: 1 << 52,
        };
        let mut protected = plaintext.clone();
        let tag = packet_key.encrypt_in_place(1, &header, &mut protected)?;
        protected.extend_from_slice(tag.as_ref());
        assert_eq!(protected, expected);

        let mut tampered = protected.clone();
        let Some(last) = tampered.last_mut() else {
            return Err("RFC vector unexpectedly empty".into());
        };
        *last ^= 1;
        assert!(
            packet_key
                .decrypt_in_place(1, &header, &mut tampered)
                .is_err()
        );
        assert_eq!(
            packet_key.decrypt_in_place(1, &header, &mut protected)?,
            plaintext
        );
        Ok(())
    }

    #[test]
    fn rfc_9001_chacha_packet_and_header_vectors_match() -> Result<(), Box<dyn StdError>> {
        let key = hex::<32>("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")?;
        let iv = hex::<12>("e0459b3474bdd0e44a41c144")?;
        let packet_key = QuicPacketKey {
            cipher: PacketCipher::Chacha20(Box::new(chacha20poly1305::ChaCha20Poly1305::new(
                &key.into(),
            ))),
            iv: Iv::from(iv),
            confidentiality_limit: u64::MAX,
            integrity_limit: 1 << 36,
        };
        let mut protected = vec![1];
        let header = [0x42, 0, 0xbf, 0xf4];
        let tag = packet_key.encrypt_in_place(654_360_564, &header, &mut protected)?;
        protected.extend_from_slice(tag.as_ref());
        assert_eq!(protected, decode_hex("655e5cd55c41f69080575d7999c25a5bfb")?);

        let header_key = ChachaHeaderKey(Some(hex::<32>(
            "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4",
        )?));
        let sample: [u8; 16] = protected[1..].try_into()?;
        let mut first = header[0];
        let mut packet_number = [header[1], header[2], header[3]];
        header_key.encrypt_in_place(&sample, &mut first, &mut packet_number)?;
        assert_eq!(
            [first, packet_number[0], packet_number[1], packet_number[2]],
            [0x4c, 0xfe, 0x41, 0x89,]
        );
        Ok(())
    }

    fn hex<const LENGTH: usize>(input: &str) -> Result<[u8; LENGTH], Box<dyn StdError>> {
        decode_hex(input)?
            .try_into()
            .map_err(|_| "hex fixture has an unexpected length".into())
    }

    fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn StdError>> {
        if !input.len().is_multiple_of(2) {
            return Err("hex fixture has an odd length".into());
        }
        let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
        if !remainder.is_empty() {
            return Err("hex fixture has an incomplete byte".into());
        }
        pairs
            .iter()
            .map(|pair| {
                let pair = std::str::from_utf8(pair)?;
                Ok(u8::from_str_radix(pair, 16)?)
            })
            .collect()
    }
}
