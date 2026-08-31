// SPDX-License-Identifier: GPL-2.0-only

use aes_gcm::aead::{AeadInOut, KeyInit};
use quinn_proto::ConnectionId;
use rustls::quic::Version;

const TAG_LENGTH: usize = 16;

const RETRY_INTEGRITY_KEY_DRAFT: [u8; 16] = [
    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
];
const RETRY_INTEGRITY_NONCE_DRAFT: [u8; 12] = [
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
];
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

pub(crate) fn tag(
    version: Version,
    original_destination: &ConnectionId,
    packet: &[u8],
) -> [u8; TAG_LENGTH] {
    let Some((key, nonce)) = key_and_nonce(version) else {
        return [0; TAG_LENGTH];
    };
    let Ok(cipher) = aes_gcm::Aes128Gcm::new_from_slice(&key) else {
        return [0; TAG_LENGTH];
    };
    let pseudo_packet = pseudo_packet(original_destination, packet);
    let mut empty = [];
    let Ok(tag) =
        cipher.encrypt_inout_detached(&nonce.into(), &pseudo_packet, empty.as_mut_slice().into())
    else {
        return [0; TAG_LENGTH];
    };
    tag.as_slice().try_into().unwrap_or([0; TAG_LENGTH])
}

pub(crate) fn valid(
    version: Version,
    original_destination: &ConnectionId,
    header: &[u8],
    payload: &[u8],
) -> bool {
    let Some(tag_start) = payload.len().checked_sub(TAG_LENGTH) else {
        return false;
    };
    let (body, tag) = payload.split_at(tag_start);
    let Some((key, nonce)) = key_and_nonce(version) else {
        return false;
    };
    let Ok(cipher) = aes_gcm::Aes128Gcm::new_from_slice(&key) else {
        return false;
    };
    let mut packet = Vec::with_capacity(header.len() + body.len());
    packet.extend_from_slice(header);
    packet.extend_from_slice(body);
    let pseudo_packet = pseudo_packet(original_destination, &packet);
    let Ok(tag) = aes_gcm::Tag::try_from(tag) else {
        return false;
    };
    let mut empty = [];
    cipher
        .decrypt_inout_detached(
            &nonce.into(),
            &pseudo_packet,
            empty.as_mut_slice().into(),
            &tag,
        )
        .is_ok()
}

fn pseudo_packet(original_destination: &ConnectionId, packet: &[u8]) -> Vec<u8> {
    let mut pseudo_packet = Vec::with_capacity(1 + original_destination.len() + packet.len());
    pseudo_packet.push(u8::try_from(original_destination.len()).unwrap_or(u8::MAX));
    pseudo_packet.extend_from_slice(original_destination);
    pseudo_packet.extend_from_slice(packet);
    pseudo_packet
}

const fn key_and_nonce(version: Version) -> Option<([u8; 16], [u8; 12])> {
    match version {
        Version::V1 => Some((RETRY_INTEGRITY_KEY_V1, RETRY_INTEGRITY_NONCE_V1)),
        Version::V1Draft => Some((RETRY_INTEGRITY_KEY_DRAFT, RETRY_INTEGRITY_NONCE_DRAFT)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use quinn_proto::ConnectionId;
    use rustls::quic::Version;

    use super::{tag, valid};

    #[test]
    fn rfc_9001_retry_integrity_vector_matches() -> Result<(), Box<dyn Error>> {
        let original_destination = ConnectionId::new(&decode_hex("8394c8f03e515708")?);
        let packet = decode_hex("ff000000010008f067a5502a4262b5746f6b656e")?;
        let expected = decode_hex("04a265ba2eff4d829058fb3f0f2496ba")?;
        assert_eq!(
            tag(Version::V1, &original_destination, &packet),
            expected.as_slice()
        );
        assert!(valid(
            Version::V1,
            &original_destination,
            &packet,
            &expected,
        ));
        let mut substituted = expected;
        let Some(last) = substituted.last_mut() else {
            return Err("retry tag fixture unexpectedly empty".into());
        };
        *last ^= 1;
        assert!(!valid(
            Version::V1,
            &original_destination,
            &packet,
            &substituted,
        ));
        Ok(())
    }

    fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
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
