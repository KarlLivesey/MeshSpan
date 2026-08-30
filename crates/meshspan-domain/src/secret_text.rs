// SPDX-License-Identifier: GPL-2.0-only

//! Shared exact lowercase encoding for secret-bearing local credential bundles.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::OperationId;

pub(crate) const IDENTIFIER_BYTES: usize = 16;
pub(crate) const SECRET_BYTES: usize = 32;

pub(crate) fn encode(
    prefix: &str,
    identifier: &[u8; IDENTIFIER_BYTES],
    secret: &[u8; SECRET_BYTES],
) -> Zeroizing<String> {
    let mut encoded = Zeroizing::new(String::with_capacity(prefix.len() + 97));
    encoded.push_str(prefix);
    append_hex(&mut encoded, identifier);
    encoded.push('.');
    append_hex(&mut encoded, secret);
    encoded
}

pub(crate) fn decode(
    value: &str,
    prefix: &str,
) -> Option<([u8; IDENTIFIER_BYTES], [u8; SECRET_BYTES])> {
    if value.len() != prefix.len() + 97 {
        return None;
    }
    let body = value.strip_prefix(prefix)?;
    let (identifier, secret) = body.split_once('.')?;
    Some((
        decode_hex::<IDENTIFIER_BYTES>(identifier)?,
        decode_hex::<SECRET_BYTES>(secret)?,
    ))
}

pub(crate) fn derive(
    domain: &[u8],
    secret: &[u8; SECRET_BYTES],
    operation_id: OperationId,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(secret);
    digest.update(operation_id.as_bytes());
    digest.finalize().into()
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut decoded = [0_u8; N];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() || pairs.len() != N {
        return None;
    }
    for (destination, pair) in decoded.iter_mut().zip(pairs) {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        *destination = (high << 4) | low;
    }
    Some(decoded)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
