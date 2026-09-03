// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::{Rfc2136Request, Rfc2136TsigKey, TsigAlgorithm, TxtUpdate};

#[test]
fn encodes_atomic_publish_with_full_authenticated_tsig() -> Result<(), Box<dyn Error>> {
    let secret = b"0123456789abcdef0123456789abcdef";
    let key = Rfc2136TsigKey::new(
        "meshspan-key.example.test",
        TsigAlgorithm::HmacSha256,
        secret.to_vec(),
    )?;
    let request = Rfc2136Request::new(
        0x1234,
        "example.test",
        "_acme-challenge.example.test",
        b"proof-token",
        TxtUpdate::Publish { ttl_seconds: 30 },
        1_700_000_000,
        300,
    )?;
    let signed = request.sign(&key)?;
    let bytes = signed.as_bytes();

    assert_eq!(&bytes[..12], &[0x12, 0x34, 0x28, 0, 0, 1, 0, 0, 0, 1, 0, 1]);
    let mac = signed.request_mac();
    assert_eq!(mac.len(), 32);
    assert!(find_subsequence(bytes, mac).is_some());
    let unsigned_end = locate_tsig(bytes).ok_or("TSIG owner was not encoded")?;
    let mut unsigned = bytes[..unsigned_end].to_vec();
    unsigned[10..12].copy_from_slice(&0_u16.to_be_bytes());
    let mut variables = Vec::new();
    encode_name(&mut variables, "meshspan-key.example.test")?;
    variables.extend_from_slice(&255_u16.to_be_bytes());
    variables.extend_from_slice(&0_u32.to_be_bytes());
    encode_name(&mut variables, "hmac-sha256")?;
    variables.extend_from_slice(&1_700_000_000_u64.to_be_bytes()[2..]);
    variables.extend_from_slice(&300_u16.to_be_bytes());
    variables.extend_from_slice(&[0_u8; 4]);
    unsigned.extend_from_slice(&variables);
    let mut verifier = Hmac::<Sha256>::new_from_slice(secret)?;
    verifier.update(&unsigned);
    verifier.verify_slice(mac)?;
    Ok(())
}

#[test]
fn rejects_out_of_zone_owner_and_invalid_publish_ttl() {
    assert!(
        Rfc2136Request::new(
            1,
            "example.test",
            "_acme-challenge.attacker.test",
            b"proof",
            TxtUpdate::Publish { ttl_seconds: 30 },
            1_700_000_000,
            300,
        )
        .is_err()
    );
    assert!(
        Rfc2136Request::new(
            1,
            "example.test",
            "_acme-challenge.example.test",
            b"proof",
            TxtUpdate::Publish { ttl_seconds: 0 },
            1_700_000_000,
            300,
        )
        .is_err()
    );
}

fn locate_tsig(bytes: &[u8]) -> Option<usize> {
    let mut encoded = Vec::new();
    encode_name(&mut encoded, "meshspan-key.example.test").ok()?;
    let suffix = [0_u8, 250, 0, 255];
    encoded.extend_from_slice(&suffix);
    find_subsequence(bytes, &encoded)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn encode_name(output: &mut Vec<u8>, name: &str) -> Result<(), Box<dyn Error>> {
    for label in name.split('.') {
        output.push(u8::try_from(label.len())?);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}
