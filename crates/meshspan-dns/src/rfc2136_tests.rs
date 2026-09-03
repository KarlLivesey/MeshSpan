// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::{
    Rfc2136Request, Rfc2136ResponseError, Rfc2136TsigKey, SignedRfc2136Request, TsigAlgorithm,
    TxtUpdate,
};

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

#[test]
fn authenticates_exact_response_and_rejects_tampering() -> Result<(), Box<dyn Error>> {
    let secret = b"0123456789abcdef0123456789abcdef";
    let key = Rfc2136TsigKey::new(
        "meshspan-key.example.test",
        TsigAlgorithm::HmacSha256,
        secret.to_vec(),
    )?;
    let request = Rfc2136Request::new(
        0x4321,
        "example.test",
        "_acme-challenge.example.test",
        b"proof-token",
        TxtUpdate::Remove,
        1_700_000_000,
        300,
    )?
    .sign(&key)?;
    let response = signed_success_response(&request, secret, 1_700_000_001)?;
    request.verify_response(&response, &key, 1_700_000_002)?;
    assert_eq!(
        request.verify_response(&response, &key, 1_700_001_000),
        Err(Rfc2136ResponseError::Authentication)
    );

    let mut tampered = response;
    tampered[3] ^= 1;
    assert_eq!(
        request.verify_response(&tampered, &key, 1_700_000_002),
        Err(Rfc2136ResponseError::Authentication)
    );
    assert_eq!(
        request.verify_response(
            &[0x43, 0x21, 0xa8, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &key,
            1_700_000_002,
        ),
        Err(Rfc2136ResponseError::Authentication)
    );
    Ok(())
}

fn signed_success_response(
    request: &SignedRfc2136Request,
    secret: &[u8],
    signed_at_seconds: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut unsigned = Vec::from(request.id().to_be_bytes());
    unsigned.extend_from_slice(&0xa800_u16.to_be_bytes());
    unsigned.extend_from_slice(&[0_u8; 8]);
    let mut variables = Vec::new();
    encode_name(&mut variables, "meshspan-key.example.test")?;
    variables.extend_from_slice(&255_u16.to_be_bytes());
    variables.extend_from_slice(&0_u32.to_be_bytes());
    encode_name(&mut variables, "hmac-sha256")?;
    variables.extend_from_slice(&signed_at_seconds.to_be_bytes()[2..]);
    variables.extend_from_slice(&300_u16.to_be_bytes());
    variables.extend_from_slice(&[0_u8; 4]);
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&u16::try_from(request.request_mac().len())?.to_be_bytes());
    mac_input.extend_from_slice(request.request_mac());
    mac_input.extend_from_slice(&unsigned);
    mac_input.extend_from_slice(&variables);
    let mut signer = Hmac::<Sha256>::new_from_slice(secret)?;
    signer.update(&mac_input);
    let mac = signer.finalize().into_bytes();

    let mut response = unsigned;
    response[10..12].copy_from_slice(&1_u16.to_be_bytes());
    encode_name(&mut response, "meshspan-key.example.test")?;
    response.extend_from_slice(&250_u16.to_be_bytes());
    response.extend_from_slice(&255_u16.to_be_bytes());
    response.extend_from_slice(&0_u32.to_be_bytes());
    let mut rdata = Vec::new();
    encode_name(&mut rdata, "hmac-sha256")?;
    rdata.extend_from_slice(&signed_at_seconds.to_be_bytes()[2..]);
    rdata.extend_from_slice(&300_u16.to_be_bytes());
    rdata.extend_from_slice(&u16::try_from(mac.len())?.to_be_bytes());
    rdata.extend_from_slice(&mac);
    rdata.extend_from_slice(&request.id().to_be_bytes());
    rdata.extend_from_slice(&[0_u8; 4]);
    response.extend_from_slice(&u16::try_from(rdata.len())?.to_be_bytes());
    response.extend_from_slice(&rdata);
    Ok(response)
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
