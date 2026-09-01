// SPDX-License-Identifier: GPL-2.0-only

//! Independent headless authenticator evidence for the black-box HTTPS process proof.

use std::error::Error;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

const CREDENTIAL_ID: &[u8] = b"headless-passkey";

pub struct RegistrationEvidence {
    pub credential_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
}

pub struct AssertionEvidence {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: String,
}

pub fn registration(
    challenge: &str,
    relying_party_id: &str,
    origin: &str,
) -> Result<RegistrationEvidence, Box<dyn Error>> {
    let signing_key = signing_key()?;
    let point = signing_key.verifying_key().to_sec1_point(false);
    let public_key: [u8; 65] = point.as_bytes().try_into()?;
    let client_data = client_data("webauthn.create", challenge, origin);
    let mut authenticator_data = Vec::from(Sha256::digest(relying_party_id.as_bytes()).as_slice());
    authenticator_data.push(0x45);
    authenticator_data.extend_from_slice(&0_u32.to_be_bytes());
    authenticator_data.extend_from_slice(&[0x33; 16]);
    authenticator_data.extend_from_slice(&u16::try_from(CREDENTIAL_ID.len())?.to_be_bytes());
    authenticator_data.extend_from_slice(CREDENTIAL_ID);
    authenticator_data.push(0xa5);
    authenticator_data.extend_from_slice(&[0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]);
    cbor_bytes(&mut authenticator_data, &public_key[1..33])?;
    authenticator_data.push(0x22);
    cbor_bytes(&mut authenticator_data, &public_key[33..65])?;
    let mut attestation = vec![0xa3];
    cbor_text(&mut attestation, "fmt")?;
    cbor_text(&mut attestation, "none")?;
    cbor_text(&mut attestation, "attStmt")?;
    attestation.push(0xa0);
    cbor_text(&mut attestation, "authData")?;
    cbor_bytes(&mut attestation, &authenticator_data)?;
    Ok(RegistrationEvidence {
        credential_id: encode_base64url(CREDENTIAL_ID),
        client_data_json: encode_base64url(client_data.as_bytes()),
        attestation_object: encode_base64url(&attestation),
    })
}

pub fn assertion(
    challenge: &str,
    relying_party_id: &str,
    origin: &str,
    user_handle: &str,
) -> Result<AssertionEvidence, Box<dyn Error>> {
    let client_data = client_data("webauthn.get", challenge, origin);
    let mut authenticator_data = Vec::from(Sha256::digest(relying_party_id.as_bytes()).as_slice());
    authenticator_data.push(0x05);
    authenticator_data.extend_from_slice(&1_u32.to_be_bytes());
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
    let signature: Signature = signing_key()?.sign(&signed);
    Ok(AssertionEvidence {
        credential_id: encode_base64url(CREDENTIAL_ID),
        client_data_json: encode_base64url(client_data.as_bytes()),
        authenticator_data: encode_base64url(&authenticator_data),
        signature: encode_base64url(signature.to_der().as_bytes()),
        user_handle: user_handle.to_owned(),
    })
}

fn signing_key() -> Result<SigningKey, p256::ecdsa::Error> {
    SigningKey::from_slice(&[0x44; 32])
}

fn client_data(kind: &str, challenge: &str, origin: &str) -> String {
    format!(
        "{{\"type\":\"{kind}\",\"challenge\":\"{challenge}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}"
    )
}

fn encode_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for block in bytes.chunks(3) {
        let bits = u32::from(block[0]) << 16
            | u32::from(*block.get(1).unwrap_or(&0)) << 8
            | u32::from(*block.get(2).unwrap_or(&0));
        encoded.push(char::from(ALPHABET[((bits >> 18) & 63) as usize]));
        encoded.push(char::from(ALPHABET[((bits >> 12) & 63) as usize]));
        if block.len() > 1 {
            encoded.push(char::from(ALPHABET[((bits >> 6) & 63) as usize]));
        }
        if block.len() > 2 {
            encoded.push(char::from(ALPHABET[(bits & 63) as usize]));
        }
    }
    encoded
}

fn cbor_text(output: &mut Vec<u8>, value: &str) -> Result<(), Box<dyn Error>> {
    let length = u8::try_from(value.len())?;
    if length >= 24 {
        return Err("test CBOR text is too long".into());
    }
    output.push(0x60 | length);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn cbor_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Box<dyn Error>> {
    if value.len() < 24 {
        output.push(0x40 | u8::try_from(value.len())?);
    } else {
        output.extend_from_slice(&[0x58, u8::try_from(value.len())?]);
    }
    output.extend_from_slice(value);
    Ok(())
}
