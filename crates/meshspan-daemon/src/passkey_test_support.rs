// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use meshspan_api_contract::SessionAuthentication;
use meshspan_domain::{EntropyError, PrincipalId, RandomSource};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

pub(crate) const RELYING_PARTY: &str = "files.example.test";
pub(crate) const ORIGIN: &str = "https://files.example.test";
pub(crate) const CREDENTIAL_ID: &[u8] = b"credential-one";

pub(crate) fn assertion(
    challenge_id: &str,
    challenge: &str,
    principal_id: PrincipalId,
    sign_count: u32,
) -> Result<SessionAuthentication, Box<dyn std::error::Error>> {
    let signing_key = signing_key()?;
    let client_data = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"{ORIGIN}\",\"crossOrigin\":false}}"
    );
    let mut authenticator_data = Vec::from(Sha256::digest(RELYING_PARTY.as_bytes()).as_slice());
    authenticator_data.push(0x05);
    authenticator_data.extend_from_slice(&sign_count.to_be_bytes());
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
    let signature: Signature = signing_key.sign(&signed);
    Ok(SessionAuthentication::Passkey {
        challenge_id: challenge_id.to_owned(),
        credential_id: encode_base64url(CREDENTIAL_ID),
        client_data_json: encode_base64url(client_data.as_bytes()),
        authenticator_data: encode_base64url(&authenticator_data),
        signature: encode_base64url(signature.to_der().as_bytes()),
        user_handle: Some(encode_base64url(&principal_id.as_bytes())),
    })
}

pub(crate) fn public_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(signing_key()?
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec())
}

fn signing_key() -> Result<SigningKey, p256::ecdsa::Error> {
    SigningKey::from_slice(&[0x42; 32])
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

#[derive(Default)]
pub(crate) struct CountingRandom {
    calls: Arc<AtomicUsize>,
}

impl RandomSource for CountingRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        let value = u8::try_from(self.calls.fetch_add(1, Ordering::SeqCst) + 1)
            .map_err(|_| EntropyError)?;
        destination.fill(value);
        Ok(())
    }
}
