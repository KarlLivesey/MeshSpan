// SPDX-License-Identifier: GPL-2.0-only

//! Exact none-attestation ES256 registration and hostile-CBOR vectors.

use p256::ecdsa::SigningKey;

use meshspan_passkey::{
    PasskeyErrorKind, Registration, RegistrationExpectation, UserVerification, verify_registration,
};
use sha2::{Digest, Sha256};

const CHALLENGE: [u8; 32] = [0x22; 32];
const CHALLENGE_TEXT: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI";
const CREDENTIAL_ID: &[u8] = b"new-credential";
const RELYING_PARTY: &str = "files.example.test";
const ORIGIN: &str = "https://files.example.test";
const ORIGINS: &[&str] = &[ORIGIN];

#[test]
fn exact_none_attestation_registration_produces_storable_key()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let outcome = verify_registration(&fixture.registration(), &expectation())?;
    assert_eq!(outcome.credential_id, CREDENTIAL_ID);
    assert_eq!(outcome.public_key.as_bytes(), fixture.public_key.as_slice());
    assert_eq!(outcome.aaguid, [0x33; 16]);
    assert_eq!(outcome.sign_count, 0);
    assert!(outcome.user_verified);
    assert!(!outcome.backup_eligible);
    assert!(!outcome.backup_state);
    Ok(())
}

#[test]
fn duplicate_unknown_and_non_none_attestation_fields_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut duplicate = fixture.attestation.clone();
    duplicate[0] = 0xa4;
    duplicate.extend_from_slice(&[0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']);
    assert_kind(
        verify_registration(
            &Registration {
                attestation_object: &duplicate,
                ..fixture.registration()
            },
            &expectation(),
        ),
        PasskeyErrorKind::Malformed,
    );

    let mut packed = fixture.attestation.clone();
    let marker = [0x64, b'n', b'o', b'n', b'e'];
    let start = packed
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or("fmt marker missing")?;
    packed[start + 1..start + marker.len()].copy_from_slice(b"pack");
    assert_kind(
        verify_registration(
            &Registration {
                attestation_object: &packed,
                ..fixture.registration()
            },
            &expectation(),
        ),
        PasskeyErrorKind::UnsupportedCredential,
    );
    Ok(())
}

#[test]
fn credential_rp_algorithm_and_curve_substitution_fail() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    assert_kind(
        verify_registration(
            &Registration {
                credential_id: b"other-credential",
                ..fixture.registration()
            },
            &expectation(),
        ),
        PasskeyErrorKind::BindingMismatch,
    );

    let mut wrong_rp = expectation();
    wrong_rp.relying_party_id = "example.test";
    assert_kind(
        verify_registration(&fixture.registration(), &wrong_rp),
        PasskeyErrorKind::BindingMismatch,
    );

    let mut wrong_algorithm = fixture.attestation.clone();
    let algorithm = wrong_algorithm
        .windows(2)
        .position(|window| window == [0x03, 0x26])
        .ok_or("algorithm marker missing")?;
    wrong_algorithm[algorithm + 1] = 0x27;
    assert_kind(
        verify_registration(
            &Registration {
                attestation_object: &wrong_algorithm,
                ..fixture.registration()
            },
            &expectation(),
        ),
        PasskeyErrorKind::UnsupportedCredential,
    );
    Ok(())
}

struct Fixture {
    client_data: String,
    attestation: Vec<u8>,
    public_key: [u8; 65],
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let signing_key = SigningKey::from_slice(&[0x44; 32])?;
        let point = signing_key.verifying_key().to_sec1_point(false);
        let public_key: [u8; 65] = point.as_bytes().try_into()?;
        let client_data = format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{CHALLENGE_TEXT}\",\"origin\":\"{ORIGIN}\",\"crossOrigin\":false}}"
        );
        let auth_data = authentication_data(&public_key)?;
        let mut attestation = Vec::new();
        attestation.push(0xa3);
        cbor_text(&mut attestation, "fmt")?;
        cbor_text(&mut attestation, "none")?;
        cbor_text(&mut attestation, "attStmt")?;
        attestation.push(0xa0);
        cbor_text(&mut attestation, "authData")?;
        cbor_bytes(&mut attestation, &auth_data)?;
        Ok(Self {
            client_data,
            attestation,
            public_key,
        })
    }

    fn registration(&self) -> Registration<'_> {
        Registration {
            credential_id: CREDENTIAL_ID,
            client_data_json: self.client_data.as_bytes(),
            attestation_object: &self.attestation,
        }
    }
}

fn authentication_data(public_key: &[u8; 65]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut output = Vec::from(Sha256::digest(RELYING_PARTY.as_bytes()).as_slice());
    output.push(0x45);
    output.extend_from_slice(&0_u32.to_be_bytes());
    output.extend_from_slice(&[0x33; 16]);
    output.extend_from_slice(&u16::try_from(CREDENTIAL_ID.len())?.to_be_bytes());
    output.extend_from_slice(CREDENTIAL_ID);
    output.push(0xa5);
    output.extend_from_slice(&[0x01, 0x02]);
    output.extend_from_slice(&[0x03, 0x26]);
    output.extend_from_slice(&[0x20, 0x01]);
    output.push(0x21);
    cbor_bytes(&mut output, &public_key[1..33])?;
    output.push(0x22);
    cbor_bytes(&mut output, &public_key[33..65])?;
    Ok(output)
}

fn cbor_text(output: &mut Vec<u8>, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let length = u8::try_from(value.len())?;
    if length >= 24 {
        return Err("test text is too long".into());
    }
    output.push(0x60 | length);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn cbor_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if value.len() < 24 {
        output.push(0x40 | u8::try_from(value.len())?);
    } else {
        output.extend_from_slice(&[0x58, u8::try_from(value.len())?]);
    }
    output.extend_from_slice(value);
    Ok(())
}

fn expectation() -> RegistrationExpectation<'static> {
    RegistrationExpectation {
        challenge: &CHALLENGE,
        relying_party_id: RELYING_PARTY,
        allowed_origins: ORIGINS,
        user_verification: UserVerification::Required,
    }
}

fn assert_kind<T>(result: Result<T, meshspan_passkey::PasskeyError>, expected: PasskeyErrorKind) {
    assert_eq!(
        result.err().map(meshspan_passkey::PasskeyError::kind),
        Some(expected)
    );
}
