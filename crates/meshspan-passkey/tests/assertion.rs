// SPDX-License-Identifier: GPL-2.0-only

//! Exact ES256 assertion and hostile-substitution vectors.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use meshspan_passkey::{
    Assertion, AssertionExpectation, CounterState, Es256PublicKey, PasskeyErrorKind,
    UserVerification, verify_assertion,
};

const CHALLENGE: [u8; 32] = [0x11; 32];
const CHALLENGE_TEXT: &str = "ERERERERERERERERERERERERERERERERERERERERERE";
const CREDENTIAL_ID: &[u8] = b"credential-one";
const USER_HANDLE: &[u8] = b"user-one";
const RELYING_PARTY: &str = "files.example.test";
const ORIGIN: &str = "https://files.example.test";
const ORIGINS: &[&str] = &[ORIGIN];

#[test]
fn exact_assertion_verifies_and_reports_authoritative_state()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(7, 0x1d)?;
    let outcome = verify_assertion(&fixture.assertion(), &fixture.expectation(6))?;
    assert_eq!(outcome.counter, CounterState::Advanced(7));
    assert!(outcome.user_verified);
    assert!(outcome.backup_eligible);
    assert!(outcome.backup_state);
    Ok(())
}

#[test]
fn every_critical_binding_and_signature_substitution_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(7, 0x05)?;
    assert_kind(
        verify_assertion(
            &Assertion {
                credential_id: b"other",
                ..fixture.assertion()
            },
            &fixture.expectation(6),
        ),
        PasskeyErrorKind::BindingMismatch,
    );

    let wrong_client = fixture.client_data.replace(
        CHALLENGE_TEXT,
        "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
    );
    assert_kind(
        verify_assertion(
            &Assertion {
                client_data_json: wrong_client.as_bytes(),
                ..fixture.assertion()
            },
            &fixture.expectation(6),
        ),
        PasskeyErrorKind::BindingMismatch,
    );

    let mut wrong_signature = fixture.signature.clone();
    if let Some(last) = wrong_signature.last_mut() {
        *last ^= 1;
    }
    assert_kind(
        verify_assertion(
            &Assertion {
                signature: &wrong_signature,
                ..fixture.assertion()
            },
            &fixture.expectation(6),
        ),
        PasskeyErrorKind::InvalidSignature,
    );
    Ok(())
}

#[test]
fn interaction_flags_counter_and_extensions_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let missing_uv = Fixture::new(7, 0x01)?;
    assert_kind(
        verify_assertion(&missing_uv.assertion(), &missing_uv.expectation(6)),
        PasskeyErrorKind::UserInteractionRequired,
    );
    let regression = Fixture::new(6, 0x05)?;
    assert_kind(
        verify_assertion(&regression.assertion(), &regression.expectation(6)),
        PasskeyErrorKind::CounterRegression,
    );
    let invalid_backup = Fixture::new(7, 0x15)?;
    assert_kind(
        verify_assertion(&invalid_backup.assertion(), &invalid_backup.expectation(6)),
        PasskeyErrorKind::UserInteractionRequired,
    );
    let dangling_extension = Fixture::new(7, 0x85)?;
    assert_kind(
        verify_assertion(
            &dangling_extension.assertion(),
            &dangling_extension.expectation(6),
        ),
        PasskeyErrorKind::UnsupportedCredential,
    );
    Ok(())
}

#[test]
fn client_and_relying_party_bindings_reject_lookalikes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(7, 0x05)?;
    for changed in [
        fixture
            .client_data
            .replace("webauthn.get", "webauthn.create"),
        fixture
            .client_data
            .replace(ORIGIN, "https://evil.example.test"),
        fixture
            .client_data
            .replace("\"crossOrigin\":false", "\"crossOrigin\":true"),
        fixture.client_data.replace(
            "\"crossOrigin\":false",
            "\"crossOrigin\":false,\"topOrigin\":\"https://evil.example.test\"",
        ),
    ] {
        assert_kind(
            verify_assertion(
                &Assertion {
                    client_data_json: changed.as_bytes(),
                    ..fixture.assertion()
                },
                &fixture.expectation(6),
            ),
            PasskeyErrorKind::BindingMismatch,
        );
    }
    let mut wrong_rp = fixture.expectation(6);
    wrong_rp.relying_party_id = "example.test";
    assert_kind(
        verify_assertion(&fixture.assertion(), &wrong_rp),
        PasskeyErrorKind::BindingMismatch,
    );
    Ok(())
}

#[test]
fn malformed_and_excessive_inputs_fail_before_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(7, 0x05)?;
    let duplicate = fixture
        .client_data
        .replace("\"type\":", "\"type\":\"webauthn.get\",\"type\":");
    assert_kind(
        verify_assertion(
            &Assertion {
                client_data_json: duplicate.as_bytes(),
                ..fixture.assertion()
            },
            &fixture.expectation(6),
        ),
        PasskeyErrorKind::Malformed,
    );
    assert_kind(
        verify_assertion(
            &Assertion {
                client_data_json: &[b' '; meshspan_passkey::MAXIMUM_CLIENT_DATA_BYTES + 1],
                ..fixture.assertion()
            },
            &fixture.expectation(6),
        ),
        PasskeyErrorKind::LimitExceeded,
    );
    assert_kind(
        verify_assertion(
            &Assertion {
                authenticator_data: &fixture.authenticator_data[..36],
                ..fixture.assertion()
            },
            &fixture.expectation(6),
        ),
        PasskeyErrorKind::LimitExceeded,
    );
    assert_kind(
        Es256PublicKey::from_sec1_bytes(&[0x04; 65]),
        PasskeyErrorKind::UnsupportedCredential,
    );
    Ok(())
}

#[test]
fn zero_counter_authenticator_is_valid_but_never_claimed_advanced()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(0, 0x05)?;
    let outcome = verify_assertion(&fixture.assertion(), &fixture.expectation(0))?;
    assert_eq!(outcome.counter, CounterState::Unsupported);
    Ok(())
}

struct Fixture {
    public_key: Es256PublicKey,
    client_data: String,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
}

impl Fixture {
    fn new(sign_count: u32, flags: u8) -> Result<Self, Box<dyn std::error::Error>> {
        let signing_key = SigningKey::from_slice(&[0x42; 32])?;
        let encoded = signing_key.verifying_key().to_sec1_point(false);
        let public_key = Es256PublicKey::from_sec1_bytes(encoded.as_bytes())?;
        let client_data = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{CHALLENGE_TEXT}\",\"origin\":\"{ORIGIN}\",\"crossOrigin\":false}}"
        );
        let mut authenticator_data = Vec::from(Sha256::digest(RELYING_PARTY.as_bytes()).as_slice());
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&sign_count.to_be_bytes());
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
        let signature: Signature = signing_key.sign(&signed);
        signing_key.verifying_key().verify(&signed, &signature)?;
        Ok(Self {
            public_key,
            client_data,
            authenticator_data,
            signature: signature.to_der().as_bytes().to_vec(),
        })
    }

    fn assertion(&self) -> Assertion<'_> {
        Assertion {
            credential_id: CREDENTIAL_ID,
            client_data_json: self.client_data.as_bytes(),
            authenticator_data: &self.authenticator_data,
            signature: &self.signature,
            user_handle: Some(USER_HANDLE),
        }
    }

    fn expectation(&self, previous_sign_count: u32) -> AssertionExpectation<'_> {
        AssertionExpectation {
            credential_id: CREDENTIAL_ID,
            public_key: &self.public_key,
            challenge: &CHALLENGE,
            relying_party_id: RELYING_PARTY,
            allowed_origins: ORIGINS,
            user_verification: UserVerification::Required,
            previous_sign_count,
            user_handle: Some(USER_HANDLE),
        }
    }
}

fn assert_kind<T>(result: Result<T, meshspan_passkey::PasskeyError>, expected: PasskeyErrorKind) {
    assert_eq!(
        result.err().map(meshspan_passkey::PasskeyError::kind),
        Some(expected)
    );
}
