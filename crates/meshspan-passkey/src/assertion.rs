// SPDX-License-Identifier: GPL-2.0-only

//! Complete ES256 `WebAuthn` authentication-assertion verification.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::authenticator_data;
use crate::client_data::{self, constant_time_equal};
use crate::{
    MAXIMUM_AUTHENTICATOR_DATA_BYTES, MAXIMUM_CLIENT_DATA_BYTES, MAXIMUM_CREDENTIAL_ID_BYTES,
    MAXIMUM_SIGNATURE_BYTES, MAXIMUM_USER_HANDLE_BYTES, PasskeyError, PasskeyErrorKind,
};

/// User-verification policy fixed when a challenge is created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserVerification {
    /// User presence is required; authenticator-local verification is preferred but optional.
    Preferred,
    /// Both user presence and authenticator-local user verification are required.
    Required,
}

/// Validated uncompressed SEC1 P-256 public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Es256PublicKey([u8; 65]);

impl Es256PublicKey {
    /// Parses a complete uncompressed P-256 point.
    ///
    /// # Errors
    ///
    /// Rejects a wrong length, compressed point, off-curve point or identity.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, PasskeyError> {
        let encoded: [u8; 65] = bytes
            .try_into()
            .map_err(|_| PasskeyError::new(PasskeyErrorKind::UnsupportedCredential))?;
        if encoded[0] != 0x04 || VerifyingKey::from_sec1_bytes(&encoded).is_err() {
            return Err(PasskeyError::new(PasskeyErrorKind::UnsupportedCredential));
        }
        Ok(Self(encoded))
    }

    /// Borrows the canonical uncompressed SEC1 point.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }
}

/// One hostile browser assertion response.
pub struct Assertion<'a> {
    /// Credential identity returned by the browser.
    pub credential_id: &'a [u8],
    /// Exact collected-client-data JSON bytes hashed into the signature.
    pub client_data_json: &'a [u8],
    /// Exact authenticator-data bytes hashed into the signature.
    pub authenticator_data: &'a [u8],
    /// ASN.1 DER ECDSA signature.
    pub signature: &'a [u8],
    /// Optional authenticator-returned user handle.
    pub user_handle: Option<&'a [u8]>,
}

/// Server-side state fixed before an assertion is accepted.
pub struct AssertionExpectation<'a> {
    /// Exact stored credential identity.
    pub credential_id: &'a [u8],
    /// Stored credential public key.
    pub public_key: &'a Es256PublicKey,
    /// Random server-issued challenge bytes.
    pub challenge: &'a [u8],
    /// Relying-party identifier supplied to the browser.
    pub relying_party_id: &'a str,
    /// Exact allowed origin serialisations for this relying party.
    pub allowed_origins: &'a [&'a str],
    /// Authenticator user-verification requirement fixed at challenge creation.
    pub user_verification: UserVerification,
    /// Stored signature counter.
    pub previous_sign_count: u32,
    /// Stored user handle, when the credential is bound to one.
    pub user_handle: Option<&'a [u8]>,
}

/// Signature-counter result after a valid assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterState {
    /// Both counters are zero; this authenticator does not supply useful counter evidence.
    Unsupported,
    /// The authenticator's non-zero counter advanced beyond the stored value.
    Advanced(u32),
}

/// Fully verified assertion evidence safe to propose to authoritative metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssertionOutcome {
    /// Validated signature-counter disposition.
    pub counter: CounterState,
    /// Whether authenticator-local user verification occurred.
    pub user_verified: bool,
    /// Whether the credential is eligible for backup/synchronisation.
    pub backup_eligible: bool,
    /// Whether the credential was currently backed up.
    pub backup_state: bool,
}

/// Verifies a complete assertion against exact pre-existing ceremony state.
///
/// # Errors
///
/// Fails closed on excess, malformed input, any ceremony-binding mismatch, missing
/// user interaction, invalid signatures and non-zero counter regression.
pub fn verify_assertion(
    assertion: &Assertion<'_>,
    expected: &AssertionExpectation<'_>,
) -> Result<AssertionOutcome, PasskeyError> {
    validate_bounds(assertion, expected)?;
    if !constant_time_equal(assertion.credential_id, expected.credential_id)
        || !optional_equal(assertion.user_handle, expected.user_handle)
    {
        return Err(PasskeyError::new(PasskeyErrorKind::BindingMismatch));
    }
    let client = client_data::verify(
        assertion.client_data_json,
        expected.challenge,
        expected.allowed_origins,
        "webauthn.get",
    )?;
    let relying_party_hash: [u8; 32] = Sha256::digest(expected.relying_party_id.as_bytes()).into();
    let authenticator = authenticator_data::verify(
        assertion.authenticator_data,
        &relying_party_hash,
        expected.user_verification,
    )?;
    verify_signature(assertion, expected.public_key, client.hash)?;
    let counter = counter_state(expected.previous_sign_count, authenticator.sign_count)?;
    Ok(AssertionOutcome {
        counter,
        user_verified: authenticator.user_verified,
        backup_eligible: authenticator.backup_eligible,
        backup_state: authenticator.backup_state,
    })
}

fn validate_bounds(
    assertion: &Assertion<'_>,
    expected: &AssertionExpectation<'_>,
) -> Result<(), PasskeyError> {
    let user_handle_length = assertion.user_handle.map_or(0, <[u8]>::len);
    if assertion.credential_id.is_empty()
        || assertion.credential_id.len() > MAXIMUM_CREDENTIAL_ID_BYTES
        || assertion.client_data_json.is_empty()
        || assertion.client_data_json.len() > MAXIMUM_CLIENT_DATA_BYTES
        || assertion.authenticator_data.len() > MAXIMUM_AUTHENTICATOR_DATA_BYTES
        || assertion.signature.is_empty()
        || assertion.signature.len() > MAXIMUM_SIGNATURE_BYTES
        || user_handle_length > MAXIMUM_USER_HANDLE_BYTES
        || expected.credential_id.is_empty()
        || expected.credential_id.len() > MAXIMUM_CREDENTIAL_ID_BYTES
        || expected.challenge.len() < 16
        || expected.challenge.len() > 64
        || expected.relying_party_id.is_empty()
        || expected.relying_party_id.len() > 253
        || expected.allowed_origins.is_empty()
        || expected.allowed_origins.len() > 16
        || expected
            .allowed_origins
            .iter()
            .any(|origin| origin.is_empty() || origin.len() > 2_048)
        || expected.user_handle.map_or(0, <[u8]>::len) > MAXIMUM_USER_HANDLE_BYTES
    {
        return Err(PasskeyError::new(PasskeyErrorKind::LimitExceeded));
    }
    Ok(())
}

fn verify_signature(
    assertion: &Assertion<'_>,
    public_key: &Es256PublicKey,
    client_data_hash: [u8; 32],
) -> Result<(), PasskeyError> {
    let signature = Signature::from_der(assertion.signature)
        .map_err(|_| PasskeyError::new(PasskeyErrorKind::InvalidSignature))?;
    let key = VerifyingKey::from_sec1_bytes(public_key.as_bytes())
        .map_err(|_| PasskeyError::new(PasskeyErrorKind::UnsupportedCredential))?;
    let mut signed = Vec::new();
    signed
        .try_reserve_exact(assertion.authenticator_data.len() + client_data_hash.len())
        .map_err(|_| PasskeyError::new(PasskeyErrorKind::LimitExceeded))?;
    signed.extend_from_slice(assertion.authenticator_data);
    signed.extend_from_slice(&client_data_hash);
    key.verify(&signed, &signature)
        .map_err(|_| PasskeyError::new(PasskeyErrorKind::InvalidSignature))
}

fn counter_state(previous: u32, current: u32) -> Result<CounterState, PasskeyError> {
    if previous == 0 && current == 0 {
        Ok(CounterState::Unsupported)
    } else if current > previous {
        Ok(CounterState::Advanced(current))
    } else {
        Err(PasskeyError::new(PasskeyErrorKind::CounterRegression))
    }
}

fn optional_equal(left: Option<&[u8]>, right: Option<&[u8]>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => constant_time_equal(left, right),
        (None, None) => true,
        _ => false,
    }
}
