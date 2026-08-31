// SPDX-License-Identifier: GPL-2.0-only

//! Bounded `WebAuthn` relying-party operations for hostile-input services.

mod assertion;
mod assertion_transport;
mod authenticator_data;
mod base64url;
mod cbor;
mod challenge;
mod client_data;
mod error;
mod registration;

pub use assertion::{
    Assertion, AssertionExpectation, AssertionOutcome, CounterState, Es256PublicKey,
    UserVerification, verify_assertion,
};
pub use assertion_transport::OwnedAssertion;
pub use challenge::{PASSKEY_CHALLENGE_BYTES, PasskeyChallenge};
pub use error::{PasskeyError, PasskeyErrorKind};
pub use registration::{
    Registration, RegistrationExpectation, RegistrationOutcome, verify_registration,
};

/// Maximum accepted client-data JSON bytes.
pub const MAXIMUM_CLIENT_DATA_BYTES: usize = 4_096;
/// Maximum accepted authenticator-data bytes.
pub const MAXIMUM_AUTHENTICATOR_DATA_BYTES: usize = 2_048;
/// Maximum accepted DER assertion-signature bytes.
pub const MAXIMUM_SIGNATURE_BYTES: usize = 1_024;
/// Maximum accepted credential identity bytes.
pub const MAXIMUM_CREDENTIAL_ID_BYTES: usize = 1_024;
/// Maximum accepted user-handle bytes.
pub const MAXIMUM_USER_HANDLE_BYTES: usize = 1_024;
/// Maximum accepted CBOR attestation-object bytes.
pub const MAXIMUM_ATTESTATION_OBJECT_BYTES: usize = 16_384;
