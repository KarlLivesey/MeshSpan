// SPDX-License-Identifier: GPL-2.0-only

//! Public passkey-registration ceremony models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{OperationId, PasskeyChallengeId, PasskeyUserVerification};

/// A durable authentication-method identifier.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AuthenticationMethodId(
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    String,
);

impl AuthenticationMethodId {
    /// Constructs canonical UUID text from already validated versioned UUID bytes.
    #[must_use]
    pub fn from_uuid_bytes(value: [u8; 16]) -> Option<Self> {
        let version = value[6] >> 4;
        if !(1..=8).contains(&version) || value[8] >> 6 != 2 {
            return None;
        }
        Some(Self(crate::model::format_uuid(value)))
    }

    /// Returns the canonical UUID text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One idempotent request for browser-ready current-user registration options.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePasskeyRegistrationChallengeRequest {
    /// Client-generated identity making challenge creation exactly replayable on this gateway.
    pub operation_id: OperationId,
}

/// `WebAuthn` public-key credential type.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum PasskeyCredentialType {
    /// A public-key credential.
    #[serde(rename = "public-key")]
    PublicKey,
}

/// One algorithm offered to the authenticator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyCredentialParameter {
    /// `WebAuthn` credential type.
    #[serde(rename = "type")]
    pub credential_type: PasskeyCredentialType,
    /// COSE algorithm identifier; the initial profile supports ES256 only.
    #[schemars(range(min = -7, max = -7))]
    pub algorithm: i32,
}

/// One existing credential the browser should exclude from registration.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyCredentialDescriptor {
    /// `WebAuthn` credential type.
    #[serde(rename = "type")]
    pub credential_type: PasskeyCredentialType,
    /// Canonical unpadded base64url credential identity.
    #[schemars(length(min = 2, max = 1_366), pattern(r"^[A-Za-z0-9_-]+$"))]
    pub id: String,
}

/// Discoverable-credential policy supplied to the browser.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyResidentKey {
    /// Require a discoverable credential for account-name-free authentication.
    Required,
}

/// Attestation policy supplied to the browser.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyAttestation {
    /// Request privacy-preserving none attestation.
    None,
}

/// Browser-ready options for registering a current user's passkey.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePasskeyRegistrationChallengeResponse {
    /// Challenge-creation operation whose exact result this response represents.
    pub operation_id: OperationId,
    /// Stable gateway-local challenge identity supplied with completion.
    pub challenge_id: PasskeyChallengeId,
    /// Canonical unpadded base64url random challenge.
    #[schemars(length(equal = 43), pattern(r"^[A-Za-z0-9_-]{43}$"))]
    pub challenge: String,
    /// Exact relying-party identifier against which authenticator data is verified.
    #[schemars(
        length(min = 1, max = 253),
        pattern(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
    )]
    pub relying_party_id: String,
    /// Human-readable relying-party name shown by authenticators.
    #[schemars(length(min = 1, max = 128), pattern(r"^[^\x00-\x1f\x7f]+$"))]
    pub relying_party_name: String,
    /// Stable opaque `WebAuthn` user handle encoded as canonical unpadded base64url.
    #[schemars(length(equal = 22), pattern(r"^[A-Za-z0-9_-]{22}$"))]
    pub user_id: String,
    /// Stable current-user account name shown by authenticators.
    #[schemars(length(min = 1, max = 128), pattern(r"^[^\x00-\x1f\x7f]+$"))]
    pub user_name: String,
    /// Human-readable current-user display name.
    #[schemars(length(min = 1, max = 128), pattern(r"^[^\x00-\x1f\x7f]+$"))]
    pub user_display_name: String,
    /// Browser hint; server expiry remains authoritative.
    #[schemars(range(min = 30_000, max = 600_000))]
    pub timeout_milliseconds: u32,
    /// Authenticator-local verification policy.
    pub user_verification: PasskeyUserVerification,
    /// Discoverable credential policy.
    pub resident_key: PasskeyResidentKey,
    /// Attestation conveyance policy.
    pub attestation: PasskeyAttestation,
    /// Exact supported public-key algorithms.
    #[schemars(length(min = 1, max = 8))]
    pub public_key_parameters: Vec<PasskeyCredentialParameter>,
    /// Existing current-user credentials the authenticator should not duplicate.
    #[schemars(length(max = 64))]
    pub exclude_credentials: Vec<PasskeyCredentialDescriptor>,
}

/// Human-readable label for one independently revocable authentication method.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AuthenticationMethodLabel(
    #[schemars(length(min = 1, max = 80), pattern(r"^[^\x00-\x1f\x7f]+$"))] String,
);

impl AuthenticationMethodLabel {
    /// Returns the untrusted label candidate for authoritative validation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Authenticator transports reported for a newly registered credential.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PasskeyTransport {
    /// USB-connected authenticator.
    Usb,
    /// Near-field-communication authenticator.
    Nfc,
    /// Bluetooth Low Energy authenticator.
    Ble,
    /// Smart-card authenticator.
    SmartCard,
    /// Hybrid/cross-device authenticator transport.
    Hybrid,
    /// Platform authenticator built into the client device.
    Internal,
}

/// One exact registration response bound to a gateway-issued challenge.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePasskeyRegistrationRequest {
    /// Client-generated identity for the authoritative method creation.
    pub operation_id: OperationId,
    /// Gateway-issued registration challenge consumed exactly once.
    pub challenge_id: PasskeyChallengeId,
    /// User-visible method label.
    pub label: AuthenticationMethodLabel,
    /// Canonical unpadded base64url credential identity.
    #[schemars(length(min = 2, max = 1_366), pattern(r"^[A-Za-z0-9_-]+$"), extend("writeOnly" = true))]
    pub credential_id: String,
    /// Canonical unpadded base64url collected-client-data JSON.
    #[schemars(length(min = 2, max = 5_462), pattern(r"^[A-Za-z0-9_-]+$"), extend("writeOnly" = true))]
    pub client_data_json: String,
    /// Canonical unpadded base64url CBOR attestation object.
    #[schemars(length(min = 2, max = 21_846), pattern(r"^[A-Za-z0-9_-]+$"), extend("writeOnly" = true))]
    pub attestation_object: String,
    /// Deduplicated bounded transports reported by the browser.
    #[schemars(length(max = 6))]
    pub transports: Vec<PasskeyTransport>,
}

/// Durable result of registering one current-user passkey.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePasskeyRegistrationResponse {
    /// Exact idempotency identity whose committed outcome was resolved.
    pub operation_id: OperationId,
    /// Newly created independently revocable authentication method.
    pub method_id: AuthenticationMethodId,
    /// Authoritative creation instant as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub created_at_epoch_micros: i64,
}
