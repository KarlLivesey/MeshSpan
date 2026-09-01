// SPDX-License-Identifier: GPL-2.0-only

//! Public JSON boundary models.

use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The maximum number of field issues returned in one public error.
pub const MAX_ERROR_ISSUES: usize = 16;

/// A client-generated idempotency key for a mutation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OperationId(
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    String,
);

impl OperationId {
    /// Constructs canonical UUID text from already validated versioned UUID bytes.
    #[must_use]
    pub fn from_uuid_bytes(value: [u8; 16]) -> Option<Self> {
        let version = value[6] >> 4;
        if !(1..=8).contains(&version) || value[8] >> 6 != 2 {
            return None;
        }
        Some(Self(format_uuid(value)))
    }

    /// Parses exact canonical versioned UUID text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        crate::directory_listing::parse_public_uuid(value).map(Self)
    }

    /// Returns the validated canonical UUID text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A durable authenticated-session identifier.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SessionId(
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    String,
);

impl SessionId {
    /// Constructs canonical UUID text from already validated versioned UUID bytes.
    #[must_use]
    pub fn from_uuid_bytes(value: [u8; 16]) -> Option<Self> {
        let version = value[6] >> 4;
        if !(1..=8).contains(&version) || value[8] >> 6 != 2 {
            return None;
        }
        Some(Self(format_uuid(value)))
    }

    /// Returns the canonical UUID text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A short-lived passkey authentication challenge identifier.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PasskeyChallengeId(
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    String,
);

impl PasskeyChallengeId {
    /// Constructs canonical UUID text from already validated versioned UUID bytes.
    #[must_use]
    pub fn from_uuid_bytes(value: [u8; 16]) -> Option<Self> {
        let version = value[6] >> 4;
        if !(1..=8).contains(&version) || value[8] >> 6 != 2 {
            return None;
        }
        Some(Self(format_uuid(value)))
    }

    /// Returns the canonical UUID text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A globally qualified principal's local UUID within the current swarm.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PrincipalId(
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    String,
);

impl PrincipalId {
    /// Parses exact canonical versioned UUID text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        crate::directory_listing::parse_public_uuid(value).map(Self)
    }

    /// Constructs canonical UUID text from already validated versioned UUID bytes.
    #[must_use]
    pub fn from_uuid_bytes(value: [u8; 16]) -> Option<Self> {
        let version = value[6] >> 4;
        if !(1..=8).contains(&version) || value[8] >> 6 != 2 {
            return None;
        }
        Some(Self(format_uuid(value)))
    }

    /// Returns the canonical UUID text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An optional property that distinguishes omission from an explicit JSON null.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum NullableField<T> {
    /// The property was not sent.
    #[default]
    Missing,
    /// The property was explicitly set to JSON null.
    Null,
    /// The property contained a value.
    Value(T),
}

impl<T> NullableField<T> {
    /// Returns true only when the property was omitted.
    #[must_use]
    pub const fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }
}

impl<T: Serialize> Serialize for NullableField<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Missing | Self::Null => serializer.serialize_none(),
            Self::Value(value) => value.serialize(serializer),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NullableField<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(|value| match value {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

impl<T: JsonSchema> JsonSchema for NullableField<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Nullable_{}", T::schema_name()).into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        <Option<T>>::json_schema(generator)
    }
}

/// A validated display label that can be cleared independently of omission.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SessionLabel(
    #[schemars(length(min = 1, max = 80), pattern(r"^[^\x00-\x1f\x7f]+$"))] String,
);

impl SessionLabel {
    /// Returns the untrusted label candidate for authoritative validation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn format_uuid(value: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(36);
    for (index, byte) in value.into_iter().enumerate() {
        if [4, 6, 8, 10].contains(&index) {
            output.push('-');
        }
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Primary proof accepted when creating an authenticated session.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "method", rename_all = "snake_case")]
pub enum SessionAuthentication {
    /// One ordinary login-capable `MeshSpan` API key.
    ApiKey {
        /// Opaque API-key secret. The key identity and scopes are resolved server-side.
        #[schemars(length(min = 16, max = 512), extend("writeOnly" = true))]
        secret: String,
    },
    /// One complete assertion bound to a previously issued `WebAuthn` challenge.
    Passkey {
        /// Server-issued challenge identity consumed exactly once.
        #[schemars(
            length(equal = 36),
            pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        )]
        challenge_id: String,
        /// Base64url-encoded `WebAuthn` credential identity.
        #[schemars(length(min = 1, max = 1_024), extend("writeOnly" = true))]
        credential_id: String,
        /// Base64url-encoded `WebAuthn` client data JSON.
        #[schemars(length(min = 1, max = 4_096), extend("writeOnly" = true))]
        client_data_json: String,
        /// Base64url-encoded authenticator data.
        #[schemars(length(min = 1, max = 2_048), extend("writeOnly" = true))]
        authenticator_data: String,
        /// Base64url-encoded assertion signature.
        #[schemars(length(min = 1, max = 1_024), extend("writeOnly" = true))]
        signature: String,
        /// Base64url-encoded user handle, null when the authenticator omitted it.
        #[schemars(length(min = 1, max = 1_024), extend("writeOnly" = true))]
        user_handle: Option<String>,
    },
}

/// Optional recovery or step-up proof supplied beside the primary method.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "method", rename_all = "snake_case")]
pub enum SessionAdditionalFactor {
    /// Current time-based one-time code.
    Totp {
        /// Six-to-eight digit TOTP value.
        #[schemars(length(min = 6, max = 8), extend("writeOnly" = true))]
        code: String,
    },
    /// One single-use recovery code.
    RecoveryCode {
        /// Opaque recovery code consumed atomically on success.
        #[schemars(length(min = 8, max = 128), extend("writeOnly" = true))]
        code: String,
    },
}

/// Input for exchanging accepted authentication proofs for a session.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSessionRequest {
    /// Client-generated idempotency key.
    pub operation_id: OperationId,
    /// Primary API-key or passkey proof. It identifies the principal server-side.
    pub authentication: SessionAuthentication,
    /// Optional TOTP or recovery-code proof when policy requires another factor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_factor: Option<SessionAdditionalFactor>,
    /// Optional client label: omitted means unchanged and null means clear.
    #[serde(default, skip_serializing_if = "NullableField::is_missing")]
    pub client_label: NullableField<SessionLabel>,
    /// Whether the caller requests the policy's longer-lived session profile.
    pub remember: bool,
}

/// Input for atomically rotating the current browser session after a fresh factor.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpCurrentSessionRequest {
    /// Client-generated idempotency key for the exact rotation.
    pub operation_id: OperationId,
    /// Fresh TOTP or single-use recovery proof; the current session supplies the primary proof.
    pub additional_factor: SessionAdditionalFactor,
}

/// Input for creating one short-lived passkey authentication challenge.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePasskeyChallengeRequest {
    /// Client-generated identity making challenge creation exactly replayable on this gateway.
    pub operation_id: OperationId,
}

/// Passkey authenticator-local user-verification requirement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PasskeyUserVerification {
    /// Require a PIN, biometric or equivalent authenticator-local verification.
    Required,
}

/// Browser-ready options for one passkey authentication ceremony.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePasskeyChallengeResponse {
    /// Challenge-creation operation whose exact result this response represents.
    pub operation_id: OperationId,
    /// Stable challenge identity supplied with the resulting assertion.
    pub challenge_id: PasskeyChallengeId,
    /// Unpadded base64url random challenge supplied to `navigator.credentials.get`.
    #[schemars(length(equal = 43), pattern(r"^[A-Za-z0-9_-]{43}$"))]
    pub challenge: String,
    /// Exact relying-party identifier against which authenticator data is verified.
    #[schemars(
        length(min = 1, max = 253),
        pattern(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
    )]
    pub relying_party_id: String,
    /// Browser hint; server expiry remains authoritative.
    #[schemars(range(min = 30_000, max = 600_000))]
    pub timeout_milliseconds: u32,
    /// Authenticator-local verification required by the challenge policy.
    pub user_verification: PasskeyUserVerification,
}

/// Authentication assurance reached by a session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    /// One accepted authentication factor.
    SingleFactor,
    /// Multiple independent accepted factors.
    MultiFactor,
    /// A recent privileged step-up ceremony.
    RecentStepUp,
}

/// Successful session creation response.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSessionResponse {
    /// The operation whose durable outcome this response represents.
    pub operation_id: OperationId,
    /// Newly created session identifier.
    pub session_id: SessionId,
    /// Authoritative UTC instant as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub expires_at_epoch_micros: i64,
    /// Assurance reached by the accepted authentication factors.
    pub assurance: AssuranceLevel,
}

/// Current caller identity and coarse panel-navigation authority.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentSessionResponse {
    /// Current committed session identity.
    pub session_id: SessionId,
    /// Current authenticated user principal.
    pub principal_id: PrincipalId,
    /// Exclusive authoritative session expiry as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub expires_at_epoch_micros: i64,
    /// Whether the current role projection permits entering administration.
    pub administration_available: bool,
}

/// Idempotent request to revoke the caller's current browser session.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeCurrentSessionRequest {
    /// Client-generated idempotency identity.
    pub operation_id: OperationId,
}

/// Durable result of revoking the caller's current browser session.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeCurrentSessionResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Session which is now authoritatively unusable.
    pub session_id: SessionId,
    /// Authoritative revocation instant as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub revoked_at_epoch_micros: i64,
}

/// Cheap readiness state returned without authentication.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// The process is initialising and cannot yet serve normal traffic.
    Starting,
    /// The process can serve its declared API contract.
    Ready,
    /// The process is serving traffic with a declared impaired capability.
    Degraded,
}

/// Bounded anonymous health response.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HealthResponse {
    /// Current readiness state.
    pub status: HealthStatus,
    /// Resolved rolling API label.
    #[schemars(length(equal = 6), pattern(r"^latest$"))]
    pub api_version: String,
    /// Digest of the exact `OpenAPI` document served by this process.
    #[schemars(length(equal = 71), pattern(r"^sha256:[0-9a-f]{64}$"))]
    pub schema_digest: String,
}

/// Public first-start lifecycle state containing no claim or identity material.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupState {
    /// A locally presented claim bundle is required to create or join a swarm.
    ClaimRequired,
    /// A claimed create/join operation is durably incomplete and will resume.
    Configuring,
    /// Initial swarm creation or enrolment has completed.
    Configured,
}

/// Cheap anonymous first-start status safe for local-network discovery.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetupStatusResponse {
    /// Current coarse setup state; this response never includes claim material.
    pub state: SetupState,
}

/// Exact first-boot claim bundle accepted only by setup mutations.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SetupClaim(
    #[schemars(
        length(equal = 115),
        pattern(r"^meshspan-claim-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$"),
        extend("writeOnly" = true)
    )]
    String,
);

impl SetupClaim {
    /// Exposes the claim only to the server-side verifier.
    #[must_use]
    pub fn expose_for_verification(&self) -> &str {
        &self.0
    }
}

/// Bounded setup display name; canonical domain validation still runs server-side.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SetupName(
    #[schemars(length(min = 1, max = 128), pattern(r"^[^\x00-\x1f\x2f\x7f\\]+$"))] String,
);

impl SetupName {
    /// Parses one bounded display name accepted by the public setup contract.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        if value.is_empty()
            || value.len() > 128
            || value
                .chars()
                .any(|character| character.is_control() || matches!(character, '/' | '\\'))
        {
            return None;
        }
        Some(Self(value.to_owned()))
    }

    /// Returns the untrusted display-name candidate for domain validation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One exact request to create the first mesh on an unclaimed daemon.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateMeshSetupRequest {
    /// Client-generated idempotency identity.
    pub operation_id: OperationId,
    /// High-entropy single-use claim printed or written by the local daemon.
    pub claim: SetupClaim,
    /// Human-readable mesh name.
    pub mesh_name: SetupName,
    /// Human-readable first administrator name.
    pub administrator_name: SetupName,
    /// Human-readable physical host name.
    pub host_name: SetupName,
    /// Human-readable daemon-node name.
    pub node_name: SetupName,
}

/// Successful, committed first-mesh creation result.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateMeshSetupResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Stable UUID of the created mesh.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub mesh_id: String,
    /// Stable UUID of the first daemon node.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub node_id: String,
    /// One-time presentation of the first administrator's ordinary API key.
    #[schemars(
        length(equal = 113),
        pattern(r"^meshspan-key-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$"),
        extend("x-meshspan-sensitive" = true)
    )]
    pub api_key: String,
    /// Exact encrypted recovery-bundle file; save it separately before enrolling more nodes.
    #[schemars(
        length(min = 256, max = 33000),
        pattern(r"^meshspan-recovery-file-v1\.[0-9a-f]+$"),
        extend("x-meshspan-sensitive" = true)
    )]
    pub recovery_bundle: String,
    /// One-time high-entropy recovery code which must be stored separately from the bundle.
    #[schemars(
        length(equal = 84),
        pattern(r"^meshspan-offline-v1\.[0-9a-f]{64}$"),
        extend("x-meshspan-sensitive" = true)
    )]
    pub recovery_code: String,
    /// Short proof entered after the administrator has saved the exact file and code.
    #[schemars(
        length(equal = 34),
        pattern(r"^meshspan-check-v1\.[0-9a-f]{16}$"),
        extend("x-meshspan-sensitive" = true)
    )]
    pub recovery_challenge: String,
}

/// Stable public error category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    /// Authentication was absent or invalid.
    Unauthenticated,
    /// The authenticated caller lacks current authority.
    Forbidden,
    /// The message did not satisfy the public contract.
    InvalidRequest,
    /// An idempotency key was reused with different canonical input.
    OperationConflict,
    /// The selected resource does not exist or is intentionally indistinguishable from absence.
    NotFound,
    /// Current state no longer matches a continuation or mutation precondition.
    StateConflict,
    /// Work was rejected by a bounded admission policy.
    Busy,
    /// An outgoing response failed its own contract.
    InternalContract,
}

/// A bounded field-specific validation issue.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiErrorIssue {
    /// JSON Pointer to the rejected field or collection element.
    #[schemars(length(max = 256))]
    pub path: String,
    /// Stable violated-constraint label.
    #[schemars(length(min = 1, max = 64), pattern(r"^[a-z][a-z0-9_]*$"))]
    pub constraint: String,
}

/// Public error envelope that never includes raw untrusted values.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    /// Stable machine-readable error category.
    pub code: ApiErrorCode,
    /// Plain bounded description safe to show to the caller.
    #[schemars(length(min = 1, max = 512))]
    pub message: String,
    /// Server request identifier for support correlation.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub request_id: String,
    /// Mutation operation identifier, or null for requests without one.
    pub operation_id: Option<OperationId>,
    /// Independently actionable field failures, capped at the trust boundary.
    #[schemars(length(max = 16))]
    pub issues: Vec<ApiErrorIssue>,
}

impl fmt::Display for AssuranceLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::SingleFactor => "single_factor",
            Self::MultiFactor => "multi_factor",
            Self::RecentStepUp => "recent_step_up",
        };
        formatter.write_str(value)
    }
}
