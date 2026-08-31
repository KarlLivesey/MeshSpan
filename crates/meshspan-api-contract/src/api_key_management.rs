// SPDX-License-Identifier: GPL-2.0-only

//! Public current-user API-key management models.

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::{AuthenticationMethodId, AuthenticationMethodLabel, NullableField, OperationId};

/// A durable public API-key identifier.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ApiKeyId(
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    String,
);

impl ApiKeyId {
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

/// One connector through which an issued API key may authenticate.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyScope {
    /// Exchange the key for an HTTPS browser session.
    HttpsSession,
    /// Authenticate directly to the headless public API.
    HeadlessApi,
    /// Authenticate an embedded SMB 3.1.1 session.
    SmbSession,
}

/// An explicit API-key expiry instant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ApiKeyExpiry(i64);

impl JsonSchema for ApiKeyExpiry {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ApiKeyExpiry".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        let mut schema = Map::new();
        schema.insert("type".to_owned(), Value::String("integer".to_owned()));
        schema.insert("minimum".to_owned(), json!(0));
        schema.insert("maximum".to_owned(), json!(9_007_199_254_740_991_i64));
        Schema::from(schema)
    }
}

impl ApiKeyExpiry {
    /// Returns epoch microseconds supplied by the untrusted request.
    #[must_use]
    pub const fn epoch_micros(self) -> i64 {
        self.0
    }
}

/// One idempotent request to issue a current-user API key.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKeyRequest {
    /// Client-generated identity binding exact retries.
    pub operation_id: OperationId,
    /// Human-readable independently revocable method label.
    pub label: AuthenticationMethodLabel,
    /// Non-empty deduplicated connector scopes; resource ACLs still apply independently.
    #[schemars(length(min = 1, max = 3))]
    pub scopes: Vec<ApiKeyScope>,
    /// Omitted applies the server default, null means no automatic expiry, and a value is exact.
    #[serde(default, skip_serializing_if = "NullableField::is_missing")]
    pub expires_at_epoch_micros: NullableField<ApiKeyExpiry>,
}

/// One exactly replayable API-key issuance result.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKeyResponse {
    /// Exact idempotency identity whose committed result was resolved.
    pub operation_id: OperationId,
    /// Independently revocable common authentication-method identity.
    pub method_id: AuthenticationMethodId,
    /// Public key identity embedded in the returned secret.
    pub key_id: ApiKeyId,
    /// Secret-bearing key returned only from this issuance operation.
    #[schemars(
        length(equal = 113),
        pattern(r"^meshspan-key-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$"),
        extend("readOnly" = true),
        extend("x-meshspan-sensitive" = true)
    )]
    pub secret: String,
    /// Exact connector scopes carried by the key.
    #[schemars(length(min = 1, max = 3))]
    pub scopes: Vec<ApiKeyScope>,
    /// Authoritative creation instant as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub created_at_epoch_micros: i64,
    /// Inclusive first accepted instant as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub valid_from_epoch_micros: i64,
    /// Exclusive expiry, or null when the key does not expire automatically.
    #[schemars(with = "Option<ApiKeyExpiry>")]
    pub expires_at_epoch_micros: Option<i64>,
}

/// Bounded audit reason for revoking one authentication method.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AuthenticationMethodRevocationReason(
    #[schemars(
        length(min = 1, max = 1_024),
        pattern(r"^[^\x00-\x20\x7f](?:[^\x00-\x1f\x7f]{0,1022}[^\x00-\x20\x7f])?$")
    )]
    String,
);

impl AuthenticationMethodRevocationReason {
    /// Returns the untrusted reason candidate for authoritative validation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One idempotent request to revoke an owned authentication method.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeAuthenticationMethodRequest {
    /// Client-generated identity binding exact retries.
    pub operation_id: OperationId,
    /// Human-readable reason retained in the immutable audit history.
    pub reason: AuthenticationMethodRevocationReason,
}

/// Durable result of revoking one owned authentication method.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeAuthenticationMethodResponse {
    /// Exact idempotency identity whose committed result was resolved.
    pub operation_id: OperationId,
    /// Authentication method which is now authoritatively unusable.
    pub method_id: AuthenticationMethodId,
    /// Authoritative revocation instant as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub revoked_at_epoch_micros: i64,
}
