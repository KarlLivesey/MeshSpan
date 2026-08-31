// SPDX-License-Identifier: GPL-2.0-only

//! Public current-user authentication-method inventory models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ApiKeyId, ApiKeyScope, AuthenticationMethodId};

/// Opaque continuation for one current-user authentication-method page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AuthenticationMethodCursor(
    #[schemars(length(min = 1, max = 1_024), pattern(r"^[A-Za-z0-9._~-]+$"))] String,
);

impl AuthenticationMethodCursor {
    /// Constructs a cursor after an authoritative codec has validated its fields.
    #[must_use]
    pub fn from_encoded(value: String) -> Option<Self> {
        let valid_length = (1..=1_024).contains(&value.len());
        let valid_alphabet = value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte));
        (valid_length && valid_alphabet).then_some(Self(value))
    }

    /// Returns the opaque continuation token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One bounded current-user authentication-method query.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListAuthenticationMethodsQuery {
    /// Exact continuation returned by the preceding page.
    pub cursor: Option<AuthenticationMethodCursor>,
    /// Requested result bound; omission applies the server default.
    #[schemars(range(min = 1, max = 256))]
    pub limit: Option<u16>,
}

/// Public lifecycle of one authentication method.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethodState {
    /// The method may currently authenticate within its other bounds.
    Active,
    /// The method is reversibly unavailable.
    Suspended,
    /// The method is permanently unusable.
    Revoked,
}

/// Method-specific public facts which never contain verifier or secret material.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthenticationMethodDetails {
    /// One `WebAuthn` credential.
    Passkey {
        /// Whether the authenticator reports that the credential can be backed up.
        backup_eligible: bool,
        /// Last authoritative backed-up state reported by the authenticator.
        backup_state: bool,
    },
    /// One time-based one-time-password seed.
    Totp,
    /// One independently replaceable set of single-use recovery codes.
    RecoveryCodes {
        /// Number of codes which have not yet been consumed.
        #[schemars(range(min = 0, max = 64))]
        remaining_codes: u8,
    },
    /// One scoped API key whose secret is never returned by inventory reads.
    ApiKey {
        /// Public identity embedded in the key.
        key_id: ApiKeyId,
        /// Connectors through which the key may authenticate.
        #[schemars(length(min = 1, max = 3))]
        scopes: Vec<ApiKeyScope>,
        /// Inclusive first accepted instant as epoch microseconds.
        #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
        valid_from_epoch_micros: i64,
    },
}

/// Secret-free current state of one independently revocable authentication method.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationMethodSummary {
    /// Common stable method identity.
    pub method_id: AuthenticationMethodId,
    /// User-facing label assigned at registration or issuance.
    #[schemars(length(min = 1, max = 80), pattern(r"^[^\x00-\x1f\x7f]+$"))]
    pub label: String,
    /// Current authoritative lifecycle state.
    pub state: AuthenticationMethodState,
    /// Method-specific public projection.
    pub details: AuthenticationMethodDetails,
    /// Authoritative creation instant as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub created_at_epoch_micros: i64,
    /// Last successful use, or null before first use.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub last_used_at_epoch_micros: Option<i64>,
    /// Exclusive expiry, or null when the method has no automatic expiry.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub expires_at_epoch_micros: Option<i64>,
    /// Last authoritative metadata revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded current-user authentication-method page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListAuthenticationMethodsResponse {
    /// Stable ordered, secret-free authentication methods.
    #[schemars(length(max = 256))]
    pub methods: Vec<AuthenticationMethodSummary>,
    /// Ready-to-follow relative URL, or null at the terminal page.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/users/current/authentication-methods")
    )]
    pub next_page_url: Option<String>,
}
