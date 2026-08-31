// SPDX-License-Identifier: GPL-2.0-only

//! Public administrator identity-management models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{OperationId, PrincipalId};

/// A bounded user/group display name; the authoritative domain performs NFC canonicalisation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PrincipalName(
    #[schemars(length(min = 1, max = 256), pattern(r"^[^\x00-\x1f\x2f\x7f\\]+$"))] String,
);

impl PrincipalName {
    /// Returns the untrusted display-name candidate for domain validation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_domain_candidate(&self) -> bool {
        self.0 == self.0.trim()
            && !matches!(self.0.as_str(), "." | "..")
            && (1..=256).contains(&self.0.len())
    }
}

/// An opaque, bounded, URL-safe identity-list continuation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PrincipalCursor(
    #[schemars(length(min = 1, max = 1_024), pattern(r"^[A-Za-z0-9._~-]+$"))] String,
);

impl PrincipalCursor {
    /// Constructs a cursor that has passed the authoritative cursor codec.
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

/// One bounded administrator identity-list query.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListPrincipalsQuery {
    /// Exact continuation returned by the preceding page.
    pub cursor: Option<PrincipalCursor>,
    /// Requested result bound; omission applies the server default.
    #[schemars(range(min = 1, max = 256))]
    pub limit: Option<u16>,
}

/// Public user/group family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// Login-capable or service user.
    User,
    /// Nested identity group.
    Group,
}

/// Public lifecycle state of one user or group.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalState {
    /// The principal may authenticate or contribute authority.
    Active,
    /// The principal is reversibly disabled.
    Suspended,
    /// The principal is terminally disabled.
    Retired,
}

/// Complete administration summary of one local user or group.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalSummary {
    /// Stable local identity.
    pub principal_id: PrincipalId,
    /// User or nested group.
    pub kind: PrincipalKind,
    /// Case-preserved NFC display name.
    pub display_name: String,
    /// Current lifecycle state.
    pub state: PrincipalState,
    /// Original authoritative creation instant as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub created_at_epoch_micros: i64,
    /// Last authoritative metadata revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded, permission-filtered administrator identity page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListPrincipalsResponse {
    /// Principal family selected by the endpoint.
    pub kind: PrincipalKind,
    /// Stable ordered identities.
    #[schemars(length(max = 256))]
    pub principals: Vec<PrincipalSummary>,
    /// Ready-to-follow relative URL, or null at the terminal page.
    #[schemars(length(min = 1, max = 16_384), pattern(r"^/api/latest/admin/"))]
    pub next_page_url: Option<String>,
}

/// Idempotent administrator request to create one user.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUserRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// Human-readable user name.
    pub display_name: PrincipalName,
}

/// Idempotent administrator request to create one nested group.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateGroupRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// Human-readable group name.
    pub display_name: PrincipalName,
}

/// Durable creation result shared by users and groups.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePrincipalResponse {
    /// Exact idempotency identity whose committed result was resolved.
    pub operation_id: OperationId,
    /// Newly created or exactly replayed principal.
    pub principal: PrincipalSummary,
}
