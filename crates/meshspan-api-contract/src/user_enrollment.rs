// SPDX-License-Identifier: GPL-2.0-only

//! Bounded first-credential invitation and recipient API-key enrollment contracts.

use crate::{ApiKeyExpiry, AuthenticationMethodLabel, NullableField, OperationId, PrincipalId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Recent-step-up manager consent for one active user's first primary method.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssueUserEnrollmentRequest {
    /// Exact retry identity; also identifies the invitation itself.
    pub operation_id: OperationId,
    /// Current target-principal revision, checked again inside the authority transaction.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub expected_principal_revision: u64,
    /// Exclusive capability expiry, at most 24 hours after authoritative issuance.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub expires_at_epoch_micros: i64,
}

/// Secret-bearing committed invitation, recoverable only during its live capability window.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssueUserEnrollmentResponse {
    /// Exact committed consent and invitation identity.
    pub operation_id: OperationId,
    /// Recipient who may register their first primary method.
    pub principal_id: PrincipalId,
    /// Distinct one-use enrollment token; never a session, API key or URL parameter.
    #[schemars(length(equal = 125), pattern(r"^meshspan-user-enrollment-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$"), extend("readOnly" = true), extend("x-meshspan-sensitive" = true))]
    pub token: String,
    /// Exclusive end of invitation redemption and secret-response retrieval.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub expires_at_epoch_micros: i64,
    /// Authoritative invitation revision for cancellation.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}

/// Exact manager request to stop invitation use and secret-bearing replay.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeUserEnrollmentRequest {
    /// Exact retry identity of this cancellation.
    pub operation_id: OperationId,
    /// Expected current invitation revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub expected_revision: u64,
}

/// Committed cancellation; an already-created method remains separately revocable.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeUserEnrollmentResponse {
    /// Exact cancellation identity.
    pub operation_id: OperationId,
    /// Issuance operation whose capability can no longer be used.
    pub enrollment_operation_id: OperationId,
    /// Resulting authoritative invitation revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}

/// Entry points supported by the initial primary-key enrollment workflow.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentApiKeyScope {
    /// Establish an ordinary browser session.
    HttpsSession,
    /// Use the native public API with the user's ordinary resource permissions.
    HeadlessApi,
}

/// Anonymous capability redemption into a normal independently revocable API key.
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemUserEnrollmentApiKeyRequest {
    /// Retained exact identity for both credential creation and response recovery.
    pub operation_id: OperationId,
    /// Secret first-credential capability; never accepted through a URL or login handler.
    #[schemars(length(equal = 125), pattern(r"^meshspan-user-enrollment-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$"), extend("writeOnly" = true), extend("x-meshspan-sensitive" = true))]
    pub token: String,
    /// Recipient's label for their ordinary credential.
    pub label: AuthenticationMethodLabel,
    /// Nonempty deduplicated entry points; these do not confer resource permissions.
    #[schemars(length(min = 1, max = 2))]
    pub scopes: Vec<EnrollmentApiKeyScope>,
    /// Exact key expiry, or explicit null for no automatic key expiry.
    pub expires_at_epoch_micros: NullableField<ApiKeyExpiry>,
}
