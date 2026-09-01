// SPDX-License-Identifier: GPL-2.0-only

//! Public administrator models for allow-only volume permission grants.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{AssuranceLevel, NamespaceRight, NullableField, OperationId, PrincipalId, VolumeId};

macro_rules! public_identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(
            #[schemars(
                length(equal = 36),
                pattern(
                    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                )
            )]
            String,
        );

        impl $name {
            /// Parses exact canonical versioned UUID text.
            #[must_use]
            pub fn parse(value: &str) -> Option<Self> {
                crate::directory_listing::parse_public_uuid(value).map(Self)
            }

            /// Constructs canonical UUID text from validated versioned UUID bytes.
            #[must_use]
            pub fn from_uuid_bytes(value: [u8; 16]) -> Option<Self> {
                let version = value[6] >> 4;
                if !(1..=8).contains(&version) || value[8] >> 6 != 2 {
                    return None;
                }
                Some(Self(crate::model::format_uuid(value)))
            }

            /// Returns canonical UUID text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

public_identifier!(
    PermissionGrantId,
    "Stable identity of one permission grant."
);
public_identifier!(
    PermissionActivationPolicyId,
    "Stable identity of one access-activation policy."
);

/// Opaque continuation for one volume permission-grant page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PermissionGrantCursor(
    #[schemars(length(min = 1, max = 1_024), pattern(r"^[A-Za-z0-9._~-]+$"))] String,
);

impl PermissionGrantCursor {
    /// Constructs a cursor after the authoritative codec has validated its fields.
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

/// One bounded permission-grant query.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListVolumePermissionGrantsQuery {
    /// Exact continuation returned by the preceding page.
    pub cursor: Option<PermissionGrantCursor>,
    /// Requested result bound; omission applies the server default.
    #[schemars(range(min = 1, max = 256))]
    pub limit: Option<u16>,
}

/// Explicit descendant behaviour for an allow-only grant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionGrantInheritance {
    /// The volume root only.
    Object,
    /// Descendants only.
    Descendants,
    /// The volume root and every descendant.
    ObjectAndDescendants,
}

/// One exact public permission-window instant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PermissionGrantInstant(#[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))] i64);

impl PermissionGrantInstant {
    /// Returns the untrusted epoch-microsecond value.
    #[must_use]
    pub const fn epoch_micros(self) -> i64 {
        self.0
    }
}

/// Optional reasoned, time-bounded activation required before a grant contributes rights.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionActivationRequirement {
    /// Longest activation the user may request.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub maximum_duration_micros: u64,
    /// Whether every activation must contain a non-blank reason.
    pub reason_required: bool,
    /// Authentication assurance required when activating.
    pub minimum_assurance: AssuranceLevel,
}

/// Idempotent administrator request to grant volume authority to one user or group.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVolumePermissionGrantRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// User or group receiving the rights.
    pub subject_principal_id: PrincipalId,
    /// Non-empty ordered protocol-neutral allow rights.
    #[schemars(length(min = 1, max = 13))]
    pub rights: Vec<NamespaceRight>,
    /// Whether authority applies to the root, descendants or both.
    pub inheritance: PermissionGrantInheritance,
    /// Omitted applies policy defaults, null is unbounded, and a value is exact.
    #[serde(default, skip_serializing_if = "NullableField::is_missing")]
    pub valid_from_epoch_micros: NullableField<PermissionGrantInstant>,
    /// Omitted applies policy defaults, null is unbounded, and a value is exact.
    #[serde(default, skip_serializing_if = "NullableField::is_missing")]
    pub valid_until_epoch_micros: NullableField<PermissionGrantInstant>,
    /// Omitted applies policy defaults, null needs no activation, and a value defines activation.
    #[serde(default, skip_serializing_if = "NullableField::is_missing")]
    pub activation: NullableField<PermissionActivationRequirement>,
}

/// One active allow-only volume permission grant.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VolumePermissionGrantSummary {
    /// Stable grant identity.
    pub grant_id: PermissionGrantId,
    /// User or group receiving the rights.
    pub subject_principal_id: PrincipalId,
    /// Volume whose root defines this grant's scope.
    pub volume_id: VolumeId,
    /// Complete ordered non-empty right set.
    #[schemars(length(min = 1, max = 13))]
    pub rights: Vec<NamespaceRight>,
    /// Explicit descendant behaviour.
    pub inheritance: PermissionGrantInheritance,
    /// Inclusive validity start, or null when unbounded below.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub valid_from_epoch_micros: Option<i64>,
    /// Exclusive validity end, or null when unbounded above.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub valid_until_epoch_micros: Option<i64>,
    /// Policy that must be activated, or null when authority is immediately usable.
    pub activation_policy_id: Option<PermissionActivationPolicyId>,
    /// Principal that created this grant.
    pub created_by: PrincipalId,
    /// Original authoritative creation instant.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub created_at_epoch_micros: i64,
    /// Current authoritative grant revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded stable page of active volume grants.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListVolumePermissionGrantsResponse {
    /// Exact volume represented by the page.
    pub volume_id: VolumeId,
    /// Stable grant records ordered by grant identity.
    #[schemars(length(max = 256))]
    pub grants: Vec<VolumePermissionGrantSummary>,
    /// Ready-to-follow relative URL, or null at the terminal page.
    #[schemars(length(min = 1, max = 16_384), pattern(r"^/api/latest/admin/volumes/"))]
    pub next_page_url: Option<String>,
}

/// Durable result of creating or exactly replaying one permission grant.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVolumePermissionGrantResponse {
    /// Exact idempotency identity whose committed result was resolved.
    pub operation_id: OperationId,
    /// Newly active or exactly replayed grant.
    pub grant: VolumePermissionGrantSummary,
}

/// A non-blank bounded reason for revoking authority.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PermissionGrantRevocationReason(
    #[schemars(length(min = 1, max = 512), pattern(r"^\S(?:[\s\S]*\S)?$"))] String,
);

impl PermissionGrantRevocationReason {
    /// Returns the validated audit-reason candidate.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_domain_candidate(&self) -> bool {
        self.0 == self.0.trim() && (1..=512).contains(&self.0.len())
    }
}

/// Idempotent administrator request to revoke one exact active grant.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokePermissionGrantRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// Human-readable audit reason retained with revocation evidence.
    pub reason: PermissionGrantRevocationReason,
}

/// Durable result of revoking or exactly replaying one permission grant.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokePermissionGrantResponse {
    /// Exact idempotency identity whose committed result was resolved.
    pub operation_id: OperationId,
    /// Exact grant that was revoked.
    pub grant_id: PermissionGrantId,
    /// Original authoritative revocation instant used by exact retries.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub revoked_at_epoch_micros: i64,
    /// Authoritative revocation revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}
