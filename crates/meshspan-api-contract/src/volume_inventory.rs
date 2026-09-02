// SPDX-License-Identifier: GPL-2.0-only

//! Public permission-filtered logical-volume inventory models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{OperationId, PrincipalId, VolumeId};

/// A bounded logical-volume display name with no path semantics.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct VolumeName(
    #[schemars(length(min = 1, max = 256), pattern(r"^[^\x00-\x1f\x2f\x7f\\]+$"))] String,
);

impl VolumeName {
    /// Returns the untrusted display-name candidate for authoritative canonicalisation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_domain_candidate(&self) -> bool {
        self.0 == self.0.trim() && !matches!(self.0.as_str(), "." | "..")
    }
}

/// Opaque continuation for one permission-filtered volume page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct VolumeCursor(
    #[schemars(length(min = 1, max = 1_024), pattern(r"^[A-Za-z0-9._~-]+$"))] String,
);

impl VolumeCursor {
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

/// One bounded current-user volume query.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListVolumesQuery {
    /// Exact continuation returned by the preceding page.
    pub cursor: Option<VolumeCursor>,
    /// Requested result bound; omission applies the server default.
    #[schemars(range(min = 1, max = 256))]
    pub limit: Option<u16>,
}

/// Public lifecycle of one logical volume.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeState {
    /// Serving authorised work.
    Active,
    /// Reversibly unavailable for ordinary work.
    Suspended,
    /// Refusing new responsibility while existing work is moved away.
    Draining,
    /// Permanently fenced from new work.
    Retired,
}

/// Protocol-neutral namespace authority currently available to this caller.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceRight {
    /// Traverse ancestor directories.
    Traverse,
    /// Enumerate directory entries.
    List,
    /// Read file bytes.
    ReadData,
    /// Create a child object.
    CreateChild,
    /// Replace or modify file bytes.
    WriteData,
    /// Append file bytes.
    AppendData,
    /// Rename or move an object.
    Rename,
    /// Delete an object or empty directory.
    Delete,
    /// Read object attributes.
    ReadAttributes,
    /// Change object attributes.
    WriteAttributes,
    /// Read owners and permission grants.
    ReadPermissions,
    /// Change permission grants.
    ChangePermissions,
    /// Change the owner set.
    ChangeOwner,
}

/// One logical volume visible through the caller's current committed authority.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeSummary {
    /// Stable logical-volume identity.
    pub volume_id: VolumeId,
    /// Stable root-directory identity used by connectors and administration.
    pub root_object_id: crate::ObjectId,
    /// Case-preserved user-facing name.
    #[schemars(length(min = 1, max = 256), pattern(r"^[^\x00-\x1f\x7f]+$"))]
    pub name: String,
    /// Current authoritative lifecycle state.
    pub state: VolumeState,
    /// Complete ordered rights available at the volume root for this request.
    #[schemars(length(min = 2, max = 13))]
    pub effective_rights: Vec<NamespaceRight>,
    /// Authoritative creation instant as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub created_at_epoch_micros: i64,
    /// Last authoritative metadata revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded current-user volume page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListVolumesResponse {
    /// Stable ordered volumes visible under the caller's current permissions.
    #[schemars(length(max = 256))]
    pub volumes: Vec<VolumeSummary>,
    /// Ready-to-follow relative URL, or null at the terminal page.
    #[schemars(length(min = 1, max = 16_384), pattern(r"^/api/latest/volumes"))]
    pub next_page_url: Option<String>,
}

/// Idempotent administrator request to create one logical volume.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVolumeRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// Human-readable logical-volume name.
    pub name: VolumeName,
    /// Non-empty user/group owner set; ownership is never inferred from shard placement.
    #[schemars(length(min = 1, max = 1_024))]
    pub owner_principal_ids: Vec<PrincipalId>,
}

/// Durable authoritative volume-creation outcome.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVolumeResponse {
    /// Exact idempotency identity whose committed result was resolved.
    pub operation_id: OperationId,
    /// Stable logical-volume identity.
    pub volume_id: VolumeId,
    /// Stable root-directory identity used by connectors.
    pub root_object_id: crate::ObjectId,
    /// Case-preserved authoritative name.
    pub name: String,
    /// Exact immutable initial owner set.
    #[schemars(length(min = 1, max = 1_024))]
    pub owner_principal_ids: Vec<PrincipalId>,
    /// Original authoritative creation instant as epoch microseconds.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub created_at_epoch_micros: i64,
    /// Authoritative revision created by the operation.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}
