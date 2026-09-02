// SPDX-License-Identifier: GPL-2.0-only

//! Public explicit SMB-export administration models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ObjectId, OperationId, VolumeId};

/// Stable replicated SMB-export identity.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SmbExportId(
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    String,
);

impl SmbExportId {
    /// Parses exact canonical versioned UUID text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        super::directory_listing::parse_public_uuid(value).map(Self)
    }

    /// Constructs canonical text from validated versioned UUID bytes.
    #[must_use]
    pub fn from_uuid_bytes(value: [u8; 16]) -> Option<Self> {
        super::directory_listing::parse_public_uuid(&crate::model::format_uuid(value)).map(Self)
    }

    /// Returns canonical UUID text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Case-preserved SMB share name with no path or control characters.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SmbShareName(
    #[schemars(length(min = 1, max = 240), pattern(r"^[^\x00-\x1f\x2f\x7f\\]+$"))] String,
);

impl SmbShareName {
    /// Returns the untrusted display-name candidate for domain canonicalisation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Gateways authorised to publish one share.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum SmbExportGatewaySelection {
    /// Every active gateway node publishes the share.
    AllEligible,
    /// Only the explicitly selected active gateway nodes publish the share.
    Selected {
        /// Non-empty unique canonical node UUIDs.
        #[schemars(length(min = 1, max = 1_024))]
        node_ids: Vec<String>,
    },
}

impl SmbExportGatewaySelection {
    /// Borrows selected node identifiers, or returns none for all eligible gateways.
    #[must_use]
    pub fn selected_node_ids(&self) -> Option<&[String]> {
        match self {
            Self::AllEligible => None,
            Self::Selected { node_ids } => Some(node_ids),
        }
    }
}

/// Exact-retry request to publish one existing volume or folder explicitly.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishSmbExportRequest {
    /// Client-generated idempotency identity.
    pub operation_id: OperationId,
    /// Stable existing directory exposed as the share root.
    pub root_object_id: ObjectId,
    /// Chosen case-insensitive share name.
    pub share_name: SmbShareName,
    /// Explicit gateway publication policy.
    pub gateways: SmbExportGatewaySelection,
    /// Whether every packet after tree connection must be encrypted.
    pub encryption_required: bool,
}

/// Durable publication result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishSmbExportResponse {
    /// Exact operation whose committed result was resolved.
    pub operation_id: OperationId,
    /// Stable export identity derived from that operation.
    pub export_id: SmbExportId,
    /// Exact containing volume.
    pub volume_id: VolumeId,
    /// Exact published directory.
    pub root_object_id: ObjectId,
    /// Case-preserved authoritative share name.
    pub share_name: SmbShareName,
    /// Committed gateway policy.
    pub gateways: SmbExportGatewaySelection,
    /// Committed tree-encryption policy.
    pub encryption_required: bool,
    /// Authoritative committed revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// Exact-retry audited withdrawal request.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawSmbExportRequest {
    /// Client-generated idempotency identity.
    pub operation_id: OperationId,
    /// Non-blank human audit reason.
    #[schemars(length(min = 1, max = 1_024), pattern(r"\S"))]
    pub reason: String,
}

/// Durable export-withdrawal result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawSmbExportResponse {
    /// Exact operation whose committed result was resolved.
    pub operation_id: OperationId,
    /// Stable withdrawn export identity.
    pub export_id: SmbExportId,
    /// Authoritative committed revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}
