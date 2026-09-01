// SPDX-License-Identifier: GPL-2.0-only

//! Public manager-only local storage-folder administration models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::OperationId;

/// One absolute UTF-8 local folder path accepted by the public appliance API.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct StorageFolderPath(
    #[schemars(length(min = 1, max = 16_384), pattern(r"^/[^\x00-\x1f\x7f]*$"))] String,
);

impl StorageFolderPath {
    /// Returns the untrusted path candidate for local capability validation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Per-folder maximum physical capacity `MeshSpan` may own.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum StorageFolderUsageLimit {
    /// Percentage of measured backing-filesystem capacity.
    Percent {
        /// Inclusive percentage from 1 through 100.
        #[schemars(range(min = 1, max = 100))]
        percent: u8,
    },
    /// Fixed byte ceiling represented as lossless decimal text.
    Bytes {
        /// Positive unsigned 64-bit decimal bytes.
        #[schemars(length(min = 1, max = 20), pattern(r"^[1-9][0-9]{0,19}$"))]
        bytes: String,
    },
}

/// Current local serving state of one registered storage folder.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageFolderState {
    /// Restart-safe registration is still completing.
    Configuring,
    /// The provider is open and serving authenticated storage work.
    Active,
    /// Registration is durable but the folder is currently unavailable.
    Unavailable,
}

/// One local storage target safe to show only to a system manager.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFolderSummary {
    /// Stable target identity independent of path spelling.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub target_id: String,
    /// Permanent daemon identity that owns this target generation.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub node_id: String,
    /// Exact local UTF-8 path, or null when a headless path cannot be represented safely.
    #[schemars(length(min = 1, max = 16_384), pattern(r"^/[^\x00-\x1f\x7f]*$"))]
    pub path: Option<String>,
    /// Current immutable target generation as lossless positive decimal text.
    #[schemars(length(min = 1, max = 20), pattern(r"^[1-9][0-9]{0,19}$"))]
    pub generation: String,
    /// Configured physical capacity ceiling.
    pub usage_limit: StorageFolderUsageLimit,
    /// Current local serving state.
    pub state: StorageFolderState,
}

/// Opaque continuation token for local storage-folder inventory.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct StorageFolderCursor(
    #[schemars(length(min = 1, max = 128), pattern(r"^[A-Za-z0-9._~-]+$"))] String,
);

impl StorageFolderCursor {
    /// Constructs one cursor after server-side codec validation.
    #[must_use]
    pub fn from_encoded(value: String) -> Option<Self> {
        ((1..=128).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte)))
        .then_some(Self(value))
    }

    /// Returns the opaque cursor bytes for server-side decoding.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded local storage-folder inventory query.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListStorageFoldersQuery {
    /// Exact continuation from the preceding page.
    pub cursor: Option<StorageFolderCursor>,
    /// Requested page bound; omission applies the server default.
    #[schemars(range(min = 1, max = 256))]
    pub limit: Option<u16>,
}

/// Current manager-only page of local storage folders.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListStorageFoldersResponse {
    /// Stable target-identity-ordered folder summaries.
    #[schemars(length(max = 256))]
    pub folders: Vec<StorageFolderSummary>,
    /// Ready-to-follow same-origin URL, or null at the terminal page.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/admin/storage-folders")
    )]
    pub next_page_url: Option<String>,
}

/// Exact-retry manager request to register one existing local folder.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterStorageFolderRequest {
    /// Client-generated idempotency identity persisted before touching the provider folder.
    pub operation_id: OperationId,
    /// Existing local folder; sibling files are never read, changed or exposed.
    pub path: StorageFolderPath,
    /// Maximum capacity `MeshSpan` may own beneath its private subdirectory.
    pub usage_limit: StorageFolderUsageLimit,
}

/// Durable registration result after the target is open locally.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterStorageFolderResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Current registered local target.
    pub folder: StorageFolderSummary,
}
