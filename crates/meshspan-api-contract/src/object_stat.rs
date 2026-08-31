// SPDX-License-Identifier: GPL-2.0-only

//! Public metadata contract for one logical object selected by path.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{NamespaceCommitId, NamespacePath, ObjectMetadataResponse, VolumeId};

/// Exact bounded path query for one logical object.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GetObjectQuery {
    /// Required root-relative logical object path.
    pub path: NamespacePath,
}

/// Complete immutable metadata for one logical object.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GetObjectResponse {
    /// Selected logical volume.
    pub volume_id: VolumeId,
    /// Exact root-relative path which resolved the object.
    pub path: NamespacePath,
    /// Immutable namespace view under which the path resolved.
    pub namespace_commit_id: NamespaceCommitId,
    /// Complete object metadata, including the immutable file version when applicable.
    pub object: ObjectMetadataResponse,
}
