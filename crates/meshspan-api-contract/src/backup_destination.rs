// SPDX-License-Identifier: GPL-2.0-only

//! Public controls for registered-folder metadata backup destinations.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::OperationId;

/// One registered target selected for encrypted recovery copies.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureBackupDestinationRequest {
    /// Stable logical identity retained across retries.
    pub operation_id: OperationId,
    /// Stable destination identity. A different provider requires a new identity.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub destination_id: String,
    /// Observed destination revision; zero creates a destination.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_u64))]
    pub expected_revision: u64,
    /// Human-facing name, without control characters.
    #[schemars(length(min = 1, max = 128), pattern(r"^\P{Cc}+$"))]
    pub name: String,
    /// Exact registered storage target, never a raw path.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub target_id: String,
    /// Observed target generation. A returned or replaced target must match it.
    #[schemars(length(min = 1, max = 20), pattern(r"^[1-9][0-9]{0,19}$"))]
    pub target_generation: String,
    /// Accept new backup copies when true; false pauses future copies, not deletion.
    pub enabled: bool,
}

/// Bounded live inventory of configured destinations, including paused entries.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListBackupDestinationsQuery {
    /// Page size; defaults to 50.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "u16", range(min = 1, max = 256))]
    pub limit: Option<u16>,
    /// Opaque continuation returned by this inventory for this caller and partition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(
        with = "String",
        length(min = 1, max = 256),
        pattern(r"^[a-zA-Z0-9._-]+$")
    )]
    pub cursor: Option<String>,
}

/// Desired eligibility; none of these states claims that verified copies exist.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupDestinationStatus {
    /// Eligible for new copies.
    Active,
    /// New copies are paused.
    Paused,
    /// Retained historical destination.
    Retired,
}

/// Declared failure evidence, not a guarantee based on folder or node count.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupDestinationFailureRelationship {
    /// Independence has not been proved.
    Unknown,
    /// A declared failure boundary overlaps.
    Overlapping,
    /// Separately recorded evidence declares independence.
    Independent,
}

/// Exact replaceable provider binding. Only registered targets are configurable here initially.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupDestinationProvider {
    /// Registered storage, local or on another node in this swarm.
    RegisteredTarget {
        /// Registered target identity.
        #[schemars(
            length(equal = 36),
            pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        )]
        target_id: String,
    },
    /// Independently administered remote swarm.
    FederatedMesh {
        /// Remote swarm identity.
        #[schemars(
            length(equal = 36),
            pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        )]
        remote_mesh_id: String,
    },
    /// Replaceable installed component.
    ComponentProvider {
        /// Component instance identity.
        #[schemars(
            length(equal = 36),
            pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        )]
        instance_id: String,
    },
}

/// Secret-free current destination configuration.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupDestinationSummary {
    /// Stable destination identity.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub destination_id: String,
    /// Human-facing display name.
    #[schemars(length(min = 1, max = 128), pattern(r"^\P{Cc}+$"))]
    pub name: String,
    /// Exact provider identity, without paths or credentials.
    pub provider: BackupDestinationProvider,
    /// Provider generation fenced into copy receipts.
    #[schemars(length(min = 1, max = 20), pattern(r"^[1-9][0-9]{0,19}$"))]
    pub provider_generation: String,
    /// Current desired eligibility.
    pub state: BackupDestinationStatus,
    /// Honest failure relationship; registration alone cannot establish independence.
    pub failure_relationship: BackupDestinationFailureRelationship,
    /// Destination-specific compare-and-swap revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One current-authorisation inventory page, ordered by destination identity.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListBackupDestinationsResponse {
    /// At most the requested number of current destination records.
    #[schemars(length(max = 256))]
    pub destinations: Vec<BackupDestinationSummary>,
    /// Relative continuation URL, or explicitly null at the end.
    #[schemars(
        length(max = 512),
        pattern(r"^/api/latest/admin/backups/destinations\?limit=[0-9]+&cursor=[a-zA-Z0-9._-]+$")
    )]
    pub next_page_url: Option<String>,
}

/// Original durable receipt; configuration does not imply completed backup protection.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureBackupDestinationResponse {
    /// Original operation identity.
    pub operation_id: OperationId,
    /// Exact destination configured.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub destination_id: String,
    /// Destination revision created by this operation, even if later superseded.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}
