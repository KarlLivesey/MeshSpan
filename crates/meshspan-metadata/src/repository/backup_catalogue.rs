// SPDX-License-Identifier: GPL-2.0-only

//! Replicated metadata-backup destinations, generations and verified-copy evidence.

mod mutation;
mod query;

use meshspan_domain::{BackupDestinationId, BackupId, MeshId, PartitionId, Revision, UnixMicros};

use crate::{BackupDestinationBinding, BackupFailureRelationship};

pub(super) use mutation::{configure_destination, record_backup, record_copy, verify_copy};
pub(super) use query::{active_destinations, backup, copy, destination, destinations};

/// Stable seek position for a backup-destination inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupDestinationCursor {
    /// Last destination returned by the preceding page.
    pub destination_id: BackupDestinationId,
}

/// Current lifecycle of one exact metadata backup generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataBackupState {
    /// Encrypted bytes exist but no destination copy has passed read-after-write verification.
    Recorded,
    /// At least one current destination copy has passed exact digest verification.
    Verified,
    /// Retained historical evidence which is no longer a restore candidate.
    Retired,
}

/// One exact encrypted metadata backup generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataBackupRecord {
    /// Stable backup identity.
    pub backup_id: BackupId,
    /// Source partition.
    pub partition_id: PartitionId,
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// Exact applied log index.
    pub last_log_index: u64,
    /// Exact applied log term.
    pub last_log_term: u64,
    /// Exact state revision.
    pub state_revision: Revision,
    /// SQLite-compatible schema version represented by the source bytes.
    pub schema_version: u32,
    /// Plaintext source length.
    pub source_byte_length: u64,
    /// Plaintext source digest.
    pub source_digest: [u8; 32],
    /// Authenticated source-manifest digest.
    pub manifest_digest: [u8; 32],
    /// Closed encrypted container length.
    pub encrypted_byte_length: u64,
    /// Digest of the complete encrypted container.
    pub encrypted_digest: [u8; 32],
    /// Current recovery lifecycle.
    pub state: MetadataBackupState,
    /// Authority time at catalogue admission.
    pub created_at: UnixMicros,
    /// First successful copy verification, when any.
    pub verified_at: Option<UnixMicros>,
    /// Last authoritative revision.
    pub revision: Revision,
}

/// Current desired state of one backup destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupDestinationState {
    /// Eligible for new backup copies.
    Active,
    /// Retained but not eligible for new copies.
    Paused,
    /// Retained historical destination no longer available for work.
    Retired,
}

/// One configured destination and its honest declared failure relationship.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupDestinationRecord {
    /// Stable destination identity.
    pub destination_id: BackupDestinationId,
    /// Human-facing display name.
    pub display_name: String,
    /// Canonical uniqueness key.
    pub canonical_name: String,
    /// Exact provider binding and generation.
    pub binding: BackupDestinationBinding,
    /// Declared relationship to source failure boundaries.
    pub failure_relationship: BackupFailureRelationship,
    /// Digest of separately inspectable failure evidence.
    pub failure_evidence_digest: [u8; 32],
    /// Current desired state.
    pub state: BackupDestinationState,
    /// First creation time.
    pub created_at: UnixMicros,
    /// Last authoritative revision.
    pub revision: Revision,
}

/// Current durable state of one backup copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupCopyState {
    /// Provider accepted the exact encrypted bytes.
    Stored,
    /// Read-after-write returned the exact expected encrypted bytes.
    Verified,
    /// Latest provider verification failed.
    Failed,
    /// Historical copy no longer eligible for restore.
    Retired,
}

/// One exact provider copy and its verification evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCopyRecord {
    /// Exact backup generation.
    pub backup_id: BackupId,
    /// Exact configured destination.
    pub destination_id: BackupDestinationId,
    /// Provider generation used for IO.
    pub provider_generation: u64,
    /// Opaque provider lookup reference.
    pub object_reference: String,
    /// Exact encrypted object length.
    pub byte_length: u64,
    /// Exact encrypted object digest.
    pub copy_digest: [u8; 32],
    /// Current copy lifecycle.
    pub state: BackupCopyState,
    /// Provider-confirmed storage time.
    pub stored_at: UnixMicros,
    /// Read-after-write verification time.
    pub verified_at: Option<UnixMicros>,
    /// Last authoritative revision.
    pub revision: Revision,
}
