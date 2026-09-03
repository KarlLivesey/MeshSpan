// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative metadata-backup catalogue commands.

use meshspan_domain::{
    BackupDestinationId, BackupId, ComponentInstanceId, MeshId, PartitionId, Revision, TargetId,
};

use crate::RecordName;

/// Maximum provider-owned object reference retained in replicated metadata.
pub const MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES: usize = 2_048;

/// Replaceable destination selected for one encrypted backup copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupDestinationBinding {
    /// One exact generation of a registered storage target.
    RegisteredTarget {
        /// Registered target identity.
        target_id: TargetId,
        /// Marker-fenced target generation.
        target_generation: u64,
    },
    /// One independently administered federated mesh.
    FederatedMesh {
        /// Remote mesh identity.
        remote_mesh_id: MeshId,
        /// Remote provider contract generation.
        provider_generation: u64,
    },
    /// One installed replaceable backup-provider component.
    ComponentProvider {
        /// Component instance identity.
        instance_id: ComponentInstanceId,
        /// Desired component configuration generation.
        provider_generation: u64,
    },
}

impl BackupDestinationBinding {
    /// Exact provider generation fenced into copy receipts.
    #[must_use]
    pub const fn provider_generation(self) -> u64 {
        match self {
            Self::RegisteredTarget {
                target_generation, ..
            } => target_generation,
            Self::FederatedMesh {
                provider_generation,
                ..
            }
            | Self::ComponentProvider {
                provider_generation,
                ..
            } => provider_generation,
        }
    }
}

/// Administrator-visible relationship between a destination and local failure boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupFailureRelationship {
    /// Independence has not been established and must not be claimed.
    Unknown,
    /// At least one declared failure boundary overlaps the protected source.
    Overlapping,
    /// The destination is declared independent by its configured evidence.
    Independent,
}

/// Creates or replaces one configured encrypted-backup destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigureBackupDestination {
    /// Stable destination identity.
    pub destination_id: BackupDestinationId,
    /// Human and canonical names.
    pub name: RecordName,
    /// Exact target, remote mesh or replaceable provider binding.
    pub binding: BackupDestinationBinding,
    /// Honest declared relationship to local failure boundaries.
    pub failure_relationship: BackupFailureRelationship,
    /// Digest of the separately inspectable failure evidence used for this declaration.
    pub failure_evidence_digest: [u8; 32],
    /// Whether new backup generations may be sent here.
    pub enabled: bool,
}

/// Exact encrypted partition backup admitted to the replicated catalogue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordMetadataBackup {
    /// Stable backup identity.
    pub backup_id: BackupId,
    /// Source partition identity.
    pub partition_id: PartitionId,
    /// Owning mesh identity.
    pub mesh_id: MeshId,
    /// Last applied committed log index represented by the source bytes.
    pub last_log_index: u64,
    /// Term of `last_log_index`.
    pub last_log_term: u64,
    /// Exact applied state revision.
    pub state_revision: Revision,
    /// SQLite-compatible schema version represented by the source bytes.
    pub schema_version: u32,
    /// Plaintext source length retained without retaining plaintext bytes.
    pub source_byte_length: u64,
    /// Digest of the exact plaintext source.
    pub source_digest: [u8; 32],
    /// Digest of the authenticated container header and source manifest.
    pub manifest_digest: [u8; 32],
    /// Closed encrypted container length.
    pub encrypted_byte_length: u64,
    /// Digest of the complete encrypted container.
    pub encrypted_digest: [u8; 32],
}

/// Provider-confirmed placement of one exact encrypted backup container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordBackupCopy {
    /// Exact backup generation copied.
    pub backup_id: BackupId,
    /// Configured destination that accepted it.
    pub destination_id: BackupDestinationId,
    /// Provider generation used for the write.
    pub provider_generation: u64,
    /// Bounded opaque lookup reference returned by the provider.
    pub object_reference: String,
    /// Exact stored object length.
    pub byte_length: u64,
    /// Digest of the stored encrypted object.
    pub copy_digest: [u8; 32],
}

/// Read-after-write verification of one unchanged backup copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyBackupCopy {
    /// Exact backup generation checked.
    pub backup_id: BackupId,
    /// Exact destination checked.
    pub destination_id: BackupDestinationId,
    /// Provider generation which returned the bytes.
    pub provider_generation: u64,
    /// Digest independently recomputed from the returned encrypted bytes.
    pub copy_digest: [u8; 32],
}
