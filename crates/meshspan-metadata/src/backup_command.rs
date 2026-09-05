// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative metadata-backup catalogue commands.

use meshspan_domain::{
    BackupDestinationId, BackupId, ComponentInstanceId, DurationMicros, MeshId, NodeId,
    PartitionId, Revision, TargetId, UnixMicros,
};

pub use meshspan_contracts::MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES;

use crate::RecordName;

/// Reconciles appliance-managed backup configuration without replacing explicit choices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconcileMetadataBackupDefaults {
    /// Owning metadata partition.
    pub partition_id: PartitionId,
    /// Topology/configuration revision used to request reconciliation.
    pub expected_topology_revision: Revision,
    /// Current defaults-state revision, or zero before first initialisation.
    pub expected_defaults_revision: Revision,
}

/// Maximum retained-generation witness set in one automatic retirement command.
pub const MAXIMUM_BACKUP_RETENTION_WITNESSES: usize = 1_024;

/// Retires an old generation only while newer verified generations satisfy current policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetireMetadataBackup {
    /// Exact older generation selected for retirement.
    pub backup_id: BackupId,
    /// Observed revision of that generation, not the entire partition.
    pub expected_backup_revision: Revision,
    /// Current retention policy sequence; a policy change invalidates the decision.
    pub expected_schedule_sequence: u64,
    /// Exact newer retained generations, unique and sorted by identity.
    pub retained_backups: Vec<BackupId>,
}

/// Records provider-confirmed physical removal of one already retired copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordBackupReclamation {
    /// Exact provider result; never a location-only claim or an inferred timeout outcome.
    pub receipt: meshspan_contracts::BackupDeleteReceipt,
}

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
    /// Exact destination revision being replaced, or zero when creating it.
    pub expected_destination_revision: Revision,
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

/// Creates or replaces the automatic backup policy for one metadata partition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigureMetadataBackupSchedule {
    /// Partition whose committed state is backed up.
    pub partition_id: PartitionId,
    /// Current immutable schedule sequence, or zero when creating it.
    pub expected_schedule_sequence: u64,
    /// Positive delay between completed backup attempts.
    pub interval: DurationMicros,
    /// Number of newest usable generations retained before reclamation.
    pub retained_generations: u16,
    /// Verified provider copies required for a protected generation.
    pub minimum_verified_copies: u8,
    /// Required subset whose configured failure relationship is independent.
    pub minimum_independent_copies: u8,
    /// Whether the scheduler may materialise new runs.
    pub enabled: bool,
    /// First or replacement authoritative due instant.
    pub next_due_at: UnixMicros,
}

/// Materialises one exact due occurrence without claiming that backup bytes exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueMetadataBackupRun {
    /// Stable identity reserved for this generation and its provider objects.
    pub backup_id: BackupId,
    /// Partition selected by the schedule.
    pub partition_id: PartitionId,
    /// Exact immutable schedule revision observed by the scheduler.
    pub expected_schedule_sequence: u64,
    /// Exact due instant observed by the scheduler.
    pub scheduled_for: UnixMicros,
}

/// Exact live worker authority carried by backup publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataBackupRunClaim {
    /// Monotonic attempt number for this run.
    pub claim_generation: u64,
    /// Authenticated worker node.
    pub worker_node_id: NodeId,
    /// Exact current daemon incarnation.
    pub worker_incarnation: u64,
    /// Positive unpredictable fence which stale workers cannot reproduce.
    pub fence: u64,
}

/// Claims one queued or expired automatic backup run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimMetadataBackupRun {
    /// Exact due generation being executed.
    pub backup_id: BackupId,
    /// New live worker authority.
    pub claim: MetadataBackupRunClaim,
    /// Bounded authoritative lease end.
    pub lease_expires_at: UnixMicros,
}

/// Extends one unchanged live automatic backup claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewMetadataBackupRun {
    /// Exact claimed generation.
    pub backup_id: BackupId,
    /// Unchanged live worker authority.
    pub claim: MetadataBackupRunClaim,
    /// Later bounded authoritative lease end.
    pub lease_expires_at: UnixMicros,
}

/// Honest terminal result of one automatic backup occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataBackupRunCompletion {
    /// Configured verified and independent-copy thresholds were met.
    Protected {
        /// Digest of the checked destination/copy evidence set.
        result_digest: [u8; 32],
    },
    /// The occurrence ended without meeting its policy and must remain visible.
    Incomplete {
        /// Typed, redacted failure and partial-evidence digest.
        result_digest: [u8; 32],
    },
}

/// Terminates one run and advances its schedule without inventing protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteMetadataBackupRun {
    /// Exact run being completed.
    pub backup_id: BackupId,
    /// Protected or explicitly incomplete result.
    pub outcome: MetadataBackupRunCompletion,
}

/// First provider receipt admitted atomically with one backup generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialBackupCopy {
    /// Configured destination that already accepted the encrypted bytes.
    pub destination_id: BackupDestinationId,
    /// Exact provider generation used for the write.
    pub provider_generation: u64,
    /// Bounded opaque lookup reference returned by the provider.
    pub object_reference: String,
    /// Exact stored encrypted-object length.
    pub byte_length: u64,
    /// Digest of the stored encrypted object.
    pub copy_digest: [u8; 32],
}

/// Exact encrypted partition backup admitted to the replicated catalogue.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    /// Exact still-live worker claim which produced and stored the bytes.
    pub claim: MetadataBackupRunClaim,
    /// Provider receipt which makes this generation recoverable at admission.
    pub initial_copy: InitialBackupCopy,
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
