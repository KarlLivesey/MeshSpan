// SPDX-License-Identifier: GPL-2.0-only

//! Strict SQLite-compatible persistence for authoritative partitions and node-local state.

mod command;
mod database;
mod migration;
mod name;
mod repository;

pub use command::{
    AbortScopeHandoff, ActivateGrant, ActivateGroup, ActivateScopeHandoff, AddGroupMember,
    AppendVersionCleanupItems, AssignComponent, AttachTag, AttestVersionCleanup,
    AuthoriseVersionCleanup, AuthoritativeCommand, BeginScopeHandoff, BootstrapMesh,
    CancelVersionCleanup, CommandContext, CommitConvergedVolumeHead, CompleteVersionCleanupItem,
    ConfigureComponent, ConfigureSnapshotSchedule, ConfigureVersionRetention,
    ConfirmVersionCleanupReclamation, ConsumeJoinGrant, ConvergedHeadEvidence,
    CreateActivationPolicy, CreateComponent, CreateGroup, CreateMetadataPartition, CreateObject,
    CreateScopeRoute, CreateTag, CreateUser, CreateVolume, CreateVolumeSnapshot, DetachTag,
    FreezeScopeHandoff, GrantInheritance, GrantPermission, IssueAuthenticationSession,
    IssueJoinGrant, IssueVersionCleanupPermit, JoinRoles, NamespaceObjectKind, PermissionScope,
    ProposeVersionCleanup, RegisterCleanupAttestationKey, RegisterRoutingSigner,
    RemoveVolumeSnapshotRoot, ReplaceObjectOwners, RepositoryCommandError,
    RequestVolumeSnapshotExpiry, RestoreVolumeSnapshot, RetentionReclaimMode,
    RevokeAuthenticationSession, RouteAttestation, RunSnapshotSchedule,
    SealVersionCleanupInventory, SnapshotExpiryReason, TagTarget, VersionCleanupAttestation,
    VersionCleanupItemPlacement,
};
pub use database::{IntegrityReport, LocalDatabase, PartitionDatabase};
pub use migration::MetadataStoreError;
pub use name::{RecordName, RecordNameError};
pub use repository::{
    AccessCapability, AccessDecision, AccessDenial, AccessRequest, ApplyDisposition,
    AuthoritativeMembership, AuthoritativeMetadataKernel, AuthoritativeRepository, CommandReceipt,
    ConsensusStoreError, ConvergedVolumeHead, EntityKind, EntityReference, GroupMemberCursor,
    InvariantFinding, InvariantKind, InvariantReport, LogPosition,
    MAXIMUM_VERSION_CLEANUP_PERMIT_LIFETIME, NamespaceCursor, NamespaceRecord, Page, PageLimit,
    PartitionBackupManifest, PartitionConsensusPersistence, PartitionSnapshotManifest,
    PreservedVote, PrincipalKind, PrincipalRecord, RepositoryConformanceCheck,
    RepositoryConformanceReport, RepositoryConformanceVector, RepositoryError,
    RetainedNamespaceRoot, RetainedNamespaceRootCursor, RetainedNamespaceRootPage,
    RetainedNamespaceRootSource, ScopeWriteAuthority, SnapshotCursor, SnapshotExpiryCandidate,
    SnapshotExpiryCursor, SnapshotSchedule, SnapshotScheduleCursor,
    VersionCleanupAttestationProgress, VersionCleanupCompletion, VersionCleanupIntent,
    VersionCleanupInventory, VersionCleanupInventoryState, VersionCleanupItem,
    VersionCleanupItemCompletion, VersionCleanupItemCursor, VersionCleanupItemReclamation,
    VersionCleanupParticipant, VersionCleanupPermitAttempt, VersionCleanupPermitAuthority,
    VersionCleanupReclamation, VersionCleanupState, VersionRetentionPolicy, VolumeSnapshot,
    restore_partition_backup, restore_partition_snapshot, run_repository_conformance,
};
