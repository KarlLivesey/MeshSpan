// SPDX-License-Identifier: GPL-2.0-only

//! Strict SQLite-compatible persistence for authoritative partitions and node-local state.

mod command;
mod database;
mod migration;
mod name;
mod repository;

pub use command::{
    AbortScopeHandoff, ActivateGrant, ActivateGroup, ActivateScopeHandoff, AddGroupMember,
    AssignComponent, AttachTag, AuthoritativeCommand, BeginScopeHandoff, BootstrapMesh,
    CommandContext, CommitConvergedVolumeHead, ConfigureComponent, ConfigureSnapshotSchedule,
    ConfigureVersionRetention, ConsumeJoinGrant, ConvergedHeadEvidence, CreateActivationPolicy,
    CreateComponent, CreateGroup, CreateMetadataPartition, CreateObject, CreateScopeRoute,
    CreateTag, CreateUser, CreateVolume, CreateVolumeSnapshot, DetachTag, FreezeScopeHandoff,
    GrantInheritance, GrantPermission, IssueJoinGrant, JoinRoles, NamespaceObjectKind,
    PermissionScope, ProposeVersionCleanup, RegisterRoutingSigner, RemoveVolumeSnapshotRoot,
    ReplaceObjectOwners, RepositoryCommandError, RequestVolumeSnapshotExpiry,
    RestoreVolumeSnapshot, RetentionReclaimMode, RouteAttestation, RunSnapshotSchedule,
    SnapshotExpiryReason, TagTarget,
};
pub use database::{IntegrityReport, LocalDatabase, PartitionDatabase};
pub use migration::MetadataStoreError;
pub use name::{RecordName, RecordNameError};
pub use repository::{
    ApplyDisposition, AuthoritativeMembership, AuthoritativeMetadataKernel,
    AuthoritativeRepository, CommandReceipt, ConsensusStoreError, ConvergedVolumeHead, EntityKind,
    EntityReference, GroupMemberCursor, InvariantFinding, InvariantKind, InvariantReport,
    LogPosition, NamespaceCursor, NamespaceRecord, Page, PageLimit, PartitionBackupManifest,
    PartitionConsensusPersistence, PartitionSnapshotManifest, PreservedVote, PrincipalKind,
    PrincipalRecord, RepositoryConformanceCheck, RepositoryConformanceReport,
    RepositoryConformanceVector, RepositoryError, RetainedNamespaceRoot,
    RetainedNamespaceRootCursor, RetainedNamespaceRootPage, RetainedNamespaceRootSource,
    ScopeWriteAuthority, SnapshotCursor, SnapshotExpiryCandidate, SnapshotExpiryCursor,
    SnapshotSchedule, SnapshotScheduleCursor, VersionCleanupIntent, VersionRetentionPolicy,
    VolumeSnapshot, restore_partition_backup, restore_partition_snapshot,
    run_repository_conformance,
};
