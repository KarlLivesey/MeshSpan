// SPDX-License-Identifier: GPL-2.0-only

//! Strict SQLite-compatible persistence for authoritative partitions and node-local state.

mod command;
mod database;
mod federation_command;
mod federation_grant_command;
mod federation_principal_command;
mod federation_quarantine_command;
mod federation_remote_authority;
#[cfg(test)]
mod federation_schema_tests;
mod federation_storage_command;
mod federation_storage_quota;
mod federation_succession_command;
mod migration;
mod name;
mod repository;

pub use command::{
    AbortScopeHandoff, ActivateGrant, ActivateGroup, ActivateScopeHandoff, AddGroupMember,
    AppendVersionCleanupItems, AssignComponent, AttachTag, AttestVersionCleanup,
    AuthoriseVersionCleanup, AuthoritativeCommand, BeginScopeHandoff, BootstrapMesh,
    CancelVersionCleanup, ChangePrincipalState, CommandContext, CommitConvergedVolumeHead,
    CompleteVersionCleanupItem, ConfigureComponent, ConfigureSnapshotSchedule,
    ConfigureVersionRetention, ConfirmVersionCleanupReclamation, ConsumeJoinGrant,
    ConvergedHeadEvidence, CreateActivationPolicy, CreateComponent, CreateGroup,
    CreateMetadataPartition, CreateObject, CreateScopeRoute, CreateTag, CreateUser, CreateVolume,
    CreateVolumeSnapshot, DetachTag, FreezeScopeHandoff, GrantInheritance, GrantPermission,
    InstallScopeRouteProjection, IssueAuthenticationSession, IssueJoinGrant,
    IssueVersionCleanupPermit, JoinRoles, NamespaceObjectKind, PermissionScope,
    PrincipalLifecycleState, ProposeVersionCleanup, RegisterCleanupAttestationKey,
    RegisterRoutingSigner, RemoveGroupMember, RemoveVolumeSnapshotRoot, ReplaceObjectOwners,
    RepositoryCommandError, RequestVolumeSnapshotExpiry, RestoreVolumeSnapshot,
    RetentionReclaimMode, RevokeAccessActivation, RevokeAuthenticationSession,
    RevokePermissionGrant, RouteAttestation, RunSnapshotSchedule, SealVersionCleanupInventory,
    SetObjectGrantInheritance, SnapshotExpiryReason, TagTarget, VersionCleanupAttestation,
    VersionCleanupItemPlacement,
};
pub use database::{IntegrityReport, LocalDatabase, PartitionDatabase};
pub use federation_command::{
    ApproveFederationRelationship, FederationGovernanceDirection, FederationGovernanceEdge,
    FederationGovernanceProof, FederationIdentityOwner, FederationTrustIdentity,
    ProposeFederationRelationship, RecoverFederationRelationship, RestrictFederationRelationship,
    RetireFederationRelationship, RevokeFederationRelationship, RotateFederationTrustIdentity,
};
pub use federation_grant_command::{
    FederationGrantRestriction, IssueFederationGrant, ReplaceFederationGrant, RevokeFederationGrant,
};
pub use federation_principal_command::{
    FederatedPrincipalKind, FederatedPrincipalState, UpsertFederatedPrincipalProjection,
};
pub use federation_quarantine_command::{
    FederationQuarantineResolution, ResolveFederatedMutationQuarantine,
    RetainFederatedMutationQuarantine, SurfaceFederatedMutationQuarantine,
};
pub use federation_remote_authority::{
    CachedFederationGrantAuthority, CachedFederationRemoteAuthority,
    FederationRemoteAuthorityCacheDisposition, FederationRemoteAuthorityCacheError,
    FederationRemoteAuthoritySnapshot,
};
pub use federation_storage_command::{
    IssueFederationStorageAllocation, RevokeFederationStorageAllocation,
};
pub use federation_storage_quota::{
    FederationStorageQuotaDisposition, FederationStorageQuotaError, FederationStorageUsage,
    FederationStorageWriteAbsence, FederationStorageWriteCompletion,
    FederationStorageWriteReservation, FederationStorageWriteReservationRequest,
    FederationStorageWriteState, MAXIMUM_FEDERATED_STORAGE_WRITE_LIFETIME_MICROS,
};
pub use federation_succession_command::{
    AcceptFederationSuccessor, ActivateFederationSuccessor, DesignateFederationSuccessor,
    FederationSuccessionEdge, RevokeFederationSuccessorDesignation,
};
pub use migration::MetadataStoreError;
pub use name::{RecordName, RecordNameError};
pub use repository::{
    AccessActivationCursor, AccessActivationRecord, AccessCapability, AccessDecision, AccessDenial,
    AccessRequest, ApplyDisposition, AuthoritativeMembership, AuthoritativeMetadataKernel,
    AuthoritativeRepository, CommandReceipt, ConsensusStoreError, ConvergedVolumeHead, EntityKind,
    EntityReference, FederatedPrincipalProjectionRecord, FederationAuthoritySnapshotError,
    FederationGrantCursor, FederationGrantCursorError, FederationGrantRecord,
    FederationGrantRecordCodecError, FederationGrantState, FederationGrantTermination,
    FederationGrantTerminationKind, FederationQuarantineRecord, FederationQuarantineState,
    FederationRelationshipRecord, FederationRelationshipState,
    FederationStorageAllocationAuthority, FederationStorageAllocationRecord,
    FederationStorageAllocationState, FederationStorageAuthorityRequest,
    FederationSuccessionRecord, FederationSuccessionState, FederationTransportAuthority,
    FederationTrustIdentityRecord, GroupMemberCursor, InvariantFinding, InvariantKind,
    InvariantReport, LogPosition, MAXIMUM_VERSION_CLEANUP_PERMIT_LIFETIME, NamespaceCursor,
    NamespaceRecord, ObjectOwnerCursor, ObjectOwnerRecord, Page, PageLimit,
    PartitionBackupManifest, PartitionConsensusPersistence, PartitionSnapshotManifest,
    PermissionGrantRecord, PreservedVote, PrincipalKind, PrincipalRecord,
    RepositoryConformanceCheck, RepositoryConformanceReport, RepositoryConformanceVector,
    RepositoryError, RetainedNamespaceRoot, RetainedNamespaceRootCursor, RetainedNamespaceRootPage,
    RetainedNamespaceRootSource, ScopeWriteAuthority, ScopedGrantCursor, SessionAccessCapability,
    SessionAccessDecision, SessionAccessDenial, SessionAccessRequest, SnapshotCursor,
    SnapshotExpiryCandidate, SnapshotExpiryCursor, SnapshotSchedule, SnapshotScheduleCursor,
    SubjectGrantCursor, VersionCleanupAttestationProgress, VersionCleanupCompletion,
    VersionCleanupIntent, VersionCleanupInventory, VersionCleanupInventoryState,
    VersionCleanupItem, VersionCleanupItemCompletion, VersionCleanupItemCursor,
    VersionCleanupItemReclamation, VersionCleanupParticipant, VersionCleanupPermitAttempt,
    VersionCleanupPermitAuthority, VersionCleanupReclamation, VersionCleanupState,
    VersionRetentionPolicy, VolumeSnapshot, restore_partition_backup, restore_partition_snapshot,
    run_repository_conformance,
};
