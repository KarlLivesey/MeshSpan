// SPDX-License-Identifier: GPL-2.0-only

//! Strict SQLite-compatible persistence for authoritative partitions and node-local state.

mod authentication_integrity;
mod command;
mod database;
mod federation_actor_attestation_command;
mod federation_command;
mod federation_grant_command;
mod federation_mutation_admission_command;
mod federation_quarantine_command;
mod federation_remote_authority;
#[cfg(test)]
mod federation_schema_tests;
mod federation_storage_admission;
mod federation_storage_capability_ledger;
mod federation_storage_command;
mod federation_storage_inventory;
mod federation_storage_lifecycle;
mod federation_storage_quota;
mod federation_storage_scrub;
mod federation_succession_command;
mod local_authentication_ceremony;
#[cfg(test)]
mod local_authentication_ceremony_tests;
mod local_claim;
#[cfg(test)]
mod local_claim_tests;
mod local_setup;
#[cfg(test)]
mod local_setup_tests;
mod migration;
mod name;
mod repository;

pub use command::{
    AbortScopeHandoff, ActivateGrant, ActivateGroup, ActivateScopeHandoff, AddGroupMember,
    AppendVersionCleanupItems, AssignComponent, AttachTag, AttestVersionCleanup,
    AuthoriseVersionCleanup, AuthoritativeCommand, BeginScopeHandoff, BootstrapAppliance,
    BootstrapMesh, CancelVersionCleanup, ChangePrincipalState, CommandContext,
    CommitConvergedVolumeHead, CompleteVersionCleanupItem, ConfigureAuthenticationPolicy,
    ConfigureComponent, ConfigureSnapshotSchedule, ConfigureVersionRetention,
    ConfirmVersionCleanupReclamation, ConsumeJoinGrant, ConvergedHeadEvidence,
    CreateActivationPolicy, CreateAuthenticationMethod, CreateComponent, CreateGroup,
    CreateMetadataPartition, CreateObject, CreateScopeRoute, CreateTag, CreateUser, CreateVolume,
    CreateVolumeSnapshot, DetachTag, FreezeScopeHandoff, GrantInheritance, GrantPermission,
    InstallScopeRouteProjection, IssueAuthenticationSession, IssueJoinGrant,
    IssueVersionCleanupPermit, JoinRoles, NamespaceObjectKind, NewAuthenticationCredential,
    NewRecoveryCode, PermissionScope, PrincipalLifecycleState, ProposeVersionCleanup,
    RegisterCleanupAttestationKey, RegisterRoutingSigner, RemoveGroupMember,
    RemoveVolumeSnapshotRoot, ReplaceObjectOwners, RepositoryCommandError,
    RequestVolumeSnapshotExpiry, RestoreVolumeSnapshot, RetentionReclaimMode,
    RevokeAccessActivation, RevokeAuthenticationMethod, RevokeAuthenticationSession,
    RevokePermissionGrant, RouteAttestation, RunSnapshotSchedule, SealVersionCleanupInventory,
    SessionAuthenticationFactor, SessionClientLabel, SetObjectGrantInheritance,
    SnapshotExpiryReason, StepUpAuthenticationSession, TagTarget, TotpAlgorithm,
    VersionCleanupAttestation, VersionCleanupItemPlacement,
};
pub use database::{IntegrityReport, LocalDatabase, PartitionDatabase};
pub use federation_actor_attestation_command::{
    FederatedActorKind, FederatedActorState, RecordFederatedActorAttestation,
};
pub use federation_command::{
    ApproveFederationRelationship, FederationGovernanceDirection, FederationGovernanceEdge,
    FederationGovernanceProof, FederationIdentityOwner, FederationTrustIdentity,
    ProposeFederationRelationship, RecoverFederationRelationship, RestrictFederationRelationship,
    RetireFederationRelationship, RevokeFederationRelationship, RotateFederationTrustIdentity,
};
pub use federation_grant_command::{
    ActivateFederationGrantAssignment, CreateFederationGrantAssignment, FederationGrantRestriction,
    IssueFederationGrant, ReplaceFederationGrant, RevokeFederationGrant,
    RevokeFederationGrantAssignment, RevokeFederationGrantAssignmentActivation,
};
pub use federation_mutation_admission_command::AdmitFederatedMutation;
pub use federation_quarantine_command::{
    FederationQuarantineResolution, ResolveFederatedMutationQuarantine,
    RetainFederatedMutationQuarantine, SurfaceFederatedMutationQuarantine,
};
pub use federation_remote_authority::{
    CachedFederationGrantAuthority, CachedFederationRemoteAuthority,
    FederationRemoteAuthorityCacheDisposition, FederationRemoteAuthorityCacheError,
    FederationRemoteAuthoritySnapshot,
};
pub use federation_storage_admission::FederationStorageAdmissionError;
pub use federation_storage_capability_ledger::{
    FederationStorageCapabilityDisposition, FederationStorageCapabilityLedgerError,
    FederationStorageCapabilityPresentation,
};
pub use federation_storage_command::{
    IssueFederationStorageAllocation, RevokeFederationStorageAllocation,
};
pub use federation_storage_inventory::{
    FederationStorageInventoryCursor, FederationStorageInventoryError,
    FederationStorageInventoryPage, MAXIMUM_FEDERATED_STORAGE_INVENTORY_ITEMS,
};
pub use federation_storage_lifecycle::{
    FederationStorageLifecycle, FederationStorageLifecycleDisposition,
    FederationStorageLifecycleError, FederationStorageLifecycleState,
    FederationStorageReclamationCompletion, FederationStorageRetirementCompletion,
};
pub use federation_storage_quota::{
    FederationStorageQuotaDisposition, FederationStorageQuotaError, FederationStorageUsage,
    FederationStorageWriteAbsence, FederationStorageWriteCompletion,
    FederationStorageWriteReservation, FederationStorageWriteReservationRequest,
    FederationStorageWriteState, MAXIMUM_FEDERATED_STORAGE_WRITE_LIFETIME_MICROS,
};
pub use federation_storage_scrub::{
    FederationStorageScrubCompletion, FederationStorageScrubError, FederationStorageScrubEvidence,
    FederationStorageScrubPreparation,
};
pub use federation_succession_command::{
    AcceptFederationSuccessor, ActivateFederationSuccessor, DesignateFederationSuccessor,
    FederationSuccessionEdge, RevokeFederationSuccessorDesignation,
};
pub use local_authentication_ceremony::{
    AuthenticationCeremonyDisposition, AuthenticationCeremonyError, AuthenticationCeremonyKind,
    AuthenticationCeremonyRecord, AuthenticationCeremonyState,
    MAXIMUM_AUTHENTICATION_CEREMONY_LIFETIME_MICROS, NewAuthenticationCeremony,
    ProtectedAuthenticationState,
};
pub use local_claim::{
    LocalClaimError, LocalClaimMutationDisposition, LocalClaimRecord, LocalClaimState,
    NewLocalClaim,
};
pub use local_setup::{
    LocalSetupDisposition, LocalSetupError, LocalSetupKind, LocalSetupRecord, LocalSetupState,
    NewLocalSetup,
};
pub use migration::MetadataStoreError;
pub use name::{RecordName, RecordNameError};
pub use repository::{
    AccessActivationCursor, AccessActivationRecord, AccessAuthentication, AccessCapability,
    AccessDecision, AccessDenial, AccessRequest, ApiKeyAuthentication, ApiKeySessionReplay,
    ApplyDisposition, AuthenticationMethodCreationReplay, AuthenticationMethodRevocationReplay,
    AuthenticationPolicy, AuthenticationRegistrationProfile, AuthenticationService,
    AuthenticationSessionReplay, AuthenticationSessionReplayCredential,
    AuthenticationSessionReplayFactor, AuthoritativeMembership, AuthoritativeMetadataKernel,
    AuthoritativeRepository, BrowserSessionAccessRequest, BrowserSessionProtection, CommandReceipt,
    ConsensusStoreError, ConvergedVolumeHead, EntityKind, EntityReference,
    FederatedActorAttestationRecord, FederatedMutationAdmissionReceipt,
    FederationAuthoritySnapshotError, FederationGrantAssignmentAuthority, FederationGrantCursor,
    FederationGrantCursorError, FederationGrantRecord, FederationGrantRecordCodecError,
    FederationGrantState, FederationGrantTermination, FederationGrantTerminationKind,
    FederationQuarantineRecord, FederationQuarantineState, FederationRelationshipRecord,
    FederationRelationshipState, FederationStorageAllocationAuthority,
    FederationStorageAllocationRecord, FederationStorageAllocationState,
    FederationStorageAuthorityRequest, FederationSuccessionRecord, FederationSuccessionState,
    FederationTransportAuthority, FederationTrustIdentityRecord, GroupMemberCursor,
    InvariantFinding, InvariantKind, InvariantReport, LogPosition,
    MAXIMUM_VERSION_CLEANUP_PERMIT_LIFETIME, NamespaceCursor, NamespaceRecord, ObjectOwnerCursor,
    ObjectOwnerRecord, Page, PageLimit, PartitionBackupManifest, PartitionConsensusPersistence,
    PartitionSnapshotManifest, PasskeyRegistrationProfile, PasskeyRegistrationReplay,
    PasskeySessionReplay, PasskeyVerificationMaterial, PermissionGrantRecord, PreservedVote,
    PrincipalKind, PrincipalRecord, RecoveryCodeVerificationMaterial, RepositoryConformanceCheck,
    RepositoryConformanceReport, RepositoryConformanceVector, RepositoryError,
    RetainedNamespaceRoot, RetainedNamespaceRootCursor, RetainedNamespaceRootPage,
    RetainedNamespaceRootSource, ScopeWriteAuthority, ScopedGrantCursor, SessionAccessCapability,
    SessionAccessDecision, SessionAccessDenial, SessionAccessRequest, SessionRevocationReplay,
    SnapshotCursor, SnapshotExpiryCandidate, SnapshotExpiryCursor, SnapshotSchedule,
    SnapshotScheduleCursor, SubjectGrantCursor, TotpVerificationMaterial,
    VersionCleanupAttestationProgress, VersionCleanupCompletion, VersionCleanupIntent,
    VersionCleanupInventory, VersionCleanupInventoryState, VersionCleanupItem,
    VersionCleanupItemCompletion, VersionCleanupItemCursor, VersionCleanupItemReclamation,
    VersionCleanupParticipant, VersionCleanupPermitAttempt, VersionCleanupPermitAuthority,
    VersionCleanupReclamation, VersionCleanupState, VersionRetentionPolicy, VolumeSnapshot,
    restore_partition_backup, restore_partition_snapshot, run_repository_conformance,
};
