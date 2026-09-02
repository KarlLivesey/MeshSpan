// SPDX-License-Identifier: GPL-2.0-only

//! Strict SQLite-compatible persistence for authoritative partitions and node-local state.

mod authentication_integrity;
mod command;
mod command_codec;
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
mod local_target;
#[cfg(test)]
mod local_target_tests;
mod migration;
mod name;
mod repository;
#[cfg(test)]
mod test_support;

pub use command::{
    AUTHENTICATION_ROOT_KEY_SECRET_KIND, AbortScopeHandoff, ActivateGrant, ActivateGroup,
    ActivateNode, ActivateScopeHandoff, AddGroupMember, AppendVersionCleanupItems, AssignComponent,
    AssignVolumeLocalityPolicy, AssignVolumeProtectionPolicy, AttachTag, AttestVersionCleanup,
    AuthoriseVersionCleanup, AuthoritativeCommand, BeginScopeHandoff, BootstrapAppliance,
    BootstrapMesh, BootstrapNodeCertificate, BootstrapRecoveryIdentity, CancelVersionCleanup,
    ChangePrincipalState, CommandContext, CommitConvergedVolumeHead, CommitSecretGeneration,
    CompleteVersionCleanupItem, ConfigureAuthenticationPolicy, ConfigureComponent,
    ConfigureSnapshotSchedule, ConfigureVersionRetention, ConfirmRecoveryBundleSaved,
    ConfirmVersionCleanupReclamation, ConsumeJoinGrant, ConvergedHeadEvidence,
    CreateActivationPolicy, CreateAuthenticationMethod, CreateAvailabilityCell, CreateComponent,
    CreateFaultGroup, CreateGroup, CreateLocalityPolicy, CreateMetadataPartition, CreateObject,
    CreateProtectionPolicy, CreateScopeRoute, CreateTag, CreateUser, CreateVolume,
    CreateVolumeSnapshot, DetachTag, FreezeScopeHandoff, GrantInheritance, GrantPermission,
    GrantPermissionWithActivation, InstallScopeRouteProjection, IssueAuthenticationSession,
    IssueJoinGrant, IssueVersionCleanupPermit, JoinRoles, LocalityRequirementConfiguration,
    NamespaceObjectKind, NewAuthenticationCredential, NewRecoveryCode,
    ONLINE_AUTHORITY_KEY_SECRET_KIND, PermissionScope, PrincipalLifecycleState,
    ProposeVersionCleanup, ProtectionScenarioConfiguration, PublishSmbExport,
    RegisterCleanupAttestationKey, RegisterNodeWrappingKey, RegisterRoutingSigner,
    RegisterStorageTarget, RemoveGroupMember, RemoveVolumeSnapshotRoot, ReplaceObjectOwners,
    RepositoryCommandError, RequestVolumeSnapshotExpiry, RestoreVolumeSnapshot,
    RetentionReclaimMode, RevokeAccessActivation, RevokeAuthenticationMethod,
    RevokeAuthenticationSession, RevokePermissionGrant, RouteAttestation, RunSnapshotSchedule,
    STORAGE_PERMIT_KEY_SECRET_KIND, SealVersionCleanupInventory, SessionAuthenticationFactor,
    SessionClientLabel, SetHostAvailabilityCellMembership, SetHostFaultGroupMembership,
    SetObjectGrantInheritance, SetTargetAvailabilityCellMembership, SmbExportGatewaySelection,
    SnapshotExpiryReason, StepUpAuthenticationSession, StorageUsageLimit, TagTarget, TotpAlgorithm,
    VOLUME_CONTENT_KEY_SECRET_KIND, VersionCleanupAttestation, VersionCleanupItemPlacement,
    WithdrawSmbExport,
};
pub use command_codec::{
    DecodedAuthoritativeCommand, METADATA_COMMAND_VERSION, MetadataCommandCodecError,
    decode_authoritative_command, encode_authoritative_command,
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
pub use local_target::{
    LocalTargetDisposition, LocalTargetError, LocalTargetRecord, LocalTargetState, NewLocalTarget,
};
pub use migration::MetadataStoreError;
pub use name::{RecordName, RecordNameError};
pub use repository::{
    AccessActivationCursor, AccessActivationRecord, AccessAuthentication, AccessCapability,
    AccessDecision, AccessDenial, AccessRequest, ActiveNodeCertificate, ApiKeyAuthentication,
    ApiKeySessionReplay, ApplyDisposition, AuthenticationMethodCreationReplay,
    AuthenticationMethodCursor, AuthenticationMethodRecord, AuthenticationMethodRecordDetails,
    AuthenticationMethodRevocationReplay, AuthenticationPolicy, AuthenticationRegistrationProfile,
    AuthenticationService, AuthenticationSessionReplay, AuthenticationSessionReplayCredential,
    AuthenticationSessionReplayFactor, AuthoritativeMembership, AuthoritativeMetadataKernel,
    AuthoritativeOperationCursor, AuthoritativeOperationState, AuthoritativeOperationStatus,
    AuthoritativeRepository, AvailabilityCellCursor, AvailabilityCellRecord,
    BrowserSessionAccessRequest, BrowserSessionProtection, CommandReceipt, ConsensusStoreError,
    ConvergedVolumeHead, EntityKind, EntityReference, FaultGroupCursor, FaultGroupMembershipCursor,
    FaultGroupMembershipRecord, FaultGroupRecord, FederatedActorAttestationRecord,
    FederatedMutationAdmissionReceipt, FederationAuthoritySnapshotError,
    FederationGrantAssignmentAuthority, FederationGrantCursor, FederationGrantCursorError,
    FederationGrantRecord, FederationGrantRecordCodecError, FederationGrantState,
    FederationGrantTermination, FederationGrantTerminationKind, FederationQuarantineRecord,
    FederationQuarantineState, FederationRelationshipRecord, FederationRelationshipState,
    FederationStorageAllocationAuthority, FederationStorageAllocationRecord,
    FederationStorageAllocationState, FederationStorageAuthorityRequest,
    FederationSuccessionRecord, FederationSuccessionState, FederationTransportAuthority,
    FederationTrustIdentityRecord, GroupMemberCursor, GroupMembershipEventKind,
    GroupMembershipEventRecord, GroupMembershipRecord, InvariantFinding, InvariantKind,
    InvariantReport, JoinGrantRecord, LocalityPolicyCursor, LocalityPolicyRecord,
    LocalityRequirementRecord, LogPosition, MAXIMUM_VERSION_CLEANUP_PERMIT_LIFETIME,
    MeshRecoveryAuthority, NamespaceCursor, NamespaceRecord, NodeActivationCandidate,
    NodeActivationRecord, NodeEnrolmentRecord, NodeWrappingKeyRecord, ObjectOwnerCursor,
    ObjectOwnerRecord, OnlineCertificateAuthorityRecord, Page, PageLimit, PartitionBackupManifest,
    PartitionConsensusPersistence, PartitionSnapshotManifest, PasskeyRegistrationProfile,
    PasskeyRegistrationReplay, PasskeySessionReplay, PasskeyVerificationMaterial,
    PermissionGrantRecord, PermissionGrantRevocationRecord, PreservedVote, PrincipalCursor,
    PrincipalKind, PrincipalRecord, ProtectionPolicyCursor, ProtectionPolicyRecord,
    ProtectionScenarioRecord, ProtectionTermRecord, RecoveryBundleState,
    RecoveryCodeVerificationMaterial, RepositoryConformanceCheck, RepositoryConformanceReport,
    RepositoryConformanceVector, RepositoryError, RetainedNamespaceRoot,
    RetainedNamespaceRootCursor, RetainedNamespaceRootPage, RetainedNamespaceRootSource,
    ScopeWriteAuthority, ScopedGrantCursor, SecretGenerationRecord, SessionAccessCapability,
    SessionAccessDecision, SessionAccessDenial, SessionAccessRequest, SessionRevocationReplay,
    SmbExportGatewayPolicy, SmbExportRecord, SmbVerificationMaterial, SnapshotCursor,
    SnapshotExpiryCandidate, SnapshotExpiryCursor, SnapshotSchedule, SnapshotScheduleCursor,
    StorageTargetProviderContext, StorageTargetRegistrationContext, SubjectGrantCursor,
    TopologyNodeCursor, TopologyNodeRecord, TopologyTargetCursor, TopologyTargetRecord,
    TotpVerificationMaterial, VersionCleanupAttestationProgress, VersionCleanupCompletion,
    VersionCleanupIntent, VersionCleanupInventory, VersionCleanupInventoryState,
    VersionCleanupItem, VersionCleanupItemCompletion, VersionCleanupItemCursor,
    VersionCleanupItemReclamation, VersionCleanupParticipant, VersionCleanupPermitAttempt,
    VersionCleanupPermitAuthority, VersionCleanupReclamation, VersionCleanupState,
    VersionRetentionPolicy, VolumeInventoryCursor, VolumeInventoryRecord, VolumeLocalityPolicy,
    VolumeProtectionPolicy, VolumeSnapshot, restore_partition_backup, restore_partition_snapshot,
    run_repository_conformance,
};
