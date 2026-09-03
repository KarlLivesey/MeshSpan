// SPDX-License-Identifier: GPL-2.0-only

//! Strict SQLite-compatible persistence for authoritative partitions and node-local state.

mod acme_command;
mod authentication_integrity;
mod backup_command;
mod command;
mod command_codec;
mod database;
mod external_certificate_command;
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
mod local_scrub_progress;
mod local_setup;
#[cfg(test)]
mod local_setup_tests;
mod local_target;
#[cfg(test)]
mod local_target_tests;
mod mesh_local_certificate_command;
mod migration;
mod name;
mod repository;
#[cfg(test)]
mod test_support;

pub use acme_command::{
    AcknowledgePublicCertificateInstallation, AcmeChallengeKind, AdvanceManualDnsTask,
    CertificateOrderCompletion, CheckpointCertificateOrder, ClaimCertificateOrder,
    CompleteCertificateOrder, ConfigureAcme, MAXIMUM_CERTIFICATE_ORDER_CHECKPOINT_BYTES,
    MAXIMUM_MANUAL_DNS_VALUE_BYTES, ManualDnsTaskPhase, ProvisionAcme, QueueCertificateOrder,
    RenewCertificateOrder, SecretGenerationReference,
};
pub use backup_command::{
    BackupDestinationBinding, BackupFailureRelationship, ClaimMetadataBackupRun,
    CompleteMetadataBackupRun, ConfigureBackupDestination, ConfigureMetadataBackupSchedule,
    InitialBackupCopy, MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES, MetadataBackupRunClaim,
    MetadataBackupRunCompletion, QueueMetadataBackupRun, RecordBackupCopy, RecordMetadataBackup,
    RenewMetadataBackupRun, VerifyBackupCopy,
};
pub use command::{
    ACME_ACCOUNT_KEY_SECRET_KIND, ACME_CHALLENGE_SETTINGS_SECRET_KIND,
    AUTHENTICATION_ROOT_KEY_SECRET_KIND, AbortScopeHandoff, AcknowledgementCellRequirement,
    AcknowledgementCellRole, AcknowledgementConsistencyClass, ActivateGrant, ActivateGroup,
    ActivateNode, ActivateScopeHandoff, AddGroupMember, AppendVersionCleanupItems, AssignComponent,
    AssignVolumeAcknowledgementPolicy, AssignVolumeLocalityPolicy, AssignVolumeProtectionPolicy,
    AttachTag, AttestStorageTargetDrain, AttestVersionCleanup, AuthoriseVersionCleanup,
    AuthoritativeCommand, BeginScopeHandoff, BeginStorageScopeDrain, BeginStorageTargetDrain,
    BootstrapAppliance, BootstrapMesh, BootstrapNodeCertificate, BootstrapRecoveryIdentity,
    CancelVersionCleanup, ChangePrincipalState, ClaimMaintenanceWork, CommandContext,
    CommitConvergedVolumeHead, CommitRebalanceScanPage, CommitScrubPass, CommitSecretGeneration,
    CommitShardRepair, CommitTargetReconciliation, CompleteMaintenanceWork,
    CompleteStorageScopeDrain, CompleteVersionCleanupItem, ConfigureAuthenticationPolicy,
    ConfigureComponent, ConfigureSnapshotSchedule, ConfigureVersionRetention,
    ConfirmRecoveryBundleSaved, ConfirmVersionCleanupReclamation, ConsumeJoinGrant,
    ConvergedHeadEvidence, CreateAcknowledgementPolicy, CreateActivationPolicy,
    CreateAuthenticationMethod, CreateAvailabilityCell, CreateComponent, CreateFaultGroup,
    CreateGroup, CreateLocalityPolicy, CreateMetadataPartition, CreateObject,
    CreateProtectionPolicy, CreateScopeRoute, CreateTag, CreateUser, CreateVolume,
    CreateVolumeSnapshot, DetachTag, FenceStorageNodeDrainMembership, FreezeScopeHandoff,
    GrantInheritance, GrantPermission, GrantPermissionWithActivation, InstallScopeRouteProjection,
    IssueAuthenticationSession, IssueJoinGrant, IssueVersionCleanupPermit, JoinRoles,
    LocalityRequirementConfiguration, MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND,
    MaintenanceWorkCompletion, NamespaceObjectKind, NewAuthenticationCredential, NewRecoveryCode,
    ONLINE_AUTHORITY_KEY_SECRET_KIND, PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
    PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND, PermissionScope, PrincipalLifecycleState,
    ProposeVersionCleanup, ProtectionScenarioConfiguration, PublishSmbExport, QueueMaintenanceWork,
    RebalanceScanCursor, RegisterCleanupAttestationKey, RegisterNodeWrappingKey,
    RegisterRoutingSigner, RegisterStorageTarget, RemoveGroupMember, RemoveVolumeSnapshotRoot,
    RenewMaintenanceWork, ReplaceObjectOwners, RepositoryCommandError, RequestVolumeSnapshotExpiry,
    RestoreVolumeSnapshot, RetentionReclaimMode, RevokeAccessActivation,
    RevokeAuthenticationMethod, RevokeAuthenticationSession, RevokePermissionGrant,
    RouteAttestation, RunSnapshotSchedule, STORAGE_PERMIT_KEY_SECRET_KIND,
    SealVersionCleanupInventory, SessionAuthenticationFactor, SessionClientLabel,
    SetHostAvailabilityCellMembership, SetHostFaultGroupMembership, SetObjectGrantInheritance,
    SetTargetAvailabilityCellMembership, SmbExportGatewaySelection, SnapshotExpiryReason,
    StepUpAuthenticationSession, StorageUsageLimit, StrongFallbackMode, TagTarget, TotpAlgorithm,
    VOLUME_CONTENT_KEY_SECRET_KIND, VersionCleanupAttestation, VersionCleanupItemPlacement,
    WithdrawSmbExport,
};
pub use command_codec::{
    DecodedAuthoritativeCommand, METADATA_COMMAND_VERSION, MetadataCommandCodecError,
    decode_authoritative_command, encode_authoritative_command,
};
pub use database::{IntegrityReport, LocalDatabase, PartitionDatabase};
pub use external_certificate_command::{
    AcknowledgeExternalCertificateInstallation, MAXIMUM_EXTERNAL_CERTIFICATE_NAMES,
    PublishExternalCertificate,
};
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
pub use local_scrub_progress::{
    LocalScrubProgress, LocalScrubProgressError, LocalScrubProgressUpdate,
};
pub use local_setup::{
    LocalSetupDisposition, LocalSetupError, LocalSetupKind, LocalSetupRecord, LocalSetupState,
    NewLocalSetup,
};
pub use local_target::{
    LocalTargetDisposition, LocalTargetError, LocalTargetRecord, LocalTargetState, NewLocalTarget,
};
pub use mesh_local_certificate_command::{
    AcknowledgeMeshLocalCertificateInstallation, CreateMeshLocalCertificateAuthority,
    IssueMeshLocalCertificate, MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES,
    MAXIMUM_MESH_LOCAL_CERTIFICATE_NAMES,
};
pub use migration::MetadataStoreError;
pub use name::{RecordName, RecordNameError};
pub use repository::{
    AccessActivationCursor, AccessActivationRecord, AccessAuthentication, AccessCapability,
    AccessDecision, AccessDenial, AccessRequest, AcknowledgementPolicyCursor,
    AcknowledgementPolicyRecord, AcmeConfigurationRecord, ActiveNodeCertificate,
    ApiKeyAuthentication, ApiKeySessionReplay, ApplyDisposition,
    AuthenticationMethodCreationReplay, AuthenticationMethodCursor, AuthenticationMethodRecord,
    AuthenticationMethodRecordDetails, AuthenticationMethodRevocationReplay, AuthenticationPolicy,
    AuthenticationRegistrationProfile, AuthenticationService, AuthenticationSessionReplay,
    AuthenticationSessionReplayCredential, AuthenticationSessionReplayFactor,
    AuthoritativeMembership, AuthoritativeMetadataKernel, AuthoritativeOperationCursor,
    AuthoritativeOperationState, AuthoritativeOperationStatus, AuthoritativeRepository,
    AvailabilityCellCursor, AvailabilityCellRecord, BackupCopyRecord, BackupCopyState,
    BackupDestinationRecord, BackupDestinationState, BrowserSessionAccessRequest,
    BrowserSessionProtection, CertificateOrderCheckpointRecord, CertificateOrderClaim,
    CertificateOrderRecord, CertificateOrderState, CertificateRenewalCandidate, CommandReceipt,
    ConsensusStoreError, ConvergedVolumeHead, DueCertificateOrderCursor,
    DueCertificateRenewalCursor, DueStorageScrub, DueStorageScrubCursor, DueStorageScrubPage,
    EncryptedBackupPaths, EncryptedPartitionBackupManifest, EncryptedRestorePaths, EntityKind,
    EntityReference, ExternalCertificateInstallationRecord, ExternalCertificatePublicationRecord,
    FaultGroupCursor, FaultGroupMembershipCursor, FaultGroupMembershipRecord, FaultGroupRecord,
    FederatedActorAttestationRecord, FederatedMutationAdmissionReceipt,
    FederationAuthoritySnapshotError, FederationGrantAssignmentAuthority, FederationGrantCursor,
    FederationGrantCursorError, FederationGrantRecord, FederationGrantRecordCodecError,
    FederationGrantState, FederationGrantTermination, FederationGrantTerminationKind,
    FederationQuarantineRecord, FederationQuarantineState, FederationRelationshipRecord,
    FederationRelationshipState, FederationStorageAllocationAuthority,
    FederationStorageAllocationRecord, FederationStorageAllocationState,
    FederationStorageAuthorityRequest, FederationSuccessionRecord, FederationSuccessionState,
    FederationTransportAuthority, FederationTrustIdentityRecord, GroupMemberCursor,
    GroupMembershipEventKind, GroupMembershipEventRecord, GroupMembershipRecord, InvariantFinding,
    InvariantKind, InvariantReport, JoinGrantRecord, LocalityPolicyCursor, LocalityPolicyRecord,
    LocalityRequirementRecord, LogPosition, MAXIMUM_VERSION_CLEANUP_PERMIT_LIFETIME,
    MaintenanceEffectReference, MaintenanceWorkClaim, MaintenanceWorkCursor, MaintenanceWorkRecord,
    MaintenanceWorkState, ManualDnsTaskCursor, ManualDnsTaskRecord, ManualDnsTaskState,
    MeshLocalCertificateAuthorityRecord, MeshLocalCertificateIssuanceRecord, MeshRecoveryAuthority,
    MetadataBackupRecord, MetadataBackupRun, MetadataBackupRunClaimRecord, MetadataBackupRunState,
    MetadataBackupSchedule, MetadataBackupState, NamespaceCursor, NamespaceRecord,
    NodeActivationCandidate, NodeActivationRecord, NodeEnrolmentRecord, NodeWrappingKeyRecord,
    ObjectOwnerCursor, ObjectOwnerRecord, OnlineCertificateAuthorityRecord, Page, PageLimit,
    PartitionBackupManifest, PartitionConsensusPersistence, PartitionSnapshotManifest,
    PasskeyRegistrationProfile, PasskeyRegistrationReplay, PasskeySessionReplay,
    PasskeyVerificationMaterial, PermissionGrantRecord, PermissionGrantRevocationRecord,
    PreservedVote, PrincipalCursor, PrincipalKind, PrincipalRecord, ProtectionPolicyCursor,
    ProtectionPolicyRecord, ProtectionScenarioRecord, ProtectionTermRecord,
    PublicCertificateInstallationRecord, PublicCertificateRolloutSummary,
    PublicCertificateSelection, PublicCertificateSource, PublicCertificateStatusRecord,
    ReadyMaintenanceWork, ReadyMaintenanceWorkPage, RebalanceScanProgress, RecoveryBundleState,
    RecoveryCodeVerificationMaterial, RepositoryConformanceCheck, RepositoryConformanceReport,
    RepositoryConformanceVector, RepositoryError, RetainedNamespaceRoot,
    RetainedNamespaceRootCursor, RetainedNamespaceRootPage, RetainedNamespaceRootSource,
    ScopeWriteAuthority, ScopedGrantCursor, SecretGenerationRecord, SessionAccessCapability,
    SessionAccessDecision, SessionAccessDenial, SessionAccessRequest, SessionRevocationReplay,
    ShardRepairEffectRecord, SmbExportGatewayPolicy, SmbExportRecord, SmbVerificationMaterial,
    SnapshotCursor, SnapshotExpiryCandidate, SnapshotExpiryCursor, SnapshotSchedule,
    SnapshotScheduleCursor, StorageDrainCursor, StorageDrainRecord, StorageDrainState,
    StorageDrainStatusPage, StorageScopeDrainAction, StorageScopeDrainCursor,
    StorageScopeDrainRecord, StorageScopeDrainState, StorageTargetProviderContext,
    StorageTargetRegistrationContext, SubjectGrantCursor, TopologyNodeCursor, TopologyNodeRecord,
    TopologyTargetCursor, TopologyTargetRecord, TotpVerificationMaterial,
    VersionCleanupAttestationProgress, VersionCleanupCompletion, VersionCleanupIntent,
    VersionCleanupInventory, VersionCleanupInventoryState, VersionCleanupItem,
    VersionCleanupItemCompletion, VersionCleanupItemCursor, VersionCleanupItemReclamation,
    VersionCleanupParticipant, VersionCleanupPermitAttempt, VersionCleanupPermitAuthority,
    VersionCleanupReclamation, VersionCleanupState, VersionRetentionPolicy,
    VolumeAcknowledgementPolicy, VolumeInventoryCursor, VolumeInventoryRecord,
    VolumeLocalityPolicy, VolumeProtectionPolicy, VolumeSnapshot,
    create_encrypted_partition_backup, empty_target_drain_catalogue_digest,
    restore_encrypted_partition_backup, restore_partition_backup, restore_partition_snapshot,
    run_repository_conformance,
};
