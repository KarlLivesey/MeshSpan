// SPDX-License-Identifier: GPL-2.0-only

//! Daemon process composition, configuration and local secret presentation.

mod api_http;
mod api_key_issuance;
mod api_key_issuance_api;
#[cfg(test)]
mod api_key_issuance_api_tests;
mod api_key_issuance_contract;
mod api_key_issuance_model;
#[cfg(test)]
mod api_key_issuance_tests;
mod appliance_api;
#[cfg(test)]
mod appliance_api_tests;
mod appliance_runtime;
mod auth_api;
#[cfg(test)]
mod auth_api_tests;
mod authentication_method_listing;
#[cfg(test)]
mod authentication_method_listing_api_tests;
#[cfg(test)]
mod authentication_method_listing_service_tests;
mod authentication_method_revocation;
mod authentication_method_revocation_api;
#[cfg(test)]
mod authentication_method_revocation_api_tests;
mod authentication_method_revocation_contract;
mod authentication_method_revocation_model;
#[cfg(test)]
mod authentication_method_revocation_tests;
mod authentication_root_loading;
#[cfg(test)]
mod authentication_root_loading_tests;
mod authoritative_txt_observer;
mod backup_publication;
#[cfg(test)]
mod backup_publication_tests;
mod backup_restore_readiness;
#[cfg(test)]
mod backup_restore_readiness_tests;
mod browser_authentication;
mod browser_session;
mod certificate_administration;
mod certificate_administration_api;
#[cfg(test)]
mod certificate_administration_api_tests;
#[cfg(test)]
mod certificate_administration_tests;
mod certificate_automation_service;
mod certificate_order_checkpointing;
#[cfg(test)]
mod certificate_order_checkpointing_tests;
mod certificate_order_completion;
#[cfg(test)]
mod certificate_order_completion_tests;
mod certificate_order_driver;
#[cfg(test)]
mod certificate_order_driver_tests;
mod certificate_order_execution;
#[cfg(test)]
mod certificate_order_execution_tests;
mod certificate_order_preparation;
#[cfg(test)]
mod certificate_order_preparation_tests;
mod certificate_order_result;
#[cfg(test)]
mod certificate_order_result_tests;
mod certificate_order_retry;
#[cfg(test)]
mod certificate_order_retry_tests;
mod certificate_order_worker;
#[cfg(test)]
mod certificate_order_worker_tests;
mod certificate_renewal_scheduler;
#[cfg(test)]
mod certificate_renewal_scheduler_tests;
mod certificate_runtime;
mod claim_file;
mod claim_service;
#[cfg(test)]
mod claim_service_tests;
mod cluster_secret_redistribution;
mod cluster_storage_provider;
mod consensus_authentication_authority;
#[cfg(test)]
mod consensus_authentication_authority_tests;
mod consensus_authentication_methods;
mod consensus_bootstrap_authority;
mod consensus_filesystem_authority;
mod consensus_identity_administration;
mod consensus_node_enrolment;
mod consensus_operation_status;
mod consensus_permission_administration;
mod consensus_smb_export_administration;
mod consensus_storage_drain_administration;
mod consensus_topology_administration;
mod create_mesh_setup;
#[cfg(test)]
mod create_mesh_setup_tests;
mod create_session;
#[cfg(test)]
mod create_session_tests;
mod current_node_bootstrap;
mod current_session_api;
#[cfg(test)]
mod current_session_api_tests;
mod daemon_local_state;
#[cfg(test)]
mod daemon_local_state_tests;
mod directory_listing_api;
#[cfg(test)]
mod directory_listing_api_tests;
mod external_certificate_publisher;
mod external_certificate_publisher_api;
#[cfg(test)]
mod external_certificate_publisher_api_tests;
#[cfg(test)]
mod external_certificate_publisher_tests;
mod file_read_api;
#[cfg(test)]
mod file_read_api_tests;
mod headless_config;
#[cfg(test)]
mod headless_config_tests;
mod headless_node_join;
mod http01_server;
#[cfg(test)]
mod http01_server_tests;
mod https_server;
#[cfg(test)]
mod https_server_tests;
mod identity_administration;
#[cfg(test)]
mod identity_administration_tests;
mod in_process_certificate_runtime;
mod join_mesh_setup;
#[cfg(test)]
mod join_mesh_setup_tests;
mod local_node_identity;
#[cfg(test)]
mod local_node_identity_tests;
mod local_passkey_ceremony_key;
mod local_totp_ceremony_key;
mod local_wrapping_key;
mod maintenance_authority;
mod maintenance_dispatcher;
mod manual_dns_task_administration;
mod manual_dns_task_administration_api;
#[cfg(test)]
mod manual_dns_task_administration_api_tests;
mod manual_dns_task_authority;
#[cfg(test)]
mod manual_dns_task_authority_tests;
mod mesh_local_certificate_api;
#[cfg(test)]
mod mesh_local_certificate_api_tests;
mod mesh_local_certificate_provisioning;
#[cfg(test)]
mod mesh_local_certificate_provisioning_tests;
mod metadata_backup_completion;
#[cfg(test)]
mod metadata_backup_completion_tests;
mod metadata_backup_coordinator;
#[cfg(test)]
mod metadata_backup_coordinator_tests;
mod metadata_backup_dispatcher;
#[cfg(test)]
mod metadata_backup_dispatcher_tests;
mod metadata_backup_placement;
#[cfg(test)]
mod metadata_backup_placement_tests;
mod metadata_backup_preparation;
#[cfg(test)]
mod metadata_backup_preparation_tests;
mod metadata_backup_provider_resolution;
mod metadata_forwarding;
mod multi_factor_session;
mod namespace_mutation_api;
mod native_api_authentication;
#[cfg(test)]
mod native_api_authentication_tests;
mod native_filesystem_runtime;
mod native_gateway_sync;
mod native_protection;
mod native_query;
mod native_upload_api;
#[cfg(test)]
mod native_upload_api_tests;
#[cfg(test)]
mod native_upload_service_tests;
mod node_activation;
mod node_enrolment;
mod node_enrolment_api;
mod node_join_grant;
mod node_join_grant_api;
mod node_wrapping_key_registration;
#[cfg(test)]
mod node_wrapping_key_registration_tests;
mod object_stat_api;
#[cfg(test)]
mod object_stat_api_tests;
mod online_authority_loading;
mod operation_status;
mod operation_status_api;
mod passkey_challenge;
mod passkey_challenge_api;
#[cfg(test)]
mod passkey_challenge_api_tests;
mod passkey_challenge_configuration;
mod passkey_challenge_state;
#[cfg(test)]
mod passkey_challenge_tests;
mod passkey_registration;
mod passkey_registration_api;
#[cfg(test)]
mod passkey_registration_api_tests;
mod passkey_registration_configuration;
mod passkey_registration_contract;
mod passkey_registration_model;
mod passkey_registration_state;
#[cfg(test)]
mod passkey_registration_tests;
mod passkey_session;
mod passkey_session_contract;
mod passkey_session_creation;
#[cfg(test)]
mod passkey_session_creation_tests;
#[cfg(test)]
mod passkey_session_tests;
#[cfg(test)]
mod passkey_test_support;
mod pending_recovery_bundle;
#[cfg(test)]
mod pending_recovery_bundle_tests;
mod periodic_scrub_scheduler;
mod permission_administration;
mod pinned_https_client;
mod private_consensus_runtime;
mod protected_api_key_issuance;
mod protected_file;
mod protected_recovery_code_issuance;
mod public_certificate_installation;
#[cfg(test)]
mod public_certificate_installation_tests;
mod public_certificate_installation_worker;
#[cfg(test)]
mod public_certificate_installation_worker_tests;
mod public_certificate_loading;
#[cfg(test)]
mod public_certificate_loading_tests;
mod public_certificate_rotation;
#[cfg(test)]
mod public_certificate_rotation_tests;
mod public_contract_api;
#[cfg(test)]
mod public_contract_api_tests;
mod rebalance_scheduler;
mod rebalance_worker;
mod recovery_bundle_verification;
mod recovery_bundle_verification_api;
#[cfg(test)]
mod recovery_bundle_verification_tests;
mod recovery_code_issuance;
mod recovery_code_issuance_api;
#[cfg(test)]
mod recovery_code_issuance_api_tests;
mod recovery_code_issuance_contract;
mod recovery_code_issuance_model;
#[cfg(test)]
mod recovery_code_issuance_tests;
mod recovery_code_session_creation;
#[cfg(test)]
mod recovery_code_session_creation_tests;
mod revoke_session;
mod revoke_session_api;
mod scope_drain_worker;
mod scrub_finding_scheduler;
mod setup_api;
#[cfg(test)]
mod setup_api_tests;
mod shard_repair_worker;
mod storage_drain_administration;
#[cfg(test)]
mod storage_drain_administration_api_tests;
mod storage_scrub_worker;
mod target_drain_worker;

pub use http01_server::{Http01Server, Http01ServerError};
pub use maintenance_authority::MaintenanceMetadataAuthority;
pub use maintenance_dispatcher::{
    MaintenanceDispatchAssignment, MaintenanceDispatchBatch, MaintenanceDispatchError,
    MaintenanceDispatcher, MaintenanceWorkSource,
};
pub use manual_dns_task_administration::{
    ManualDnsTaskAdministrationAuthority, ManualDnsTaskAdministrationController,
    ManualDnsTaskAdministrationError, ManualDnsTaskAdministrationService,
};
pub use manual_dns_task_administration_api::{
    ManualDnsTaskAdministrationApiError, manual_dns_task_administration_api_router,
};
pub use manual_dns_task_authority::{
    ConsensusManualDnsTaskAuthority, ManualDnsTaskCommitAuthority, SharedManualDnsTaskAuthority,
};
pub use periodic_scrub_scheduler::{
    PeriodicScrubAdmissionPage, PeriodicScrubAuthority, PeriodicScrubScheduler,
    PeriodicScrubSchedulingError,
};
pub use rebalance_scheduler::{
    RebalanceAdmissionPage, RebalanceScheduler, RebalanceSchedulingAuthority,
    RebalanceSchedulingError,
};
pub use rebalance_worker::{
    RebalanceCatalogue, RebalanceExecution, RebalanceExecutionError, RebalanceMaintenanceAuthority,
    RebalanceStepReceipt, execute_rebalance_step,
};
pub use scope_drain_worker::{ScopeDrainCoordinatorError, execute_scope_drain_action};
pub use scrub_finding_scheduler::{
    AutomaticScrubFindingScheduler, RepairCandidateResolver, ScrubFindingSchedulingError,
    ScrubFindingSink,
};
pub use shard_repair_worker::{
    PhysicalShardRepair, ShardRepairExecution, ShardRepairExecutionError,
    ShardRepairExecutionReceipt, execute_shard_repair,
};
pub use storage_scrub_worker::{
    PhysicalStorageScrub, RecoverableMaintenanceAuthority, ResumableStorageScrubExecution,
    ResumableStorageScrubReceipt, ResumableTargetReconciliationReceipt, ScrubProgressStore,
    StorageScrubExecution, StorageScrubExecutionError, StorageScrubExecutionReceipt,
    StorageScrubSummary, execute_resumable_storage_scrub, execute_resumable_target_reconciliation,
    execute_storage_scrub,
};
pub use target_drain_worker::{
    TargetDrainError, TargetDrainExecution, TargetDrainStepReceipt, TargetShardInventorySource,
    execute_target_drain_step,
};
mod smb_authentication;
mod smb_connection;
mod smb_export_administration;
mod smb_export_administration_api;
#[cfg(test)]
mod smb_export_administration_api_tests;
mod smb_server;
mod smb_verifier_secret;
mod step_up_session;
mod step_up_session_api;
#[cfg(test)]
mod step_up_session_api_tests;
#[cfg(test)]
mod step_up_session_tests;
mod storage_folder_administration;
mod storage_folder_administration_api;
#[cfg(test)]
mod storage_folder_administration_api_tests;
mod storage_permit_loading;
#[cfg(test)]
mod storage_permit_loading_tests;
mod storage_provider_opening;
#[cfg(test)]
mod storage_provider_opening_tests;
mod storage_target_registration;
#[cfg(test)]
mod storage_target_registration_tests;
mod system_manager_authentication;
mod topology_administration;
#[cfg(test)]
mod topology_administration_api_tests;
mod totp_registration;
mod totp_registration_api;
#[cfg(test)]
mod totp_registration_api_tests;
mod totp_registration_configuration;
mod totp_registration_contract;
mod totp_registration_model;
mod totp_registration_state;
#[cfg(test)]
mod totp_registration_tests;
mod totp_secret;
mod totp_session;
mod totp_session_contract;
mod totp_session_creation;
#[cfg(test)]
mod totp_session_creation_tests;
mod volume_administration;
mod volume_administration_api;
#[cfg(test)]
mod volume_administration_tests;
mod volume_inventory;
#[cfg(test)]
mod volume_inventory_api_tests;
#[cfg(test)]
mod volume_inventory_tests;
mod volume_key_loading;
#[cfg(test)]
mod volume_key_loading_tests;

pub use api_key_issuance::ApiKeyIssuanceService;
pub use api_key_issuance_api::{
    ApiKeyIssuanceApiError, ApiKeyIssuanceController, api_key_issuance_api_router,
};
pub use api_key_issuance_contract::{
    ApiKeyIssuanceAuthority, ApiKeyIssuanceAuthorityError, ApiKeyIssuanceCommit,
    ApiKeyIssuanceError,
};
pub use appliance_api::{
    AdministrationApiRoutes, ApplianceApiRoutes, AuthenticationApiRoutes, FileApiRoutes,
    SessionApiRoutes,
};
pub use appliance_runtime::{DaemonProcessError, run_headless_daemon};
pub use auth_api::{CreateSessionController, SessionApiError, session_api_router};
pub use authentication_method_listing::{
    AuthenticationMethodListingApiError, AuthenticationMethodListingAuthority,
    AuthenticationMethodListingAuthorityError, AuthenticationMethodListingController,
    AuthenticationMethodListingError, AuthenticationMethodListingService,
    authentication_method_listing_api_router,
};
pub use authentication_method_revocation::AuthenticationMethodRevocationService;
pub use authentication_method_revocation_api::{
    AuthenticationMethodRevocationApiError, AuthenticationMethodRevocationController,
    authentication_method_revocation_api_router,
};
pub use authentication_method_revocation_contract::{
    AuthenticationMethodRevocationAuthority, AuthenticationMethodRevocationAuthorityError,
    AuthenticationMethodRevocationCommit, AuthenticationMethodRevocationError,
};
pub use authentication_root_loading::{
    AuthenticationRootAuthority, AuthenticationRootLoadingError, AuthenticationRootLoadingService,
    AuthenticationRuntimeKeys, ProtectedTotpFactorVerifier,
    ProtectedTotpRegistrationSecretProtector,
};
pub use authoritative_txt_observer::SystemAuthoritativeTxtObserver;
pub use backup_publication::{
    BackupPublicationAuthority, BackupPublicationError, BackupPublicationOutcome,
    BackupPublicationRequest, MetadataBackupPublisher,
};
pub use backup_restore_readiness::{
    BackupRestoreReadinessAuthority, BackupRestoreReadinessError, BackupRestoreReadinessEvidence,
    BackupRestoreReadinessPaths, BackupRestoreReadinessRequest, MetadataBackupRestoreReadiness,
};
pub use browser_authentication::{
    BrowserAuthenticationError, BrowserSessionAuthenticator, BrowserSessionAuthority,
    BrowserSessionAuthorityError, GatewaySessionIdentity,
};
pub use browser_session::{
    BrowserRequestProtection, BrowserSessionError, BrowserSessionEvidence, parse_browser_session,
};
pub use certificate_administration::{
    CertificateProvisioningAuthority, CertificateProvisioningAuthorityError,
    CertificateProvisioningCommit, CertificateProvisioningController, CertificateProvisioningError,
    CertificateProvisioningService,
};
pub use certificate_administration_api::{
    CertificateProvisioningApiError, certificate_provisioning_api_router,
};
pub use certificate_automation_service::{
    CertificateAutomationComponents, CertificateAutomationError, CertificateAutomationOutcome,
    CertificateAutomationPolicy, CertificateAutomationService, CertificateExecutionFactory,
    CertificateExecutionFactoryError, CertificateOrderPreparer,
};
pub use certificate_order_checkpointing::{
    CertificateOrderCheckpoint, CertificateOrderCheckpointAuthority,
    CertificateOrderCheckpointAuthorityError, CertificateOrderCheckpointCommit,
    CertificateOrderCheckpointError, CertificateOrderCheckpointService,
};
pub use certificate_order_completion::{
    CertificateOrderCompletionAuthority, CertificateOrderCompletionAuthorityError,
    CertificateOrderCompletionCommit, CertificateOrderCompletionError,
    CertificateOrderCompletionService, CertificateOrderIssuance,
};
pub use certificate_order_driver::{
    CertificateOrderDriveOutcome, CertificateOrderDrivePolicy, CertificateOrderDriver,
    CertificateOrderDriverError,
};
pub use certificate_order_execution::{
    CertificateOrderExecution, CertificateOrderExecutionError, CertificateOrderStepResult,
};
pub use certificate_order_preparation::{
    CertificateOrderPreparationAuthority, CertificateOrderPreparationAuthorityError,
    CertificateOrderPreparationError, CertificateOrderPreparationService, PreparedCertificateOrder,
};
pub use certificate_order_result::{CertificateOrderResultError, CertificateOrderResultService};
pub use certificate_order_retry::{
    CertificateOrderFailureClass, CertificateOrderRetryCommit, CertificateOrderRetryError,
    CertificateOrderRetryService,
};
pub use certificate_order_worker::{
    CertificateOrderAssignment, CertificateOrderDispatchError, CertificateOrderDispatcher,
    CertificateOrderWorkerAuthority,
};
pub use certificate_renewal_scheduler::{
    CertificateRenewalAuthority, CertificateRenewalScheduleCommit, CertificateRenewalScheduleError,
    CertificateRenewalScheduler,
};
pub use claim_file::{ClaimFile, ClaimFileError};
pub use claim_service::{
    ClaimConsumptionOutcome, ClaimEnsureDisposition, ClaimEnsureOutcome, ClaimRotationOutcome,
    FirstBootClaimError, FirstBootClaimService,
};
pub use consensus_authentication_authority::ConsensusAuthenticationAuthority;
pub use consensus_bootstrap_authority::ConsensusBootstrapAuthority;
pub use create_mesh_setup::{
    BootstrapAuthority, BootstrapAuthorityError, BootstrapCommit, CreateMeshSetupConfiguration,
    CreateMeshSetupError, CreateMeshSetupService,
};
pub use create_session::{
    CreateSessionError, CreateSessionResult, CreateSessionService, SessionAuthority,
    SessionAuthorityError, SessionCommit,
};
pub use current_node_bootstrap::{ActiveNodeCertificateAuthority, CurrentNodeBootstrapPeerSource};
pub use current_session_api::{
    CurrentSessionApiError, CurrentSessionController, CurrentSessionError,
    current_session_api_router,
};
pub use daemon_local_state::{DaemonLocalState, DaemonLocalStateError};
pub use directory_listing_api::{
    DirectoryLister, DirectoryListingApiError, DirectoryListingController, DirectoryListingError,
    DirectoryListingService, FileApiFailure, NativeFileApiAuthenticator,
    NativeFileRequestProtection, directory_listing_api_router,
};
pub use external_certificate_publisher::{
    ExternalCertificatePublisherAuthority, ExternalCertificatePublisherAuthorityError,
    ExternalCertificatePublisherCommit, ExternalCertificatePublisherController,
    ExternalCertificatePublisherError, ExternalCertificatePublisherService,
};
pub use external_certificate_publisher_api::{
    ExternalCertificatePublisherApiError, external_certificate_publisher_api_router,
};
pub use file_read_api::{
    FileRangeReader, FileReadApiError, FileReadController, FileReadError, FileReadResult,
    FileReadService, file_read_api_router,
};
pub use headless_config::{HeadlessDaemonConfig, HeadlessDaemonConfigError};
pub use https_server::{HttpsServer, HttpsServerError};
pub use identity_administration::{
    GroupMembershipAdministrationCommit, IdentityAdministrationApiError,
    IdentityAdministrationAuthority, IdentityAdministrationAuthorityError,
    IdentityAdministrationCommit, IdentityAdministrationController, IdentityAdministrationError,
    IdentityAdministrationService, IdentityAdministrator, identity_administration_api_router,
};
pub use in_process_certificate_runtime::{
    InProcessCertificateChallenge, InProcessCertificateExecutionFactory,
    InProcessCertificateRuntimeComponents, InProcessCertificateRuntimePolicy,
    InProcessChallengeKind,
};
pub use join_mesh_setup::{JoinMeshSetupError, JoinMeshSetupService};
pub use local_node_identity::{LocalNodeIdentity, LocalNodeIdentityError};
pub use local_passkey_ceremony_key::{LocalPasskeyCeremonyKey, LocalPasskeyCeremonyKeyError};
pub use local_totp_ceremony_key::{LocalTotpCeremonyKey, LocalTotpCeremonyKeyError};
pub use local_wrapping_key::{LocalWrappingKey, LocalWrappingKeyError};
pub use mesh_local_certificate_api::{
    MeshLocalCertificateApiError, mesh_local_certificate_api_router,
};
pub use mesh_local_certificate_provisioning::{
    MeshLocalAuthorityCommit, MeshLocalCertificateAuthorityError, MeshLocalCertificateCommit,
    MeshLocalCertificateProvisioningAuthority, MeshLocalCertificateProvisioningController,
    MeshLocalCertificateProvisioningError, MeshLocalCertificateProvisioningService,
};
pub use metadata_backup_completion::{
    MetadataBackupCompletionAuthority, MetadataBackupCompletionError,
    MetadataBackupCompletionOutcome, MetadataBackupCompletionService,
};
pub use metadata_backup_coordinator::{
    ComposedMetadataBackupCycle, MetadataBackupCycle, MetadataBackupCycleError,
    MetadataBackupCyclePlacement, MetadataBackupWorker, MetadataBackupWorkerError,
    MetadataBackupWorkerLimits, MetadataBackupWorkerOutcome,
};
pub use metadata_backup_dispatcher::{
    MetadataBackupDispatchAuthority, MetadataBackupDispatchError, MetadataBackupDispatchOutcome,
    MetadataBackupDispatcher,
};
pub use metadata_backup_placement::{
    MetadataBackupDestinationWriter, MetadataBackupPlacementAuthority,
    MetadataBackupPlacementError, MetadataBackupPlacementInput, MetadataBackupPlacementPage,
    MetadataBackupPlacementService,
};
pub use metadata_backup_preparation::{
    MetadataBackupPreparationAuthority, MetadataBackupPreparationError,
    MetadataBackupPreparationService, PreparedMetadataBackup,
};
pub use metadata_backup_provider_resolution::{
    MetadataBackupProviderResolutionError, MetadataBackupProviderResolver, RegisteredBackupTarget,
    RegisteredTargetBackupProviderResolver, ResolvingMetadataBackupDestinationWriter,
};
pub use namespace_mutation_api::{
    NativeNamespaceMutationApiError, NativeNamespaceMutationController,
    NativeNamespaceMutationError, NativeNamespaceMutationService,
    native_namespace_mutation_api_router,
};
pub use native_api_authentication::{
    FileApiAuthenticationError, NativeApiAuthenticator, NativeApiKeyAuthenticator,
    NativeApiKeyAuthority, NativeApiKeyAuthorityError,
};
pub(crate) use native_filesystem_runtime::{
    NativeFilesystemRuntime, NativeFilesystemRuntimeConfiguration, NativeStorageTarget,
    classify_native_filesystem_error,
};
pub use native_upload_api::{
    NativeUploadApiError, NativeUploadController, NativeUploadError, NativeUploadService,
    NativeUploadServicePolicy, UploadRangeCursor, UploadRangePageRequest, UploadRangeWriteRequest,
    native_upload_api_router,
};
pub use node_activation::{
    NodeActivationAuthority, NodeActivationAuthorityError, NodeActivationCommit,
    NodeActivationError, NodeActivationRequest, NodeActivationService,
};
pub use node_enrolment::{
    NodeEnrolmentAuthority, NodeEnrolmentAuthorityError, NodeEnrolmentBootstrap,
    NodeEnrolmentBootstrapSource, NodeEnrolmentCommit, NodeEnrolmentController, NodeEnrolmentError,
    NodeEnrolmentService,
};
pub use node_enrolment_api::{NodeEnrolmentApiError, node_enrolment_api_router};
pub use node_join_grant::{
    NodeJoinGrantIssuanceAuthority, NodeJoinGrantIssuanceAuthorityError,
    NodeJoinGrantIssuanceCommit, NodeJoinGrantIssuanceController, NodeJoinGrantIssuanceError,
    NodeJoinGrantIssuanceService,
};
pub use node_join_grant_api::{NodeJoinGrantIssuanceApiError, node_join_grant_api_router};
pub use node_wrapping_key_registration::{
    NodeWrappingKeyRegistrationAuthority, NodeWrappingKeyRegistrationAuthorityError,
    NodeWrappingKeyRegistrationError, NodeWrappingKeyRegistrationService,
};
pub use object_stat_api::{
    ObjectStatApiError, ObjectStatController, ObjectStatError, ObjectStatReader, ObjectStatService,
    object_stat_api_router,
};
pub use online_authority_loading::{
    OnlineAuthorityLoadingAuthority, OnlineAuthorityLoadingError, OnlineAuthorityLoadingService,
};
pub use operation_status::{
    OperationStatusAuthority, OperationStatusAuthorityError, OperationStatusController,
    OperationStatusError, OperationStatusService, OperationStatusViewer,
};
pub use operation_status_api::{OperationStatusApiError, operation_status_api_router};
pub use passkey_challenge::{
    PasskeyCeremonyStore, PasskeyCeremonyStoreError, PasskeyChallengeError, PasskeyChallengeService,
};
pub use passkey_challenge_api::{
    CreatePasskeyChallengeController, PasskeyChallengeApiError, passkey_challenge_api_router,
};
pub use passkey_challenge_configuration::{
    PasskeyChallengeConfiguration, PasskeyChallengeConfigurationError,
};
pub use passkey_challenge_state::{PasskeyCeremonyKey, PasskeyChallengeStateError};
pub use passkey_registration::PasskeyRegistrationService;
pub use passkey_registration_api::{
    PasskeyRegistrationApiError, PasskeyRegistrationController, passkey_registration_api_router,
};
pub use passkey_registration_configuration::{
    PasskeyRegistrationConfiguration, PasskeyRegistrationConfigurationError,
};
pub use passkey_registration_contract::{
    AuthenticationRegistrationStore, AuthenticationRegistrationStoreError,
    PasskeyRegistrationAuthority, PasskeyRegistrationAuthorityError, PasskeyRegistrationCommit,
    PasskeyRegistrationError, PasskeyRegistrationStore, PasskeyRegistrationStoreError,
};
pub use passkey_session::{
    PasskeySessionError, PasskeySessionService, PasskeySessionStore, PasskeySessionStoreError,
    PreparedPasskeySession, VerifiedPasskeyFactor,
};
pub use passkey_session_contract::{
    DisabledPasskeyProof, DisabledPasskeySessions, PasskeySessionCeremony, PreparedPasskeyProof,
};
pub use pending_recovery_bundle::{
    PendingRecoveryBundle, PendingRecoveryBundleError, PendingRecoveryBundleRemoval,
};
pub use permission_administration::{
    PermissionAdministrationApiError, PermissionAdministrationAuthority,
    PermissionAdministrationAuthorityError, PermissionAdministrationController,
    PermissionAdministrationError, PermissionAdministrationService,
    permission_administration_api_router,
};
pub use protected_api_key_issuance::ProtectedApiKeyIssuanceController;
pub use protected_recovery_code_issuance::ProtectedRecoveryCodeIssuanceController;
pub use public_certificate_installation::{
    PublicCertificateInstallationAuthority, PublicCertificateInstallationAuthorityError,
    PublicCertificateInstallationCommit, PublicCertificateInstallationError,
    PublicCertificateInstallationRequest, PublicCertificateInstallationService,
};
pub use public_certificate_installation_worker::{
    PublicCertificateInstallationWorker, PublicCertificateInstallationWorkerComponents,
    PublicCertificateInstallationWorkerError, PublicCertificateInstallationWorkerOutcome,
    PublicCertificateSelectionAuthority, PublicCertificateSelectionAuthorityError,
};
pub use public_certificate_loading::{
    LoadedPublicCertificate, PublicCertificateLoadingError, PublicCertificateLoadingService,
};
pub use public_certificate_rotation::{
    InstalledPublicCertificate, PublicCertificateInstallOutcome, PublicCertificateRotationError,
    RotatingHttpsIdentity,
};
pub use public_contract_api::{
    PublicContractApiError, ReadinessSource, public_contract_api_router,
};
pub use recovery_bundle_verification::{
    RecoveryBundleVerificationAuthority, RecoveryBundleVerificationAuthorityError,
    RecoveryBundleVerificationCommit, RecoveryBundleVerificationController,
    RecoveryBundleVerificationError, RecoveryBundleVerificationService,
};
pub use recovery_bundle_verification_api::{
    RecoveryBundleVerificationApiError, recovery_bundle_verification_api_router,
};
pub use recovery_code_issuance::RecoveryCodeIssuanceService;
pub use recovery_code_issuance_api::{
    RecoveryCodeIssuanceApiError, RecoveryCodeIssuanceController, recovery_code_issuance_api_router,
};
pub use recovery_code_issuance_contract::{
    RecoveryCodeIssuanceAuthority, RecoveryCodeIssuanceAuthorityError, RecoveryCodeIssuanceCommit,
    RecoveryCodeIssuanceError,
};
pub use revoke_session::{
    RevokeCurrentSessionError, RevokeCurrentSessionService, SessionRevocationAuthority,
    SessionRevocationAuthorityError, SessionRevocationCommit,
};
pub use revoke_session_api::{
    RevokeCurrentSessionApiError, RevokeCurrentSessionController, revoke_current_session_api_router,
};
pub use setup_api::{
    CreateMeshSetupController, JoinMeshSetupController, SetupApiError, SetupLifecycleError,
    SetupStateSnapshot, SetupStatusSource, setup_api_router, setup_api_router_with_creation,
    setup_api_router_with_mutations,
};
pub use smb_authentication::{
    ProtectedSmbVerifierKeySource, SmbAuthenticatedIdentity, SmbAuthentication,
    SmbAuthenticationAuthority, SmbAuthenticationAuthorityError, SmbAuthenticationError,
    SmbAuthenticationService, SmbCredentialEvidence, SmbSessionAuthority, SmbVerifierKeySource,
};
pub use smb_export_administration::{
    SmbExportAdministrationAuthority, SmbExportAdministrationAuthorityError,
    SmbExportAdministrationController, SmbExportAdministrationError,
    SmbExportAdministrationService,
};
pub use smb_export_administration_api::{
    SmbExportAdministrationApiError, smb_export_administration_api_router,
};
pub use smb_server::{
    SmbConnectionHandler, SmbHandlerFuture, SmbServer, SmbServerConfigurationError, SmbServerError,
    SmbServerLimits,
};
pub use smb_verifier_secret::{
    SmbVerifierBinding, SmbVerifierCipher, SmbVerifierEnvelopeKey, SmbVerifierMaterial,
    SmbVerifierSecretError,
};
pub use step_up_session::{
    StepUpCurrentSessionError, StepUpCurrentSessionService, StepUpSessionAuthority,
};
pub use step_up_session_api::{
    StepUpCurrentSessionApiError, StepUpCurrentSessionController,
    step_up_current_session_api_router,
};
pub use storage_drain_administration::{
    StorageDrainAdministrationApiError, StorageDrainAdministrationAuthority,
    StorageDrainAdministrationAuthorityError, StorageDrainAdministrationController,
    StorageDrainAdministrationError, StorageDrainAdministrationService,
    storage_drain_administration_api_router,
};
pub use storage_folder_administration::{
    StorageFolderAdministrationBackend, StorageFolderAdministrationBackendError,
    StorageFolderAdministrationController, StorageFolderAdministrationError,
    StorageFolderAdministrationService,
};
pub use storage_folder_administration_api::{
    StorageFolderAdministrationApiError, storage_folder_administration_api_router,
};
pub use storage_permit_loading::{
    StoragePermitAuthority, StoragePermitLoadingError, StoragePermitLoadingService,
};
pub use storage_provider_opening::{
    LocalFolderStorageProvider, StorageProviderOpeningError, StorageProviderOpeningService,
};
pub use storage_target_registration::{
    RegisteredStorageTarget, StorageTargetRegistrationAuthority,
    StorageTargetRegistrationAuthorityError, StorageTargetRegistrationError,
    StorageTargetRegistrationService,
};
pub use system_manager_authentication::{
    SystemManagerAuthenticationError, SystemManagerAuthority, authenticate_system_manager,
    authenticate_system_manager_read,
};
pub use topology_administration::{
    TopologyAdministrationApiError, TopologyAdministrationAuthority,
    TopologyAdministrationAuthorityError, TopologyAdministrationController,
    TopologyAdministrationError, TopologyAdministrationService, topology_administration_api_router,
};
pub use totp_registration::TotpRegistrationService;
pub use totp_registration_api::{
    TotpRegistrationApiError, TotpRegistrationController, totp_registration_api_router,
};
pub use totp_registration_configuration::{
    TotpRegistrationConfiguration, TotpRegistrationConfigurationError,
};
pub use totp_registration_contract::{
    TotpRegistrationAuthority, TotpRegistrationAuthorityError, TotpRegistrationCommit,
    TotpRegistrationError, TotpRegistrationSecretProtector,
};
pub use totp_registration_state::{TotpCeremonyKey, TotpRegistrationStateError};
pub use totp_secret::{TotpEnvelopeKey, TotpSecretBinding, TotpSecretCipher, TotpSecretError};
pub use totp_session::TotpSessionVerifier;
pub use totp_session_contract::{
    DisabledTotpFactors, TotpFactorVerifier, TotpSessionError, VerifiedTotpFactor,
};
pub use volume_administration::{
    VolumeAdministrationAuthority, VolumeAdministrationAuthorityError, VolumeAdministrationCommit,
    VolumeAdministrationController, VolumeAdministrationError, VolumeAdministrationService,
};
pub use volume_administration_api::{
    VolumeAdministrationApiError, volume_administration_api_router,
};
pub use volume_inventory::{
    VolumeInventoryApiError, VolumeInventoryAuthority, VolumeInventoryAuthorityError,
    VolumeInventoryController, VolumeInventoryError, VolumeInventoryService,
    volume_inventory_api_router,
};
pub use volume_key_loading::{
    SecretGenerationAuthority, SecretGenerationAuthorityError, SecretGenerationDecryptor,
    SecretGenerationDecryptorError, SecretGenerationLoadingError, VolumeKeyAuthority,
    VolumeKeyLoadingError, VolumeKeyLoadingService,
};

use std::time::{SystemTime, UNIX_EPOCH};

use meshspan_domain::{Clock, EntropyError, RandomSource, UnixMicros};

/// Operating-system time exposed through the injectable domain clock boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperatingSystemClock;

impl Clock for OperatingSystemClock {
    fn now(&self) -> UnixMicros {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_micros()).ok())
            .unwrap_or(i64::MIN);
        UnixMicros::new(micros)
    }
}

/// Operating-system cryptographic entropy used by daemon-owned secret material.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperatingSystemRandom;

impl RandomSource for OperatingSystemRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(destination).map_err(|_| EntropyError)
    }
}
#[cfg(test)]
mod bootstrap_test_support;
