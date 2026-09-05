// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative public API models, schemas, and trust-boundary validation.

mod api_key_management;
mod api_key_validation;
mod authentication_method_listing;
mod authentication_method_listing_validation;
mod backup_destination;
#[cfg(test)]
mod backup_destination_tests;
mod backup_destination_validation;
mod backup_export;
#[cfg(test)]
mod backup_export_tests;
mod backup_history;
#[cfg(test)]
mod backup_history_tests;
mod backup_history_validation;
mod backup_schedule;
#[cfg(test)]
mod backup_schedule_tests;
mod backup_schedule_validation;

mod certificate_administration;
mod certificate_administration_validation;
mod directory_listing;
mod directory_listing_validation;
mod file_read;
mod file_read_validation;
mod file_upload;
mod file_upload_validation;
mod group_membership_administration;
mod group_membership_administration_validation;
mod identity_administration;
mod identity_administration_validation;
mod manual_dns_task;
mod manual_dns_task_validation;
mod model;
mod namespace_mutation;
mod namespace_mutation_validation;
mod node_enrolment;
mod node_enrolment_validation;
mod object_stat;
mod object_stat_validation;
mod openapi;
mod operation_status;
mod operation_status_validation;
mod passkey_registration;
mod passkey_validation;
mod permission_administration;
mod permission_administration_validation;
mod placement_policy_administration;
mod placement_policy_administration_validation;
mod protection_administration;
mod protection_administration_validation;
mod recovery_bundle_verification;
mod recovery_bundle_verification_validation;
mod recovery_code_management;
mod recovery_code_validation;
mod schema;
mod smb_export_administration;
mod smb_export_administration_validation;
mod storage_drain_administration;
mod storage_drain_administration_validation;
mod storage_folder_administration;
mod storage_folder_administration_validation;
mod topology_administration;
mod topology_administration_validation;
mod totp_registration;
mod totp_validation;
mod validation;
mod volume_inventory;
mod volume_inventory_validation;

#[cfg(test)]
mod authentication_method_listing_tests;
#[cfg(test)]
mod certificate_administration_tests;
#[cfg(test)]
mod file_upload_tests;
#[cfg(test)]
mod group_membership_administration_tests;
#[cfg(test)]
mod identity_administration_tests;
#[cfg(test)]
mod manual_dns_task_tests;
#[cfg(test)]
mod namespace_mutation_tests;
#[cfg(test)]
mod placement_policy_administration_tests;
#[cfg(test)]
mod recovery_bundle_verification_tests;
#[cfg(test)]
mod smb_export_administration_tests;
#[cfg(test)]
mod volume_inventory_tests;

pub use api_key_management::{
    ApiKeyExpiry, ApiKeyId, ApiKeyScope, AuthenticationMethodRevocationReason, CreateApiKeyRequest,
    CreateApiKeyResponse, RevokeAuthenticationMethodRequest, RevokeAuthenticationMethodResponse,
};
pub use api_key_validation::{
    MAX_CREATE_API_KEY_BYTES, MAX_REVOKE_AUTHENTICATION_METHOD_BYTES,
    decode_create_api_key_request, decode_revoke_authentication_method_request,
    encode_create_api_key_response, encode_revoke_authentication_method_response,
    validate_create_api_key_request_value, validate_create_api_key_response_value,
    validate_revoke_authentication_method_request_value,
    validate_revoke_authentication_method_response_value,
};
pub use authentication_method_listing::{
    AuthenticationMethodCursor, AuthenticationMethodDetails, AuthenticationMethodState,
    AuthenticationMethodSummary, ListAuthenticationMethodsQuery, ListAuthenticationMethodsResponse,
};
pub use authentication_method_listing_validation::{
    encode_list_authentication_methods_response, validate_list_authentication_methods_query,
    validate_list_authentication_methods_query_value,
};
pub use backup_destination::{
    BackupDestinationFailureRelationship, BackupDestinationProvider, BackupDestinationStatus,
    BackupDestinationSummary, ConfigureBackupDestinationRequest,
    ConfigureBackupDestinationResponse, ListBackupDestinationsQuery,
    ListBackupDestinationsResponse,
};
pub use backup_destination_validation::{
    MAX_CONFIGURE_BACKUP_DESTINATION_BYTES, decode_configure_backup_destination_request,
    encode_configure_backup_destination_response, encode_list_backup_destinations_response,
    validate_list_backup_destinations_query,
};
pub use backup_export::{
    BackupExportHeaders, BackupExportPath, validate_backup_export_headers,
    validate_backup_export_path,
};
pub use backup_history::{
    BackupRunStatus, BackupRunSummary, ListBackupRunsQuery, ListBackupRunsResponse,
};
pub use backup_history_validation::{
    encode_list_backup_runs_response, validate_list_backup_runs_query,
};
pub use backup_schedule::{
    BackupSchedulePolicy, BackupScheduleResponse, BackupScheduleStatus,
    ConfigureBackupScheduleRequest, ConfigureBackupScheduleResponse,
};
pub use backup_schedule_validation::{
    MAX_CONFIGURE_BACKUP_SCHEDULE_BYTES, decode_configure_backup_schedule_request,
    encode_backup_schedule_response, encode_configure_backup_schedule_response,
};
pub use certificate_administration::{
    AcmeConfigurationId, CertificateChainPem, CertificateChallenge, CertificateGeneration,
    CertificateOperationalState, CertificateOrderId, CertificateStatusResponse,
    CertificateStatusSource, CurrentCertificateStatus, ExternalCertificatePrivateKeyPem,
    ExternalCertificatePublicationId, MeshLocalCertificateAuthorityId,
    MeshLocalCertificateIssuanceId, ProtectedText, ProvisionCertificateRequest,
    ProvisionCertificateResponse, ProvisionMeshLocalCertificateRequest,
    ProvisionMeshLocalCertificateResponse, PublicCertificateId, PublishExternalCertificateRequest,
    PublishExternalCertificateResponse, Rfc2136TsigAlgorithm,
};
pub use certificate_administration_validation::{
    MAX_PROVISION_CERTIFICATE_BYTES, MAX_PROVISION_MESH_LOCAL_CERTIFICATE_BYTES,
    MAX_PUBLISH_EXTERNAL_CERTIFICATE_BYTES, decode_provision_certificate_request,
    decode_provision_mesh_local_certificate_request, decode_publish_external_certificate_request,
    encode_certificate_status_response, encode_provision_certificate_response,
    encode_provision_mesh_local_certificate_response, encode_publish_external_certificate_response,
    validate_provision_certificate_request_value,
};
pub use directory_listing::{
    DirectoryCursor, DirectoryEntryKind, FileVersionId, ListDirectoryQuery, ListDirectoryResponse,
    NamespaceCommitId, NamespacePath, ObjectId, ObjectMetadataResponse, ObjectRevisionId, VolumeId,
};
pub use directory_listing_validation::{
    encode_list_directory_response, validate_list_directory_query,
    validate_list_directory_query_value, validate_list_directory_response_value,
};
pub use file_read::{MAX_FILE_READ_BYTES, MAX_SAFE_FILE_OFFSET, ReadFileQuery};
pub use file_read_validation::{validate_read_file_query, validate_read_file_query_value};
pub use file_upload::{
    AbortUploadRequest, AbortUploadResponse, BeginUploadRequest, BeginUploadResponse,
    CommitUploadRequest, CommitUploadResponse, ListUploadRangesQuery, ListUploadRangesResponse,
    MAX_UPLOAD_RANGE_BYTES, UploadDisposition, UploadId, UploadRange, UploadRangeCursor,
    UploadState, UploadStatusResponse, WriteAcknowledgement, WriteDurabilityScope,
    WriteUploadRangeResponse,
};
pub use file_upload_validation::{
    MAX_ABORT_UPLOAD_BYTES, MAX_BEGIN_UPLOAD_BYTES, MAX_COMMIT_UPLOAD_BYTES,
    decode_abort_upload_request, decode_begin_upload_request, decode_commit_upload_request,
    encode_abort_upload_response, encode_begin_upload_response, encode_commit_upload_response,
    encode_list_upload_ranges_response, encode_upload_status_response,
    encode_write_upload_range_response, validate_list_upload_ranges_query,
};
pub use group_membership_administration::{
    AddGroupMemberRequest, AddGroupMemberResponse, GroupMembershipCursor, GroupMembershipInstant,
    GroupMembershipRemovalReason, GroupMembershipSummary, ListGroupMembershipsQuery,
    ListGroupMembershipsResponse, RemoveGroupMemberRequest, RemoveGroupMemberResponse,
};
pub use group_membership_administration_validation::{
    MAX_GROUP_MEMBERSHIP_MUTATION_BYTES, decode_add_group_member_request,
    decode_remove_group_member_request, encode_add_group_member_response,
    encode_list_group_memberships_response, encode_remove_group_member_response,
    validate_list_group_memberships_query,
};
pub use identity_administration::{
    CreateGroupRequest, CreatePrincipalResponse, CreateUserRequest, ListPrincipalsQuery,
    ListPrincipalsResponse, PrincipalCursor, PrincipalKind, PrincipalName, PrincipalState,
    PrincipalSummary,
};
pub use identity_administration_validation::{
    MAX_CREATE_PRINCIPAL_BYTES, decode_create_group_request, decode_create_user_request,
    encode_create_principal_response, encode_list_principals_response,
    validate_list_principals_query, validate_list_principals_query_value,
};
pub use manual_dns_task::{
    ListManualDnsTasksQuery, ListManualDnsTasksResponse, ManualDnsTaskAction, ManualDnsTaskCursor,
    ManualDnsTaskSummary,
};
pub use manual_dns_task_validation::{
    encode_list_manual_dns_tasks_response, validate_list_manual_dns_tasks_query,
};
pub use model::{
    ApiError, ApiErrorCode, ApiErrorIssue, AssuranceLevel, CreateMeshSetupRequest,
    CreateMeshSetupResponse, CreatePasskeyChallengeRequest, CreatePasskeyChallengeResponse,
    CreateSessionRequest, CreateSessionResponse, CurrentSessionResponse, HealthResponse,
    HealthStatus, JoinMeshSetupRequest, JoinMeshSetupResponse, NullableField, OperationId,
    PasskeyChallengeId, PasskeyUserVerification, PrincipalId, RevokeCurrentSessionRequest,
    RevokeCurrentSessionResponse, SessionAdditionalFactor, SessionAuthentication, SessionId,
    SetupClaim, SetupName, SetupState, SetupStatusResponse, StepUpCurrentSessionRequest,
};
pub use namespace_mutation::{
    CreateDirectoryRequest, CreateDirectoryResponse, DeleteObjectRequest, DeleteObjectResponse,
    DeleteObjectScope, RenameObjectRequest, RenameObjectResponse,
};
pub use namespace_mutation_validation::{
    MAX_NAMESPACE_MUTATION_BYTES, decode_create_directory_request, decode_delete_object_request,
    decode_rename_object_request, encode_create_directory_response, encode_delete_object_response,
    encode_rename_object_response,
};
pub use node_enrolment::{
    CreateNodeJoinGrantRequest, CreateNodeJoinGrantResponse, EnrolNodeRequest, EnrolNodeResponse,
    EnrolmentBootstrapPeer, NodeJoinHost, NodeJoinRole,
};
pub use node_enrolment_validation::{
    MAX_CREATE_NODE_JOIN_GRANT_BYTES, MAX_ENROL_NODE_BYTES, decode_create_node_join_grant_request,
    decode_enrol_node_request, decode_enrol_node_response, encode_create_node_join_grant_response,
    encode_enrol_node_request, encode_enrol_node_response,
};
pub use object_stat::{GetObjectQuery, GetObjectResponse};
pub use object_stat_validation::{
    encode_get_object_response, validate_get_object_query, validate_get_object_query_value,
    validate_get_object_response_value,
};
pub use openapi::{OPENAPI_PATH, OpenApiDocument, generate_openapi};
pub use operation_status::{
    ListOperationsQuery, ListOperationsResponse, OperationCursor, OperationFailure, OperationKind,
    OperationProgress, OperationProgressUnit, OperationRetryClass, OperationState,
    OperationStatusResponse,
};
pub use operation_status_validation::{
    encode_list_operations_response, encode_operation_status_response,
    validate_list_operations_query,
};
pub use passkey_registration::{
    AuthenticationMethodId, AuthenticationMethodLabel, CreatePasskeyRegistrationChallengeRequest,
    CreatePasskeyRegistrationChallengeResponse, CreatePasskeyRegistrationRequest,
    CreatePasskeyRegistrationResponse, PasskeyAttestation, PasskeyCredentialDescriptor,
    PasskeyCredentialParameter, PasskeyCredentialType, PasskeyResidentKey, PasskeyTransport,
};
pub use passkey_validation::{
    MAX_CREATE_PASSKEY_CHALLENGE_BYTES, MAX_CREATE_PASSKEY_REGISTRATION_BYTES,
    MAX_CREATE_PASSKEY_REGISTRATION_CHALLENGE_BYTES, decode_create_passkey_challenge_request,
    decode_create_passkey_registration_challenge_request,
    decode_create_passkey_registration_request, encode_create_passkey_challenge_response,
    encode_create_passkey_registration_challenge_response,
    encode_create_passkey_registration_response, validate_create_passkey_challenge_request_value,
    validate_create_passkey_challenge_response_value,
    validate_create_passkey_registration_challenge_request_value,
    validate_create_passkey_registration_challenge_response_value,
    validate_create_passkey_registration_request_value,
    validate_create_passkey_registration_response_value,
};
pub use permission_administration::{
    CreateVolumePermissionGrantRequest, CreateVolumePermissionGrantResponse,
    ListVolumePermissionGrantsQuery, ListVolumePermissionGrantsResponse,
    PermissionActivationPolicyId, PermissionActivationRequirement, PermissionGrantCursor,
    PermissionGrantId, PermissionGrantInheritance, PermissionGrantInstant,
    PermissionGrantRevocationReason, RevokePermissionGrantRequest, RevokePermissionGrantResponse,
    VolumePermissionGrantSummary,
};
pub use permission_administration_validation::{
    MAX_PERMISSION_GRANT_MUTATION_BYTES, decode_create_volume_permission_grant_request,
    decode_revoke_permission_grant_request, encode_create_volume_permission_grant_response,
    encode_list_volume_permission_grants_response, encode_revoke_permission_grant_response,
    validate_list_volume_permission_grants_query,
};
pub use placement_policy_administration::{
    AcknowledgementCellMode, AcknowledgementConsistency, AcknowledgementPolicySummary,
    AssignVolumePlacementPolicyRequest, AssignVolumePlacementPolicyResponse,
    CreateAcknowledgementCellRequirement, CreateAcknowledgementPolicyRequest,
    CreateAcknowledgementPolicyResponse, CreateLocalityPolicyRequest, CreateLocalityPolicyResponse,
    CreateLocalityRequirement, ListAcknowledgementPoliciesResponse, ListLocalityPoliciesResponse,
    ListPlacementPoliciesQuery, LocalityPolicySummary, LocalityRequirementSummary,
    PlacementPolicyCursor, ProtectionScenarioReferenceId, StrongFallback,
};
pub use placement_policy_administration_validation::{
    MAX_PLACEMENT_POLICY_MUTATION_BYTES, decode_assign_volume_placement_policy_request,
    decode_create_acknowledgement_policy_request, decode_create_locality_policy_request,
    encode_assign_volume_placement_policy_response, encode_create_acknowledgement_policy_response,
    encode_create_locality_policy_response, encode_list_acknowledgement_policies_response,
    encode_list_locality_policies_response,
};
pub use protection_administration::{
    AssignVolumeProtectionPolicyRequest, AssignVolumeProtectionPolicyResponse,
    CreateProtectionPolicyRequest, CreateProtectionPolicyResponse, CreateProtectionScenario,
    ListProtectionPoliciesQuery, ListProtectionPoliciesResponse, ProtectionFailureTerm,
    ProtectionFailureTermSummary, ProtectionName, ProtectionPolicyCursor, ProtectionPolicySummary,
    ProtectionScenarioSummary,
};
pub use protection_administration_validation::{
    MAX_PROTECTION_POLICY_MUTATION_BYTES, decode_assign_volume_protection_policy_request,
    decode_create_protection_policy_request, encode_assign_volume_protection_policy_response,
    encode_create_protection_policy_response, encode_list_protection_policies_response,
};
pub use recovery_bundle_verification::{
    ConfirmRecoveryBundleRequest, ConfirmRecoveryBundleResponse,
};
pub use recovery_bundle_verification_validation::{
    MAX_CONFIRM_RECOVERY_BUNDLE_BYTES, decode_confirm_recovery_bundle_request,
    encode_confirm_recovery_bundle_response, validate_confirm_recovery_bundle_request_value,
};
pub use recovery_code_management::{
    CreateRecoveryCodesRequest, CreateRecoveryCodesResponse, RECOVERY_CODES_PER_SET, RecoveryCode,
};
pub use recovery_code_validation::{
    MAX_CREATE_RECOVERY_CODES_BYTES, decode_create_recovery_codes_request,
    encode_create_recovery_codes_response, validate_create_recovery_codes_request_value,
    validate_create_recovery_codes_response_value,
};
pub use smb_export_administration::{
    PublishSmbExportRequest, PublishSmbExportResponse, SmbExportGatewaySelection, SmbExportId,
    SmbShareName, WithdrawSmbExportRequest, WithdrawSmbExportResponse,
};
pub use smb_export_administration_validation::{
    MAX_PUBLISH_SMB_EXPORT_BYTES, MAX_WITHDRAW_SMB_EXPORT_BYTES, decode_publish_smb_export_request,
    decode_withdraw_smb_export_request, encode_publish_smb_export_response,
    encode_withdraw_smb_export_response,
};
pub use storage_drain_administration::{
    BeginStorageDrainRequest, BeginStorageDrainResponse, ListStorageDrainsQuery,
    ListStorageDrainsResponse, StorageDrainCursor, StorageDrainScope, StorageDrainState,
    StorageDrainSummary,
};
pub use storage_drain_administration_validation::{
    MAX_BEGIN_STORAGE_DRAIN_BYTES, decode_begin_storage_drain_request,
    encode_begin_storage_drain_response, encode_list_storage_drains_response,
    encode_storage_drain_summary, validate_list_storage_drains_query,
};
pub use storage_folder_administration::{
    ListStorageFoldersQuery, ListStorageFoldersResponse, RegisterStorageFolderRequest,
    RegisterStorageFolderResponse, StorageFolderCursor, StorageFolderPath, StorageFolderState,
    StorageFolderSummary, StorageFolderUsageLimit,
};
pub use storage_folder_administration_validation::{
    MAX_REGISTER_STORAGE_FOLDER_BYTES, decode_register_storage_folder_request,
    encode_list_storage_folders_response, encode_register_storage_folder_response,
    validate_list_storage_folders_query,
};
pub use topology_administration::{
    AvailabilityCellSummary, CreateAvailabilityCellRequest, CreateAvailabilityCellResponse,
    CreateFaultGroupRequest, CreateFaultGroupResponse, FaultGroupClassName,
    FaultGroupMembershipSummary, FaultGroupName, FaultGroupSummary, ListAvailabilityCellsResponse,
    ListFaultGroupMembershipsResponse, ListFaultGroupsResponse, ListTopologyNodesResponse,
    ListTopologyQuery, ListTopologyTargetsResponse, SetAvailabilityCellMembershipResponse,
    SetFaultGroupMembershipRequest, SetFaultGroupMembershipResponse, TopologyCursor,
    TopologyNodeRoles, TopologyNodeState, TopologyNodeSummary, TopologyTargetState,
    TopologyTargetSummary,
};
pub use topology_administration_validation::{
    MAX_TOPOLOGY_MUTATION_BYTES, decode_create_availability_cell_request,
    decode_create_fault_group_request, decode_set_fault_group_membership_request,
    encode_create_availability_cell_response, encode_create_fault_group_response,
    encode_list_availability_cells_response, encode_list_fault_group_memberships_response,
    encode_list_fault_groups_response, encode_list_topology_nodes_response,
    encode_list_topology_targets_response, encode_set_availability_cell_membership_response,
    encode_set_fault_group_membership_response, validate_list_topology_query,
};
pub use totp_registration::{
    CreateTotpRegistrationChallengeRequest, CreateTotpRegistrationChallengeResponse,
    CreateTotpRegistrationRequest, CreateTotpRegistrationResponse, TotpRegistrationAlgorithm,
    TotpRegistrationChallengeId,
};
pub use totp_validation::{
    MAX_CREATE_TOTP_REGISTRATION_BYTES, MAX_CREATE_TOTP_REGISTRATION_CHALLENGE_BYTES,
    decode_create_totp_registration_challenge_request, decode_create_totp_registration_request,
    encode_create_totp_registration_challenge_response, encode_create_totp_registration_response,
};
pub use validation::{
    BoundaryError, MAX_CREATE_MESH_SETUP_BYTES, MAX_CREATE_SESSION_BYTES,
    MAX_JOIN_MESH_SETUP_BYTES, MAX_REVOKE_CURRENT_SESSION_BYTES, MAX_STEP_UP_CURRENT_SESSION_BYTES,
    ValidationIssue, decode_create_mesh_setup_request, decode_create_session_request,
    decode_join_mesh_setup_request, decode_revoke_current_session_request,
    decode_step_up_current_session_request, encode_api_error, encode_create_mesh_setup_response,
    encode_create_session_response, encode_current_session_response,
    encode_join_mesh_setup_request, encode_join_mesh_setup_response,
    encode_revoke_current_session_response, encode_setup_status_response, validate_api_error_value,
    validate_create_mesh_setup_request_value, validate_create_mesh_setup_response_value,
    validate_create_session_request_value, validate_create_session_response_value,
    validate_revoke_current_session_request_value, validate_revoke_current_session_response_value,
    validate_setup_status_response_value, validate_step_up_current_session_request_value,
};
pub use volume_inventory::{
    CreateVolumeRequest, CreateVolumeResponse, ListVolumesQuery, ListVolumesResponse,
    NamespaceRight, VolumeCursor, VolumeName, VolumeState, VolumeSummary,
};
pub use volume_inventory_validation::{
    MAX_CREATE_VOLUME_BYTES, decode_create_volume_request, encode_create_volume_response,
    encode_list_volumes_response, validate_list_volumes_query, validate_list_volumes_query_value,
};
