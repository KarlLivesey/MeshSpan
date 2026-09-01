// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative public API models, schemas, and trust-boundary validation.

mod api_key_management;
mod api_key_validation;
mod authentication_method_listing;
mod authentication_method_listing_validation;
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
mod recovery_bundle_verification;
mod recovery_bundle_verification_validation;
mod recovery_code_management;
mod recovery_code_validation;
mod schema;
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
mod file_upload_tests;
#[cfg(test)]
mod group_membership_administration_tests;
#[cfg(test)]
mod identity_administration_tests;
#[cfg(test)]
mod namespace_mutation_tests;
#[cfg(test)]
mod recovery_bundle_verification_tests;
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
    UploadState, UploadStatusResponse, WriteUploadRangeResponse,
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
    CreateFaultGroupRequest, CreateFaultGroupResponse, FaultGroupClassName,
    FaultGroupMembershipSummary, FaultGroupName, FaultGroupSummary,
    ListFaultGroupMembershipsResponse, ListFaultGroupsResponse, ListTopologyNodesResponse,
    ListTopologyQuery, ListTopologyTargetsResponse, SetFaultGroupMembershipRequest,
    SetFaultGroupMembershipResponse, TopologyCursor, TopologyNodeRoles, TopologyNodeState,
    TopologyNodeSummary, TopologyTargetState, TopologyTargetSummary,
};
pub use topology_administration_validation::{
    MAX_TOPOLOGY_MUTATION_BYTES, decode_create_fault_group_request,
    decode_set_fault_group_membership_request, encode_create_fault_group_response,
    encode_list_fault_group_memberships_response, encode_list_fault_groups_response,
    encode_list_topology_nodes_response, encode_list_topology_targets_response,
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
