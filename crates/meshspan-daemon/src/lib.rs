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
mod browser_authentication;
mod browser_session;
mod claim_file;
mod claim_service;
#[cfg(test)]
mod claim_service_tests;
mod create_mesh_setup;
#[cfg(test)]
mod create_mesh_setup_tests;
mod create_session;
#[cfg(test)]
mod create_session_tests;
mod current_session_api;
#[cfg(test)]
mod current_session_api_tests;
mod directory_listing_api;
#[cfg(test)]
mod directory_listing_api_tests;
mod file_read_api;
#[cfg(test)]
mod file_read_api_tests;
mod headless_config;
#[cfg(test)]
mod headless_config_tests;
mod https_server;
#[cfg(test)]
mod https_server_tests;
mod identity_administration;
#[cfg(test)]
mod identity_administration_tests;
mod local_node_identity;
#[cfg(test)]
mod local_node_identity_tests;
mod multi_factor_session;
mod namespace_mutation_api;
mod native_api_authentication;
#[cfg(test)]
mod native_api_authentication_tests;
mod native_query;
mod native_upload_api;
#[cfg(test)]
mod native_upload_api_tests;
#[cfg(test)]
mod native_upload_service_tests;
mod object_stat_api;
#[cfg(test)]
mod object_stat_api_tests;
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
mod protected_file;
mod public_contract_api;
#[cfg(test)]
mod public_contract_api_tests;
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
mod setup_api;
#[cfg(test)]
mod setup_api_tests;
mod step_up_session;
mod step_up_session_api;
#[cfg(test)]
mod step_up_session_api_tests;
#[cfg(test)]
mod step_up_session_tests;
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
mod volume_inventory;
#[cfg(test)]
mod volume_inventory_api_tests;
#[cfg(test)]
mod volume_inventory_tests;

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
pub use browser_authentication::{
    BrowserAuthenticationError, BrowserSessionAuthenticator, BrowserSessionAuthority,
    BrowserSessionAuthorityError, GatewaySessionIdentity,
};
pub use browser_session::{
    BrowserRequestProtection, BrowserSessionError, BrowserSessionEvidence, parse_browser_session,
};
pub use claim_file::{ClaimFile, ClaimFileError};
pub use claim_service::{
    ClaimConsumptionOutcome, ClaimEnsureDisposition, ClaimEnsureOutcome, ClaimRotationOutcome,
    FirstBootClaimError, FirstBootClaimService,
};
pub use create_mesh_setup::{
    BootstrapAuthority, BootstrapAuthorityError, BootstrapCommit, CreateMeshSetupError,
    CreateMeshSetupService,
};
pub use create_session::{
    CreateSessionError, CreateSessionResult, CreateSessionService, SessionAuthority,
    SessionAuthorityError, SessionCommit,
};
pub use current_session_api::{
    CurrentSessionApiError, CurrentSessionController, CurrentSessionError,
    current_session_api_router,
};
pub use directory_listing_api::{
    DirectoryLister, DirectoryListingApiError, DirectoryListingController, DirectoryListingError,
    DirectoryListingService, FileApiFailure, NativeFileApiAuthenticator,
    NativeFileRequestProtection, directory_listing_api_router,
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
pub use local_node_identity::{LocalNodeIdentity, LocalNodeIdentityError};
pub use namespace_mutation_api::{
    NativeNamespaceMutationApiError, NativeNamespaceMutationController,
    NativeNamespaceMutationError, NativeNamespaceMutationService,
    native_namespace_mutation_api_router,
};
pub use native_api_authentication::{
    FileApiAuthenticationError, NativeApiAuthenticator, NativeApiKeyAuthenticator,
    NativeApiKeyAuthority, NativeApiKeyAuthorityError,
};
pub use native_upload_api::{
    NativeUploadApiError, NativeUploadController, NativeUploadError, NativeUploadService,
    NativeUploadServicePolicy, UploadRangeCursor, UploadRangePageRequest, UploadRangeWriteRequest,
    native_upload_api_router,
};
pub use object_stat_api::{
    ObjectStatApiError, ObjectStatController, ObjectStatError, ObjectStatReader, ObjectStatService,
    object_stat_api_router,
};
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
pub use public_contract_api::{
    PublicContractApiError, ReadinessSource, public_contract_api_router,
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
    CreateMeshSetupController, SetupApiError, SetupLifecycleError, SetupStateSnapshot,
    SetupStatusSource, setup_api_router, setup_api_router_with_creation,
};
pub use step_up_session::{
    StepUpCurrentSessionError, StepUpCurrentSessionService, StepUpSessionAuthority,
};
pub use step_up_session_api::{
    StepUpCurrentSessionApiError, StepUpCurrentSessionController,
    step_up_current_session_api_router,
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
    TotpRegistrationError,
};
pub use totp_registration_state::{TotpCeremonyKey, TotpRegistrationStateError};
pub use totp_secret::{TotpEnvelopeKey, TotpSecretBinding, TotpSecretCipher, TotpSecretError};
pub use totp_session::TotpSessionVerifier;
pub use totp_session_contract::{
    DisabledTotpFactors, TotpFactorVerifier, TotpSessionError, VerifiedTotpFactor,
};
pub use volume_inventory::{
    VolumeInventoryApiError, VolumeInventoryAuthority, VolumeInventoryAuthorityError,
    VolumeInventoryController, VolumeInventoryError, VolumeInventoryService,
    volume_inventory_api_router,
};

use meshspan_domain::{EntropyError, RandomSource};

/// Operating-system cryptographic entropy used by daemon-owned secret material.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperatingSystemRandom;

impl RandomSource for OperatingSystemRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(destination).map_err(|_| EntropyError)
    }
}
