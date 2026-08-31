// SPDX-License-Identifier: GPL-2.0-only

//! Daemon process composition, configuration and local secret presentation.

mod api_http;
mod auth_api;
#[cfg(test)]
mod auth_api_tests;
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
mod passkey_challenge;
mod passkey_challenge_api;
#[cfg(test)]
mod passkey_challenge_api_tests;
mod passkey_challenge_configuration;
mod passkey_challenge_state;
#[cfg(test)]
mod passkey_challenge_tests;
mod revoke_session;
mod revoke_session_api;
mod setup_api;
#[cfg(test)]
mod setup_api_tests;

pub use auth_api::{CreateSessionController, SessionApiError, session_api_router};
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

use meshspan_domain::{EntropyError, RandomSource};

/// Operating-system cryptographic entropy used by daemon-owned secret material.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperatingSystemRandom;

impl RandomSource for OperatingSystemRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(destination).map_err(|_| EntropyError)
    }
}
