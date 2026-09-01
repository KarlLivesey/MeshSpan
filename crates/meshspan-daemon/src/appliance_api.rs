// SPDX-License-Identifier: GPL-2.0-only

//! Complete typed composition of the Stage 6 public appliance API.

use axum::Router;

/// Session creation, inspection, revocation and step-up routes.
pub struct SessionApiRoutes([Router; 4]);

impl SessionApiRoutes {
    /// Requires every session lifecycle router before composition.
    #[must_use]
    pub fn new(creation: Router, current: Router, revocation: Router, step_up: Router) -> Self {
        Self([creation, current, revocation, step_up])
    }

    fn into_router(self) -> Router {
        merge_all(self.0)
    }
}

/// Current-user authentication-method lifecycle routes.
pub struct AuthenticationApiRoutes([Router; 7]);

impl AuthenticationApiRoutes {
    /// Requires challenge, registration, additional-factor and method-management routers.
    #[must_use]
    pub fn new(
        passkey_challenge: Router,
        passkey_registration: Router,
        totp_registration: Router,
        recovery_codes: Router,
        api_keys: Router,
        method_listing: Router,
        method_revocation: Router,
    ) -> Self {
        Self([
            passkey_challenge,
            passkey_registration,
            totp_registration,
            recovery_codes,
            api_keys,
            method_listing,
            method_revocation,
        ])
    }

    fn into_router(self) -> Router {
        merge_all(self.0)
    }
}

/// Native specialised namespace, byte-transfer and visible-volume routes.
pub struct FileApiRoutes([Router; 6]);

impl FileApiRoutes {
    /// Requires every native file-data and namespace router.
    #[must_use]
    pub fn new(
        directory_listing: Router,
        object_stat: Router,
        file_read: Router,
        namespace_mutation: Router,
        upload: Router,
        volume_inventory: Router,
    ) -> Self {
        Self([
            directory_listing,
            object_stat,
            file_read,
            namespace_mutation,
            upload,
            volume_inventory,
        ])
    }

    fn into_router(self) -> Router {
        merge_all(self.0)
    }
}

/// Permission-gated administration routes included in the current appliance slice.
pub struct AdministrationApiRoutes([Router; 1]);

impl AdministrationApiRoutes {
    /// Requires the user, group and direct-membership administration router.
    #[must_use]
    pub fn new(identity: Router) -> Self {
        Self([identity])
    }

    fn into_router(self) -> Router {
        merge_all(self.0)
    }
}

/// All required public route families for one Stage 6 appliance process.
pub struct ApplianceApiRoutes {
    administration: AdministrationApiRoutes,
    authentication: AuthenticationApiRoutes,
    contract: Router,
    files: FileApiRoutes,
    sessions: SessionApiRoutes,
    setup: Router,
}

impl ApplianceApiRoutes {
    /// Requires every Stage 6 route family before a public appliance router can be produced.
    #[must_use]
    pub fn new(
        contract: Router,
        setup: Router,
        sessions: SessionApiRoutes,
        authentication: AuthenticationApiRoutes,
        administration: AdministrationApiRoutes,
        files: FileApiRoutes,
    ) -> Self {
        Self {
            administration,
            authentication,
            contract,
            files,
            sessions,
            setup,
        }
    }

    /// Consumes the typed route set and returns one Axum router for the HTTPS listener.
    pub fn into_router(self) -> Router {
        merge_all([
            self.contract,
            self.setup,
            self.sessions.into_router(),
            self.authentication.into_router(),
            self.administration.into_router(),
            self.files.into_router(),
        ])
    }
}

fn merge_all<const N: usize>(routers: [Router; N]) -> Router {
    routers.into_iter().fold(Router::new(), Router::merge)
}
