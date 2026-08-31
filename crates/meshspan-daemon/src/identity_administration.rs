// SPDX-License-Identifier: GPL-2.0-only

//! Public user/group administration over committed mesh-wide identity state.

mod api;
mod contract;
mod model;
mod service;

use axum::http::HeaderMap;
use meshspan_api_contract::{
    CreateGroupRequest, CreatePrincipalResponse, CreateUserRequest, ListPrincipalsQuery,
    ListPrincipalsResponse, PrincipalKind,
};
use meshspan_domain::{PrincipalId, UnixMicros};
use thiserror::Error;

use crate::BrowserRequestProtection;

pub use api::{IdentityAdministrationApiError, identity_administration_api_router};
pub use contract::{
    IdentityAdministrationAuthority, IdentityAdministrationAuthorityError,
    IdentityAdministrationCommit,
};
pub use service::IdentityAdministrationService;

/// Authenticated, current system-manager context passed separately from untrusted input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityAdministrator {
    /// Exact actor recorded by every committed mutation.
    pub principal_id: PrincipalId,
    /// Authoritative request instant used by command and access checks.
    pub now: UnixMicros,
}

/// Synchronous identity administration executed on Tokio's bounded blocking pool.
pub trait IdentityAdministrationController: Send + 'static {
    /// Authenticates and proves current manager authority before body consumption or data access.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale, revoked, insufficient or unavailable current authority.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, IdentityAdministrationError>;

    /// Returns one bounded current user/group page.
    ///
    /// # Errors
    ///
    /// Rejects substituted cursors and unavailable or corrupt authority.
    fn list_principals(
        &self,
        administrator: IdentityAdministrator,
        kind: PrincipalKind,
        query: ListPrincipalsQuery,
    ) -> Result<ListPrincipalsResponse, IdentityAdministrationError>;

    /// Creates or exactly replays one local user.
    ///
    /// # Errors
    ///
    /// Rejects invalid names, changed retries and unavailable or corrupt authority.
    fn create_user(
        &mut self,
        administrator: IdentityAdministrator,
        request: CreateUserRequest,
    ) -> Result<CreatePrincipalResponse, IdentityAdministrationError>;

    /// Creates or exactly replays one local nested group.
    ///
    /// # Errors
    ///
    /// Rejects invalid names, changed retries and unavailable or corrupt authority.
    fn create_group(
        &mut self,
        administrator: IdentityAdministrator,
        request: CreateGroupRequest,
    ) -> Result<CreatePrincipalResponse, IdentityAdministrationError>;
}

/// Closed non-secret identity-administration failure categories.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IdentityAdministrationError {
    /// Public identifiers, names, bounds or continuations are invalid.
    #[error("identity-administration input is invalid")]
    InvalidInput,
    /// No current authenticated browser session was accepted.
    #[error("identity-administration authentication was rejected")]
    Unauthenticated,
    /// The current principal lacks system-manager authority.
    #[error("identity-administration authority was denied")]
    Forbidden,
    /// Name uniqueness or exact operation replay conflicts with committed state.
    #[error("identity-administration operation conflicts with committed state")]
    Conflict,
    /// Required committed authority is temporarily unavailable.
    #[error("identity-administration authority is unavailable")]
    Unavailable,
    /// Persisted evidence, response construction or an invariant failed closed.
    #[error("identity-administration failed closed")]
    Failed,
}
