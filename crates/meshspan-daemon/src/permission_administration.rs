// SPDX-License-Identifier: GPL-2.0-only

//! Swarm-wide allow-only permission administration over replicated metadata.

mod api;
mod contract;
mod model;
mod service;

use axum::http::HeaderMap;
use meshspan_api_contract::{
    CreateVolumePermissionGrantRequest, CreateVolumePermissionGrantResponse,
    ListVolumePermissionGrantsQuery, ListVolumePermissionGrantsResponse, PermissionGrantId,
    RevokePermissionGrantRequest, RevokePermissionGrantResponse, VolumeId as ApiVolumeId,
};
use meshspan_domain::UnixMicros;
use thiserror::Error;

use crate::{BrowserRequestProtection, IdentityAdministrator};

pub use api::{PermissionAdministrationApiError, permission_administration_api_router};
pub use contract::{PermissionAdministrationAuthority, PermissionAdministrationAuthorityError};
pub use service::PermissionAdministrationService;

/// Synchronous manager-only permission controller.
pub trait PermissionAdministrationController: Send + 'static {
    /// Authenticates current system-manager authority before body consumption or disclosure.
    ///
    /// # Errors
    ///
    /// Rejects ambiguous, stale, revoked, insufficient or unavailable authority.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, PermissionAdministrationError>;

    /// Returns one bounded current volume-grant page.
    ///
    /// # Errors
    ///
    /// Rejects unknown volumes, substituted cursors or untrustworthy committed state.
    fn list_volume_grants(
        &self,
        administrator: IdentityAdministrator,
        volume_id: &ApiVolumeId,
        query: ListVolumePermissionGrantsQuery,
    ) -> Result<ListVolumePermissionGrantsResponse, PermissionAdministrationError>;

    /// Creates or exactly replays one allow-only volume grant.
    ///
    /// # Errors
    ///
    /// Rejects unknown resources, invalid rights/windows and changed operation reuse.
    fn create_volume_grant(
        &mut self,
        administrator: IdentityAdministrator,
        volume_id: &ApiVolumeId,
        request: CreateVolumePermissionGrantRequest,
    ) -> Result<CreateVolumePermissionGrantResponse, PermissionAdministrationError>;

    /// Revokes or exactly replays one active permission grant.
    ///
    /// # Errors
    ///
    /// Rejects scope substitution, missing grants and changed operation reuse.
    fn revoke_grant(
        &mut self,
        administrator: IdentityAdministrator,
        volume_id: &ApiVolumeId,
        grant_id: &PermissionGrantId,
        request: RevokePermissionGrantRequest,
    ) -> Result<RevokePermissionGrantResponse, PermissionAdministrationError>;
}

/// Closed non-secret permission-administration failure categories.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PermissionAdministrationError {
    /// Public identifiers, rights, bounds or continuations are invalid.
    #[error("permission-administration input is invalid")]
    InvalidInput,
    /// Current authentication was rejected.
    #[error("permission-administration authentication was rejected")]
    Unauthenticated,
    /// Current authority does not permit system administration.
    #[error("permission-administration authority was denied")]
    Forbidden,
    /// Exact operation reuse or committed state conflicts with the request.
    #[error("permission-administration operation conflicts with committed state")]
    Conflict,
    /// The requested volume, principal or active grant does not exist.
    #[error("permission-administration resource was not found")]
    NotFound,
    /// Required committed authority is temporarily unavailable.
    #[error("permission-administration authority is unavailable")]
    Unavailable,
    /// Persisted evidence or an invariant failed closed.
    #[error("permission-administration failed closed")]
    Failed,
}
