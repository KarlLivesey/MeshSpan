// SPDX-License-Identifier: GPL-2.0-only

//! Shared browser/API-key authentication boundary for system-manager mutations.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_domain::{PrincipalId, UnixMicros};
use thiserror::Error;

use crate::{
    BrowserRequestProtection, BrowserSessionAuthenticator, BrowserSessionAuthority,
    FileApiAuthenticationError, GatewaySessionIdentity, IdentityAdministrator,
    NativeApiKeyAuthenticator, NativeApiKeyAuthority,
};

/// Authority query needed after a native API key has established a principal.
pub trait SystemManagerAuthority: BrowserSessionAuthority + NativeApiKeyAuthority {
    /// Reports whether the principal currently has system-manager authority.
    ///
    /// # Errors
    ///
    /// Fails closed when current role evidence is unavailable or malformed.
    fn principal_is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, SystemManagerAuthenticationError>;
}

/// Authenticates exactly one browser session or native API key before a body is consumed.
///
/// # Errors
///
/// Rejects ambiguous credential families, invalid CSRF, stale authority and non-managers.
pub fn authenticate_system_manager<A>(
    authority: &A,
    gateway: GatewaySessionIdentity,
    headers: &HeaderMap,
    now: UnixMicros,
) -> Result<IdentityAdministrator, SystemManagerAuthenticationError>
where
    A: SystemManagerAuthority,
{
    let has_authorization = headers.contains_key(AUTHORIZATION);
    if has_authorization && headers.contains_key(COOKIE) {
        return Err(SystemManagerAuthenticationError::Rejected);
    }
    if has_authorization {
        let principal_id = NativeApiKeyAuthenticator::new(authority, gateway)
            .authenticate_principal(headers, now)
            .map_err(map_api_key_error)?;
        return authority
            .principal_is_system_manager(principal_id, now)?
            .then_some(IdentityAdministrator { principal_id, now })
            .ok_or(SystemManagerAuthenticationError::Forbidden);
    }
    let capability = BrowserSessionAuthenticator::new(authority, gateway)
        .authenticate(
            headers,
            BrowserRequestProtection::Mutation,
            meshspan_domain::AssuranceLevel::SingleFactor,
            now,
        )
        .map_err(|error| match error {
            crate::BrowserAuthenticationError::Rejected => {
                SystemManagerAuthenticationError::Rejected
            }
            crate::BrowserAuthenticationError::Authority(
                crate::BrowserSessionAuthorityError::Unavailable,
            ) => SystemManagerAuthenticationError::Unavailable,
            crate::BrowserAuthenticationError::InvalidGateway
            | crate::BrowserAuthenticationError::Authority(
                crate::BrowserSessionAuthorityError::Failed,
            ) => SystemManagerAuthenticationError::Failed,
        })?;
    capability
        .is_system_manager()
        .then_some(IdentityAdministrator {
            principal_id: capability.principal_id,
            now,
        })
        .ok_or(SystemManagerAuthenticationError::Forbidden)
}

fn map_api_key_error(error: FileApiAuthenticationError) -> SystemManagerAuthenticationError {
    match error {
        FileApiAuthenticationError::Rejected => SystemManagerAuthenticationError::Rejected,
        FileApiAuthenticationError::AuthorityUnavailable => {
            SystemManagerAuthenticationError::Unavailable
        }
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => SystemManagerAuthenticationError::Failed,
    }
}

/// Closed shared authentication failure without credential detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SystemManagerAuthenticationError {
    /// Credential or mutation protection was rejected.
    #[error("system-manager authentication was rejected")]
    Rejected,
    /// The principal lacks current system-manager authority.
    #[error("system-manager authority is required")]
    Forbidden,
    /// Current authentication or role authority is temporarily unavailable.
    #[error("system-manager authentication is unavailable")]
    Unavailable,
    /// Authentication evidence failed closed.
    #[error("system-manager authentication failed closed")]
    Failed,
}
