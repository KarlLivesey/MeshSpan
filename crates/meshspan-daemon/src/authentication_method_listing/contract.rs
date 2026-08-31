// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable authority and closed failures for authentication-method inventory.

use meshspan_domain::PrincipalId;
use meshspan_metadata::{
    AuthenticationMethodCursor, AuthenticationMethodRecord, AuthoritativeRepository, Page,
    PageLimit, RepositoryError,
};
use thiserror::Error;

use crate::{BrowserSessionAuthority, NativeApiKeyAuthority};

/// Replicated reads required by a current-user authentication-method inventory.
pub trait AuthenticationMethodListingAuthority:
    BrowserSessionAuthority + NativeApiKeyAuthority
{
    /// Returns one bounded, secret-free method page for one exact user.
    ///
    /// # Errors
    ///
    /// Rejects cursor substitution and unavailable or corrupt committed state.
    fn authentication_methods(
        &self,
        principal_id: PrincipalId,
        after: Option<AuthenticationMethodCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<AuthenticationMethodRecord, AuthenticationMethodCursor>,
        AuthenticationMethodListingAuthorityError,
    >;
}

impl AuthenticationMethodListingAuthority for AuthoritativeRepository {
    fn authentication_methods(
        &self,
        principal_id: PrincipalId,
        after: Option<AuthenticationMethodCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<AuthenticationMethodRecord, AuthenticationMethodCursor>,
        AuthenticationMethodListingAuthorityError,
    > {
        AuthoritativeRepository::authentication_methods(self, principal_id, after, limit)
            .map_err(|error| map_repository_error(&error))
    }
}

fn map_repository_error(error: &RepositoryError) -> AuthenticationMethodListingAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            AuthenticationMethodListingAuthorityError::Unavailable
        }
        _ => AuthenticationMethodListingAuthorityError::Failed,
    }
}

/// Closed replicated-authority failures safe for public classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthenticationMethodListingAuthorityError {
    /// Current replicated authority cannot be reached.
    #[error("authentication-method authority is unavailable")]
    Unavailable,
    /// Persisted authority failed validation.
    #[error("authentication-method authority failed closed")]
    Failed,
}

/// Stable inventory failure without credential, cursor or session material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthenticationMethodListingError {
    /// Query bounds or cursor structure are invalid.
    #[error("authentication-method inventory request is invalid")]
    InvalidRequest,
    /// Browser or API-key authentication was rejected.
    #[error("authentication-method inventory authentication was rejected")]
    Rejected,
    /// Authentication authority is temporarily unavailable.
    #[error("authentication-method inventory is unavailable")]
    Unavailable,
    /// Persisted or projected evidence failed closed.
    #[error("authentication-method inventory evidence is invalid")]
    Failed,
}
