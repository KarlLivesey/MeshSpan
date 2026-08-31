// SPDX-License-Identifier: GPL-2.0-only

//! Current-user authentication-method inventory service.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{
    ListAuthenticationMethodsQuery, ListAuthenticationMethodsResponse,
    validate_list_authentication_methods_query,
};
use meshspan_domain::{AssuranceLevel, PrincipalId, UnixMicros};
use meshspan_metadata::PageLimit;

use super::model::{decode_cursor, list_response};
use super::{
    AuthenticationMethodListingAuthority, AuthenticationMethodListingAuthorityError,
    AuthenticationMethodListingError,
};
use crate::{
    BrowserAuthenticationError, BrowserRequestProtection, BrowserSessionAuthenticator,
    FileApiAuthenticationError, GatewaySessionIdentity, NativeApiKeyAuthenticator,
};

const DEFAULT_PAGE_LIMIT: u16 = 100;

/// Complete method inventory over replaceable replicated authority.
pub struct AuthenticationMethodListingService<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A> AuthenticationMethodListingService<A> {
    /// Binds current-user authentication and reads to one gateway authority view.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }

    /// Returns the owned authority for process persistence and shutdown composition.
    #[must_use]
    pub fn into_authority(self) -> A {
        self.authority
    }
}

impl<A> AuthenticationMethodListingService<A>
where
    A: AuthenticationMethodListingAuthority,
{
    /// Authenticates the current caller and returns one bounded secret-free method page.
    ///
    /// # Errors
    ///
    /// Rejects mixed credentials, stale sessions, invalid cursors and unavailable or malformed
    /// replicated authority.
    pub fn list(
        &self,
        headers: &HeaderMap,
        query: &ListAuthenticationMethodsQuery,
        now: UnixMicros,
    ) -> Result<ListAuthenticationMethodsResponse, AuthenticationMethodListingError> {
        validate_list_authentication_methods_query(query)
            .map_err(|_| AuthenticationMethodListingError::InvalidRequest)?;
        let principal_id = self.authenticate(headers, now)?;
        let cursor = query
            .cursor
            .as_ref()
            .map(|value| decode_cursor(value, principal_id))
            .transpose()?;
        let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        let page = self
            .authority
            .authentication_methods(
                principal_id,
                cursor,
                PageLimit::new(usize::from(limit))
                    .map_err(|_| AuthenticationMethodListingError::InvalidRequest)?,
            )
            .map_err(map_authority_error)?;
        list_response(limit, page)
    }

    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<PrincipalId, AuthenticationMethodListingError> {
        let has_authorization = headers.contains_key(AUTHORIZATION);
        if has_authorization && headers.contains_key(COOKIE) {
            return Err(AuthenticationMethodListingError::Rejected);
        }
        if has_authorization {
            return NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
                .authenticate_principal(headers, now)
                .map_err(map_file_authentication_error);
        }
        BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(
                headers,
                BrowserRequestProtection::Read,
                AssuranceLevel::SingleFactor,
                now,
            )
            .map(|capability| capability.principal_id)
            .map_err(map_browser_authentication_error)
    }
}

const fn map_authority_error(
    error: AuthenticationMethodListingAuthorityError,
) -> AuthenticationMethodListingError {
    match error {
        AuthenticationMethodListingAuthorityError::Unavailable => {
            AuthenticationMethodListingError::Unavailable
        }
        AuthenticationMethodListingAuthorityError::Failed => {
            AuthenticationMethodListingError::Failed
        }
    }
}

const fn map_browser_authentication_error(
    error: BrowserAuthenticationError,
) -> AuthenticationMethodListingError {
    match error {
        BrowserAuthenticationError::Rejected => AuthenticationMethodListingError::Rejected,
        BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Unavailable) => {
            AuthenticationMethodListingError::Unavailable
        }
        BrowserAuthenticationError::InvalidGateway
        | BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Failed) => {
            AuthenticationMethodListingError::Failed
        }
    }
}

const fn map_file_authentication_error(
    error: FileApiAuthenticationError,
) -> AuthenticationMethodListingError {
    match error {
        FileApiAuthenticationError::Rejected => AuthenticationMethodListingError::Rejected,
        FileApiAuthenticationError::AuthorityUnavailable => {
            AuthenticationMethodListingError::Unavailable
        }
        FileApiAuthenticationError::AuthorityFailed
        | FileApiAuthenticationError::InvalidGateway => AuthenticationMethodListingError::Failed,
    }
}
