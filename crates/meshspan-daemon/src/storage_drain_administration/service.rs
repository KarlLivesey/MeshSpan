// SPDX-License-Identifier: GPL-2.0-only

//! Manager-authorised storage-drain application service.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{
    BeginStorageDrainRequest, BeginStorageDrainResponse, ListStorageDrainsQuery,
    ListStorageDrainsResponse, StorageDrainSummary, validate_list_storage_drains_query,
};
use meshspan_domain::{AssuranceLevel, UnixMicros};
use thiserror::Error;

use super::model::{
    api_operation_id, begin_response, decode_cursor, list_response, operation_matches, page_limit,
    parse_drain_id, public_summary, request_command, request_digest,
};
use super::{StorageDrainAdministrationAuthority, StorageDrainAdministrationAuthorityError};
use crate::{
    BrowserAuthenticationError, BrowserRequestProtection, BrowserSessionAuthenticator,
    FileApiAuthenticationError, GatewaySessionIdentity, IdentityAdministrationAuthorityError,
    IdentityAdministrator, NativeApiKeyAuthenticator,
};

const DEFAULT_PAGE_LIMIT: u16 = 50;

/// Synchronous controller executed on blocking workers by the HTTP boundary.
pub trait StorageDrainAdministrationController: Send + 'static {
    /// Authenticates a system manager before parsing query/body data.
    ///
    /// # Errors
    ///
    /// Rejects missing, ambiguous, stale or insufficient credentials.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, StorageDrainAdministrationError>;

    /// Admits or exactly resolves one safe-removal request.
    ///
    /// # Errors
    ///
    /// Rejects invalid, conflicting or unavailable authority state.
    fn begin_storage_drain(
        &mut self,
        administrator: IdentityAdministrator,
        request: BeginStorageDrainRequest,
    ) -> Result<BeginStorageDrainResponse, StorageDrainAdministrationError>;

    /// Resolves one exact manager-visible storage drain.
    ///
    /// # Errors
    ///
    /// Rejects invalid, absent or untrustworthy drain state.
    fn get_storage_drain(
        &self,
        administrator: IdentityAdministrator,
        drain_id: &str,
    ) -> Result<StorageDrainSummary, StorageDrainAdministrationError>;

    /// Returns one bounded newest-first drain page.
    ///
    /// # Errors
    ///
    /// Rejects invalid continuations or untrustworthy drain state.
    fn list_storage_drains(
        &self,
        administrator: IdentityAdministrator,
        query: ListStorageDrainsQuery,
    ) -> Result<ListStorageDrainsResponse, StorageDrainAdministrationError>;
}

/// Complete drain administration over one replaceable replicated authority.
pub struct StorageDrainAdministrationService<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A> StorageDrainAdministrationService<A> {
    /// Binds manager authentication and drain operations to one authority view.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }
}

impl<A> StorageDrainAdministrationController for StorageDrainAdministrationService<A>
where
    A: StorageDrainAdministrationAuthority + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, StorageDrainAdministrationError> {
        if headers.contains_key(AUTHORIZATION) && headers.contains_key(COOKIE) {
            return Err(StorageDrainAdministrationError::Unauthenticated);
        }
        if headers.contains_key(AUTHORIZATION) {
            let principal_id = NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
                .authenticate_principal(headers, now)
                .map_err(map_file_authentication_error)?;
            return self
                .authority
                .is_system_manager(principal_id, now)
                .map_err(map_identity_authority_error)?
                .then_some(IdentityAdministrator { principal_id, now })
                .ok_or(StorageDrainAdministrationError::Forbidden);
        }
        let capability = BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(headers, protection, AssuranceLevel::SingleFactor, now)
            .map_err(map_browser_authentication_error)?;
        if !capability.is_system_manager() {
            return Err(StorageDrainAdministrationError::Forbidden);
        }
        Ok(IdentityAdministrator {
            principal_id: capability.principal_id,
            now,
        })
    }

    fn begin_storage_drain(
        &mut self,
        administrator: IdentityAdministrator,
        request: BeginStorageDrainRequest,
    ) -> Result<BeginStorageDrainResponse, StorageDrainAdministrationError> {
        let api_operation = request.operation_id.clone();
        let (operation_id, drain_id, context, command) = request_command(administrator, &request)?;
        let expected_digest = request_digest(&command, context);
        let receipt = self
            .authority
            .commit_storage_drain_operation(context, &command)
            .map_err(map_authority_error)?;
        if !operation_matches(&receipt, expected_digest, &command) {
            return Err(StorageDrainAdministrationError::Conflict);
        }
        let record = self
            .authority
            .storage_drain(drain_id)
            .map_err(map_authority_error)?
            .ok_or(StorageDrainAdministrationError::Failed)?;
        if api_operation_id(operation_id)? != api_operation {
            return Err(StorageDrainAdministrationError::Failed);
        }
        begin_response(api_operation, record)
    }

    fn get_storage_drain(
        &self,
        _administrator: IdentityAdministrator,
        drain_id: &str,
    ) -> Result<StorageDrainSummary, StorageDrainAdministrationError> {
        self.authority
            .storage_drain(parse_drain_id(drain_id)?)
            .map_err(map_authority_error)?
            .ok_or(StorageDrainAdministrationError::NotFound)
            .and_then(public_summary)
    }

    fn list_storage_drains(
        &self,
        _administrator: IdentityAdministrator,
        query: ListStorageDrainsQuery,
    ) -> Result<ListStorageDrainsResponse, StorageDrainAdministrationError> {
        validate_list_storage_drains_query(&query)
            .map_err(|_| StorageDrainAdministrationError::InvalidInput)?;
        let after = query.cursor.as_ref().map(decode_cursor).transpose()?;
        let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        let page = self
            .authority
            .storage_drains(after, page_limit(limit)?)
            .map_err(map_authority_error)?;
        list_response(page, limit)
    }
}

/// Closed public service errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StorageDrainAdministrationError {
    /// Request body, query or identifier is invalid.
    #[error("storage-drain input is invalid")]
    InvalidInput,
    /// Authentication was missing, ambiguous or invalid.
    #[error("authentication was rejected")]
    Unauthenticated,
    /// Current system-manager authority is absent.
    #[error("system-manager authority is required")]
    Forbidden,
    /// The exact drain does not exist.
    #[error("storage drain was not found")]
    NotFound,
    /// Request conflicts with committed lifecycle or idempotency state.
    #[error("storage-drain request conflicts with durable state")]
    Conflict,
    /// Replicated authority is temporarily unavailable.
    #[error("storage-drain authority is unavailable")]
    Unavailable,
    /// Integrity or outgoing contract validation failed closed.
    #[error("storage-drain administration failed closed")]
    Failed,
}

fn map_authority_error(
    error: StorageDrainAdministrationAuthorityError,
) -> StorageDrainAdministrationError {
    match error {
        StorageDrainAdministrationAuthorityError::Unavailable => {
            StorageDrainAdministrationError::Unavailable
        }
        StorageDrainAdministrationAuthorityError::Conflict => {
            StorageDrainAdministrationError::Conflict
        }
        StorageDrainAdministrationAuthorityError::Failed => StorageDrainAdministrationError::Failed,
    }
}

fn map_file_authentication_error(
    error: FileApiAuthenticationError,
) -> StorageDrainAdministrationError {
    match error {
        FileApiAuthenticationError::Rejected => StorageDrainAdministrationError::Unauthenticated,
        FileApiAuthenticationError::AuthorityUnavailable => {
            StorageDrainAdministrationError::Unavailable
        }
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => StorageDrainAdministrationError::Failed,
    }
}

fn map_browser_authentication_error(
    error: BrowserAuthenticationError,
) -> StorageDrainAdministrationError {
    match error {
        BrowserAuthenticationError::Rejected => StorageDrainAdministrationError::Unauthenticated,
        BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Unavailable) => {
            StorageDrainAdministrationError::Unavailable
        }
        BrowserAuthenticationError::InvalidGateway
        | BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Failed) => {
            StorageDrainAdministrationError::Failed
        }
    }
}

fn map_identity_authority_error(
    error: IdentityAdministrationAuthorityError,
) -> StorageDrainAdministrationError {
    match error {
        IdentityAdministrationAuthorityError::Unavailable => {
            StorageDrainAdministrationError::Unavailable
        }
        IdentityAdministrationAuthorityError::Conflict => StorageDrainAdministrationError::Conflict,
        IdentityAdministrationAuthorityError::Failed => StorageDrainAdministrationError::Failed,
    }
}
