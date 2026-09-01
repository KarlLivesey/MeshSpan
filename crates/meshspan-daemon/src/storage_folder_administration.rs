// SPDX-License-Identifier: GPL-2.0-only

//! Manager-only administration of daemon-local storage folders.

use std::path::PathBuf;

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{
    ListStorageFoldersQuery, ListStorageFoldersResponse, RegisterStorageFolderRequest,
    RegisterStorageFolderResponse, StorageFolderCursor, StorageFolderSummary,
    StorageFolderUsageLimit, validate_list_storage_folders_query,
};
use meshspan_domain::{AssuranceLevel, OperationId, UnixMicros};
use meshspan_metadata::StorageUsageLimit;
use thiserror::Error;

use crate::create_mesh_setup::parse_uuid;
use crate::{
    BrowserAuthenticationError, BrowserRequestProtection, BrowserSessionAuthenticator,
    FileApiAuthenticationError, GatewaySessionIdentity, IdentityAdministrationAuthority,
    IdentityAdministrationAuthorityError, IdentityAdministrator, NativeApiKeyAuthenticator,
};

const DEFAULT_PAGE_LIMIT: u16 = 50;
const CURSOR_PREFIX: &str = "v1.";
const LIST_ROUTE: &str = "/api/latest/admin/storage-folders";

/// Local runtime operations needed by the public storage-folder service.
pub trait StorageFolderAdministrationBackend: Send + 'static {
    /// Returns every local folder in stable target-identity order.
    ///
    /// # Errors
    ///
    /// Fails closed when local journal or live runtime state cannot be trusted.
    fn storage_folders(
        &self,
    ) -> Result<Vec<StorageFolderSummary>, StorageFolderAdministrationBackendError>;

    /// Registers and opens one exact existing folder immediately.
    ///
    /// # Errors
    ///
    /// Rejects changed retries and unavailable, unsafe or incompatible folders.
    fn register_storage_folder(
        &mut self,
        path: PathBuf,
        operation_id: OperationId,
        usage_limit: StorageUsageLimit,
        now: UnixMicros,
    ) -> Result<StorageFolderSummary, StorageFolderAdministrationBackendError>;
}

/// Synchronous manager-only storage-folder controller.
pub trait StorageFolderAdministrationController: Send + 'static {
    /// Authenticates before query parsing, body consumption or inventory access.
    ///
    /// # Errors
    ///
    /// Rejects ambiguous, stale or insufficient credentials and unavailable authority.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, StorageFolderAdministrationError>;

    /// Returns one bounded page of local storage folders.
    ///
    /// # Errors
    ///
    /// Rejects invalid continuations and untrustworthy local runtime state.
    fn list_storage_folders(
        &self,
        administrator: IdentityAdministrator,
        query: ListStorageFoldersQuery,
    ) -> Result<ListStorageFoldersResponse, StorageFolderAdministrationError>;

    /// Registers and opens one local existing folder.
    ///
    /// # Errors
    ///
    /// Rejects invalid paths, changed retries and unsafe or unavailable folders.
    fn register_storage_folder(
        &mut self,
        administrator: IdentityAdministrator,
        request: RegisterStorageFolderRequest,
    ) -> Result<RegisterStorageFolderResponse, StorageFolderAdministrationError>;
}

/// Complete storage-folder administration over replaceable authority and runtime boundaries.
pub struct StorageFolderAdministrationService<A, B> {
    authority: A,
    backend: B,
    gateway: GatewaySessionIdentity,
}

impl<A, B> StorageFolderAdministrationService<A, B> {
    /// Binds manager authentication to one daemon-local storage runtime.
    #[must_use]
    pub const fn new(authority: A, backend: B, gateway: GatewaySessionIdentity) -> Self {
        Self {
            authority,
            backend,
            gateway,
        }
    }
}

impl<A, B> StorageFolderAdministrationController for StorageFolderAdministrationService<A, B>
where
    A: IdentityAdministrationAuthority + Send + 'static,
    B: StorageFolderAdministrationBackend,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, StorageFolderAdministrationError> {
        let has_authorization = headers.contains_key(AUTHORIZATION);
        if has_authorization && headers.contains_key(COOKIE) {
            return Err(StorageFolderAdministrationError::Unauthenticated);
        }
        if has_authorization {
            let principal_id = NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
                .authenticate_principal(headers, now)
                .map_err(map_file_authentication_error)?;
            return self
                .authority
                .is_system_manager(principal_id, now)
                .map_err(map_authority_error)?
                .then_some(IdentityAdministrator { principal_id, now })
                .ok_or(StorageFolderAdministrationError::Forbidden);
        }
        let capability = BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(headers, protection, AssuranceLevel::SingleFactor, now)
            .map_err(map_browser_authentication_error)?;
        if !capability.is_system_manager() {
            return Err(StorageFolderAdministrationError::Forbidden);
        }
        Ok(IdentityAdministrator {
            principal_id: capability.principal_id,
            now,
        })
    }

    fn list_storage_folders(
        &self,
        _administrator: IdentityAdministrator,
        query: ListStorageFoldersQuery,
    ) -> Result<ListStorageFoldersResponse, StorageFolderAdministrationError> {
        validate_list_storage_folders_query(&query)
            .map_err(|_| StorageFolderAdministrationError::InvalidInput)?;
        let after = query.cursor.as_ref().map(decode_cursor).transpose()?;
        let limit = usize::from(query.limit.unwrap_or(DEFAULT_PAGE_LIMIT));
        let folders = self.backend.storage_folders().map_err(map_backend_error)?;
        let mut page = folders
            .into_iter()
            .filter(|folder| {
                after
                    .as_deref()
                    .is_none_or(|value| folder.target_id.as_str() > value)
            })
            .take(limit.saturating_add(1))
            .collect::<Vec<_>>();
        let next_page_url = if page.len() > limit {
            page.truncate(limit);
            page.last()
                .map(|folder| next_page_url(&folder.target_id, query.limit))
                .transpose()?
        } else {
            None
        };
        Ok(ListStorageFoldersResponse {
            folders: page,
            next_page_url,
        })
    }

    fn register_storage_folder(
        &mut self,
        administrator: IdentityAdministrator,
        request: RegisterStorageFolderRequest,
    ) -> Result<RegisterStorageFolderResponse, StorageFolderAdministrationError> {
        let operation_id = OperationId::from_bytes(
            parse_uuid(request.operation_id.as_str())
                .map_err(|_| StorageFolderAdministrationError::InvalidInput)?,
        )
        .map_err(|_| StorageFolderAdministrationError::InvalidInput)?;
        let path = PathBuf::from(request.path.as_str());
        if !path.is_absolute() {
            return Err(StorageFolderAdministrationError::InvalidInput);
        }
        let usage_limit = domain_usage_limit(&request.usage_limit)?;
        let folder = self
            .backend
            .register_storage_folder(path, operation_id, usage_limit, administrator.now)
            .map_err(map_backend_error)?;
        Ok(RegisterStorageFolderResponse {
            operation_id: request.operation_id,
            folder,
        })
    }
}

fn domain_usage_limit(
    value: &StorageFolderUsageLimit,
) -> Result<StorageUsageLimit, StorageFolderAdministrationError> {
    match value {
        StorageFolderUsageLimit::Percent { percent } if (1..=100).contains(percent) => {
            Ok(StorageUsageLimit::Percent(*percent))
        }
        StorageFolderUsageLimit::Bytes { bytes } => bytes
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0 && i64::try_from(*value).is_ok())
            .map(StorageUsageLimit::Bytes)
            .ok_or(StorageFolderAdministrationError::InvalidInput),
        StorageFolderUsageLimit::Percent { .. } => {
            Err(StorageFolderAdministrationError::InvalidInput)
        }
    }
}

fn decode_cursor(cursor: &StorageFolderCursor) -> Result<String, StorageFolderAdministrationError> {
    cursor
        .as_str()
        .strip_prefix(CURSOR_PREFIX)
        .filter(|value| value.len() == 36)
        .and_then(|value| parse_uuid(value).ok().map(|_| value.to_owned()))
        .ok_or(StorageFolderAdministrationError::InvalidInput)
}

fn next_page_url(
    target_id: &str,
    requested_limit: Option<u16>,
) -> Result<String, StorageFolderAdministrationError> {
    parse_uuid(target_id).map_err(|_| StorageFolderAdministrationError::Failed)?;
    let mut url = format!("{LIST_ROUTE}?cursor={CURSOR_PREFIX}{target_id}");
    if let Some(limit) = requested_limit {
        use std::fmt::Write;
        write!(url, "&limit={limit}").map_err(|_| StorageFolderAdministrationError::Failed)?;
    }
    Ok(url)
}

const fn map_authority_error(
    error: IdentityAdministrationAuthorityError,
) -> StorageFolderAdministrationError {
    match error {
        IdentityAdministrationAuthorityError::Unavailable => {
            StorageFolderAdministrationError::Unavailable
        }
        IdentityAdministrationAuthorityError::Conflict
        | IdentityAdministrationAuthorityError::Failed => StorageFolderAdministrationError::Failed,
    }
}

const fn map_file_authentication_error(
    error: FileApiAuthenticationError,
) -> StorageFolderAdministrationError {
    match error {
        FileApiAuthenticationError::Rejected => StorageFolderAdministrationError::Unauthenticated,
        FileApiAuthenticationError::AuthorityUnavailable => {
            StorageFolderAdministrationError::Unavailable
        }
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => StorageFolderAdministrationError::Failed,
    }
}

const fn map_browser_authentication_error(
    error: BrowserAuthenticationError,
) -> StorageFolderAdministrationError {
    match error {
        BrowserAuthenticationError::Rejected => StorageFolderAdministrationError::Unauthenticated,
        BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Unavailable) => {
            StorageFolderAdministrationError::Unavailable
        }
        BrowserAuthenticationError::InvalidGateway
        | BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Failed) => {
            StorageFolderAdministrationError::Failed
        }
    }
}

const fn map_backend_error(
    error: StorageFolderAdministrationBackendError,
) -> StorageFolderAdministrationError {
    match error {
        StorageFolderAdministrationBackendError::InvalidInput => {
            StorageFolderAdministrationError::InvalidInput
        }
        StorageFolderAdministrationBackendError::Conflict => {
            StorageFolderAdministrationError::Conflict
        }
        StorageFolderAdministrationBackendError::Unavailable => {
            StorageFolderAdministrationError::Unavailable
        }
        StorageFolderAdministrationBackendError::Failed => StorageFolderAdministrationError::Failed,
    }
}

/// Closed local runtime failure categories safe for the application service.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StorageFolderAdministrationBackendError {
    /// Path or capacity input cannot name a safe local provider.
    #[error("storage-folder input is invalid")]
    InvalidInput,
    /// Exact retry or durable folder ownership conflicts.
    #[error("storage-folder registration conflicts")]
    Conflict,
    /// Local path, storage runtime or consensus authority is temporarily unavailable.
    #[error("storage-folder runtime is unavailable")]
    Unavailable,
    /// Durable state or an internal invariant failed closed.
    #[error("storage-folder runtime failed closed")]
    Failed,
}

/// Closed manager-only storage-folder administration outcomes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StorageFolderAdministrationError {
    /// Path, capacity, operation identity, bound or continuation is invalid.
    #[error("storage-folder administration input is invalid")]
    InvalidInput,
    /// No current credential was accepted.
    #[error("storage-folder administration authentication was rejected")]
    Unauthenticated,
    /// The current principal lacks system-manager authority.
    #[error("storage-folder administration authority was denied")]
    Forbidden,
    /// Exact operation replay or durable folder ownership conflicts.
    #[error("storage-folder administration operation conflicts")]
    Conflict,
    /// Required authority or local storage is temporarily unavailable.
    #[error("storage-folder administration is unavailable")]
    Unavailable,
    /// Persisted evidence, output construction or an invariant failed closed.
    #[error("storage-folder administration failed closed")]
    Failed,
}
