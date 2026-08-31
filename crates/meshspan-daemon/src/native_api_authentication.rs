// SPDX-License-Identifier: GPL-2.0-only

//! Direct scoped authentication for `MeshSpan`'s native specialised HTTPS API.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_domain::{ApiKeyBundle, ApiKeyId, AssuranceLevel, AuthenticationService, UnixMicros};
use meshspan_filesystem::FilesystemAccessContext;
use meshspan_metadata::{ApiKeyAuthentication, AuthoritativeRepository, RepositoryError};
use thiserror::Error;

use crate::{
    BrowserAuthenticationError, BrowserSessionAuthenticator, BrowserSessionAuthority,
    GatewaySessionIdentity, NativeFileApiAuthenticator, NativeFileRequestProtection,
};

const BEARER_SCHEME: &str = "Bearer";
const MAXIMUM_AUTHORIZATION_BYTES: usize = 512;

/// Minimal current authority needed to authenticate a direct native-API presentation.
pub trait NativeApiKeyAuthority {
    /// Resolves one exact API-key identity and digest under current headless operation policy.
    ///
    /// # Errors
    ///
    /// Fails closed when committed authentication authority cannot be trusted.
    fn authenticate_native_api_key(
        &self,
        key_id: ApiKeyId,
        digest: [u8; 32],
        required_assurance: AssuranceLevel,
        now: UnixMicros,
    ) -> Result<Option<ApiKeyAuthentication>, NativeApiKeyAuthorityError>;
}

impl NativeApiKeyAuthority for AuthoritativeRepository {
    fn authenticate_native_api_key(
        &self,
        key_id: ApiKeyId,
        digest: [u8; 32],
        required_assurance: AssuranceLevel,
        now: UnixMicros,
    ) -> Result<Option<ApiKeyAuthentication>, NativeApiKeyAuthorityError> {
        self.authenticate_api_key_for_operation(
            digest,
            AuthenticationService::HeadlessApi,
            AuthenticationService::HeadlessApi.api_key_login_scope(),
            required_assurance,
            now,
        )
        .map(|authentication| authentication.filter(|value| value.key_id == key_id))
        .map_err(|error| map_repository_error(&error))
    }
}

impl<T> NativeApiKeyAuthority for &T
where
    T: NativeApiKeyAuthority + ?Sized,
{
    fn authenticate_native_api_key(
        &self,
        key_id: ApiKeyId,
        digest: [u8; 32],
        required_assurance: AssuranceLevel,
        now: UnixMicros,
    ) -> Result<Option<ApiKeyAuthentication>, NativeApiKeyAuthorityError> {
        (*self).authenticate_native_api_key(key_id, digest, required_assurance, now)
    }
}

/// Direct bearer authenticator bound to one exact live gateway process.
pub struct NativeApiKeyAuthenticator<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A> NativeApiKeyAuthenticator<A> {
    /// Composes current replicated key authority with one live gateway identity.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }
}

impl<A> NativeApiKeyAuthenticator<A>
where
    A: NativeApiKeyAuthority,
{
    pub(crate) fn authenticate_principal(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<meshspan_domain::PrincipalId, FileApiAuthenticationError> {
        let key = parse_bearer(headers)?;
        self.authority
            .authenticate_native_api_key(
                key.key_id(),
                key.secret_digest(),
                AssuranceLevel::SingleFactor,
                now,
            )?
            .map(|authentication| authentication.principal_id)
            .ok_or(FileApiAuthenticationError::Rejected)
    }
}

impl<A> NativeFileApiAuthenticator for NativeApiKeyAuthenticator<A>
where
    A: NativeApiKeyAuthority + Send + 'static,
{
    fn authenticate_file_request(
        &self,
        headers: &HeaderMap,
        _protection: NativeFileRequestProtection,
        now: UnixMicros,
    ) -> Result<FilesystemAccessContext, FileApiAuthenticationError> {
        let key = parse_bearer(headers)?;
        let digest = key.secret_digest();
        self.authority
            .authenticate_native_api_key(key.key_id(), digest, AssuranceLevel::SingleFactor, now)?
            .ok_or(FileApiAuthenticationError::Rejected)?;
        Ok(FilesystemAccessContext {
            authentication_service: AuthenticationService::HeadlessApi,
            credential_digest: digest,
            required_assurance: AssuranceLevel::SingleFactor,
            gateway_node_id: self.gateway.node_id,
            gateway_incarnation: self.gateway.incarnation,
            now,
        })
    }
}

/// Browser-session and direct-key authentication for one native API surface.
pub struct NativeApiAuthenticator<B, H> {
    browser: BrowserSessionAuthenticator<B>,
    headless: NativeApiKeyAuthenticator<H>,
}

impl<B, H> NativeApiAuthenticator<B, H> {
    /// Composes both supported native API presentations without weakening either contract.
    #[must_use]
    pub const fn new(
        browser: BrowserSessionAuthenticator<B>,
        headless: NativeApiKeyAuthenticator<H>,
    ) -> Self {
        Self { browser, headless }
    }
}

impl<B, H> NativeFileApiAuthenticator for NativeApiAuthenticator<B, H>
where
    B: BrowserSessionAuthority + Send + 'static,
    H: NativeApiKeyAuthority + Send + 'static,
{
    fn authenticate_file_request(
        &self,
        headers: &HeaderMap,
        protection: NativeFileRequestProtection,
        now: UnixMicros,
    ) -> Result<FilesystemAccessContext, FileApiAuthenticationError> {
        let has_authorization = headers.contains_key(AUTHORIZATION);
        if has_authorization && headers.contains_key(COOKIE) {
            return Err(FileApiAuthenticationError::Rejected);
        }
        if has_authorization {
            self.headless
                .authenticate_file_request(headers, protection, now)
        } else {
            self.browser
                .authenticate_file_request(headers, protection, now)
        }
    }
}

fn parse_bearer(headers: &HeaderMap) -> Result<ApiKeyBundle, FileApiAuthenticationError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(FileApiAuthenticationError::Rejected)?;
    if values.next().is_some() {
        return Err(FileApiAuthenticationError::Rejected);
    }
    let value = value
        .to_str()
        .map_err(|_| FileApiAuthenticationError::Rejected)?;
    if value.len() > MAXIMUM_AUTHORIZATION_BYTES {
        return Err(FileApiAuthenticationError::Rejected);
    }
    let (scheme, credential) = value
        .split_once(' ')
        .ok_or(FileApiAuthenticationError::Rejected)?;
    if !scheme.eq_ignore_ascii_case(BEARER_SCHEME)
        || credential.is_empty()
        || credential.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(FileApiAuthenticationError::Rejected);
    }
    ApiKeyBundle::parse(credential).map_err(|_| FileApiAuthenticationError::Rejected)
}

fn map_repository_error(error: &RepositoryError) -> NativeApiKeyAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            NativeApiKeyAuthorityError::Unavailable
        }
        _ => NativeApiKeyAuthorityError::Failed,
    }
}

/// Closed current-authority failure safe to map at the public HTTP boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NativeApiKeyAuthorityError {
    /// Current replicated authority cannot be reached.
    #[error("native API-key authority is unavailable")]
    Unavailable,
    /// Persisted evidence or an invariant failed validation.
    #[error("native API-key authority failed closed")]
    Failed,
}

/// Non-disclosing authentication result shared by the native API operations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FileApiAuthenticationError {
    /// Local gateway configuration cannot safely execute an operation.
    #[error("native API gateway identity is invalid")]
    InvalidGateway,
    /// Credential presentation or current authority was not accepted.
    #[error("native API authentication was rejected")]
    Rejected,
    /// Current committed authentication authority is unavailable.
    #[error("native API authentication authority is unavailable")]
    AuthorityUnavailable,
    /// Current committed authentication authority failed closed.
    #[error("native API authentication authority failed closed")]
    AuthorityFailed,
}

impl From<NativeApiKeyAuthorityError> for FileApiAuthenticationError {
    fn from(value: NativeApiKeyAuthorityError) -> Self {
        match value {
            NativeApiKeyAuthorityError::Unavailable => Self::AuthorityUnavailable,
            NativeApiKeyAuthorityError::Failed => Self::AuthorityFailed,
        }
    }
}

impl From<BrowserAuthenticationError> for FileApiAuthenticationError {
    fn from(value: BrowserAuthenticationError) -> Self {
        match value {
            BrowserAuthenticationError::InvalidGateway => Self::InvalidGateway,
            BrowserAuthenticationError::Rejected => Self::Rejected,
            BrowserAuthenticationError::Authority(error) => match error {
                crate::BrowserSessionAuthorityError::Unavailable => Self::AuthorityUnavailable,
                crate::BrowserSessionAuthorityError::Failed => Self::AuthorityFailed,
            },
        }
    }
}
