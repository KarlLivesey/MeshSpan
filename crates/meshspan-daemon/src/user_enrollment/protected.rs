// SPDX-License-Identifier: GPL-2.0-only

//! Request-scoped root loading for invitation and credential secret derivation.

use super::{UserEnrollmentAuthority, UserEnrollmentError, UserEnrollmentService};
use crate::{
    AuthenticationRootAuthority, AuthenticationRootLoadingError, AuthenticationRootLoadingService,
    AuthenticationRuntimeKeys, GatewaySessionIdentity, IdentityAdministrator,
    SecretGenerationDecryptor,
};
use axum::http::HeaderMap;
use meshspan_api_contract::{
    CreateApiKeyResponse, IssueUserEnrollmentRequest, IssueUserEnrollmentResponse, OperationId,
    PrincipalId, RedeemUserEnrollmentApiKeyRequest, RevokeUserEnrollmentRequest,
    RevokeUserEnrollmentResponse,
};
use meshspan_domain::{ApiKeyIssuanceKey, UnixMicros};

/// Synchronous enrollment boundary, called only on bounded blocking workers.
pub trait UserEnrollmentController: Send + 'static {
    /// Proves current manager authority with recent step-up before body consumption.
    /// # Errors
    /// Rejects invalid or insufficient authentication.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, UserEnrollmentError>;
    /// Commits or exactly retrieves a live invitation.
    /// # Errors
    /// Rejects invalid or stale consent and unknown outcomes.
    fn issue(
        &mut self,
        actor: IdentityAdministrator,
        target: &PrincipalId,
        request: &IssueUserEnrollmentRequest,
    ) -> Result<IssueUserEnrollmentResponse, UserEnrollmentError>;
    /// Cancels capability use while retaining any committed credential.
    /// # Errors
    /// Rejects stale revisions and changed retries.
    fn revoke(
        &mut self,
        actor: IdentityAdministrator,
        invitation: &OperationId,
        request: &RevokeUserEnrollmentRequest,
    ) -> Result<RevokeUserEnrollmentResponse, UserEnrollmentError>;
    /// Exchanges explicit consent for one independent primary credential.
    /// # Errors
    /// Rejects invalid, expired or replayed capabilities.
    fn redeem(
        &mut self,
        request: &RedeemUserEnrollmentApiKeyRequest,
        now: UnixMicros,
    ) -> Result<CreateApiKeyResponse, UserEnrollmentError>;
}

/// Live enrollment controller retaining no decrypted root between requests.
pub struct ProtectedUserEnrollmentController<A, R, D> {
    service: UserEnrollmentService<A>,
    roots: AuthenticationRootLoadingService<R, D>,
}
impl<A: UserEnrollmentAuthority, R, D> ProtectedUserEnrollmentController<A, R, D> {
    /// Binds replicated consent, current root authority and one recipient's local decryptor.
    #[must_use]
    pub const fn new(
        authority: A,
        roots: R,
        decryptor: D,
        gateway: GatewaySessionIdentity,
    ) -> Self {
        Self {
            service: UserEnrollmentService::new(authority, gateway),
            roots: AuthenticationRootLoadingService::new(roots, decryptor),
        }
    }
}
impl<A, R, D> UserEnrollmentController for ProtectedUserEnrollmentController<A, R, D>
where
    A: UserEnrollmentAuthority + Send + 'static,
    R: AuthenticationRootAuthority + Send + 'static,
    D: SecretGenerationDecryptor + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, UserEnrollmentError> {
        self.service.authenticate(headers, now)
    }
    fn issue(
        &mut self,
        actor: IdentityAdministrator,
        target: &PrincipalId,
        request: &IssueUserEnrollmentRequest,
    ) -> Result<IssueUserEnrollmentResponse, UserEnrollmentError> {
        let key = issuance_key(&self.roots)?;
        self.service.issue(actor, target, request, &key)
    }
    fn revoke(
        &mut self,
        actor: IdentityAdministrator,
        invitation: &OperationId,
        request: &RevokeUserEnrollmentRequest,
    ) -> Result<RevokeUserEnrollmentResponse, UserEnrollmentError> {
        self.service.revoke(actor, invitation, request)
    }
    fn redeem(
        &mut self,
        request: &RedeemUserEnrollmentApiKeyRequest,
        now: UnixMicros,
    ) -> Result<CreateApiKeyResponse, UserEnrollmentError> {
        let key = issuance_key(&self.roots)?;
        self.service.redeem_api_key(request, &key, now)
    }
}
fn issuance_key<R: AuthenticationRootAuthority, D: SecretGenerationDecryptor>(
    roots: &AuthenticationRootLoadingService<R, D>,
) -> Result<ApiKeyIssuanceKey, UserEnrollmentError> {
    let (key, _, _) = roots
        .load_latest()
        .map(AuthenticationRuntimeKeys::into_api_key_issuance_parts)
        .map_err(|error| match error {
            AuthenticationRootLoadingError::NotFound
            | AuthenticationRootLoadingError::NotRecipient
            | AuthenticationRootLoadingError::Unavailable => UserEnrollmentError::Unavailable,
            AuthenticationRootLoadingError::InvalidInput
            | AuthenticationRootLoadingError::Failed => UserEnrollmentError::Failed,
        })?;
    Ok(key)
}
