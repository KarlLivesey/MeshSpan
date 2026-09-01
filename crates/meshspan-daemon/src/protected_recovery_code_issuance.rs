// SPDX-License-Identifier: GPL-2.0-only

//! Request-time recovery-code issuance from the current recipient-bound authentication root.

use axum::http::HeaderMap;
use meshspan_api_contract::{CreateRecoveryCodesRequest, CreateRecoveryCodesResponse};
use meshspan_domain::UnixMicros;

use crate::{
    AuthenticationRootAuthority, AuthenticationRootLoadingError, AuthenticationRootLoadingService,
    AuthenticationRuntimeKeys, GatewaySessionIdentity, RecoveryCodeIssuanceAuthority,
    RecoveryCodeIssuanceAuthorityError, RecoveryCodeIssuanceController, RecoveryCodeIssuanceError,
    SecretGenerationDecryptor, recovery_code_issuance::issue_recovery_codes_with,
};

/// Live issuance controller which retains no decrypted root or derived key between requests.
pub struct ProtectedRecoveryCodeIssuanceController<A, R, D> {
    authority: A,
    roots: AuthenticationRootLoadingService<R, D>,
    gateway: GatewaySessionIdentity,
}

impl<A, R, D> ProtectedRecoveryCodeIssuanceController<A, R, D> {
    /// Binds issuance mutations, replicated root reads and one node-local wrapping key.
    #[must_use]
    pub const fn new(
        authority: A,
        root_authority: R,
        decryptor: D,
        gateway: GatewaySessionIdentity,
    ) -> Self {
        Self {
            authority,
            roots: AuthenticationRootLoadingService::new(root_authority, decryptor),
            gateway,
        }
    }
}

impl<A, R, D> RecoveryCodeIssuanceController for ProtectedRecoveryCodeIssuanceController<A, R, D>
where
    A: RecoveryCodeIssuanceAuthority + Send + 'static,
    R: AuthenticationRootAuthority + Send + 'static,
    D: SecretGenerationDecryptor + Send + 'static,
{
    fn issue_recovery_codes(
        &mut self,
        request: &CreateRecoveryCodesRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateRecoveryCodesResponse, RecoveryCodeIssuanceError> {
        let issuance_key = self
            .roots
            .load_latest()
            .map(AuthenticationRuntimeKeys::into_recovery_code_issuance_key)
            .map_err(map_loading_error)?;
        issue_recovery_codes_with(
            &mut self.authority,
            &issuance_key,
            self.gateway,
            request,
            headers,
            now,
        )
    }
}

const fn map_loading_error(error: AuthenticationRootLoadingError) -> RecoveryCodeIssuanceError {
    match error {
        AuthenticationRootLoadingError::NotFound
        | AuthenticationRootLoadingError::NotRecipient
        | AuthenticationRootLoadingError::Unavailable => {
            RecoveryCodeIssuanceError::Authority(RecoveryCodeIssuanceAuthorityError::Unavailable)
        }
        AuthenticationRootLoadingError::InvalidInput | AuthenticationRootLoadingError::Failed => {
            RecoveryCodeIssuanceError::Material
        }
    }
}
