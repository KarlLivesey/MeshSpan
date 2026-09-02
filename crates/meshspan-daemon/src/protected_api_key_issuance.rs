// SPDX-License-Identifier: GPL-2.0-only

//! Request-time API-key issuance from the current recipient-bound authentication root.

use axum::http::HeaderMap;
use meshspan_api_contract::{CreateApiKeyRequest, CreateApiKeyResponse};
use meshspan_domain::UnixMicros;

use crate::api_key_issuance::issue_api_key_with;
use crate::{
    ApiKeyIssuanceAuthority, ApiKeyIssuanceAuthorityError, ApiKeyIssuanceController,
    ApiKeyIssuanceError, AuthenticationRootAuthority, AuthenticationRootLoadingError,
    AuthenticationRootLoadingService, AuthenticationRuntimeKeys, GatewaySessionIdentity,
    SecretGenerationDecryptor,
};

/// Live issuance controller which retains no decrypted root or derived key between requests.
pub struct ProtectedApiKeyIssuanceController<A, R, D> {
    authority: A,
    roots: AuthenticationRootLoadingService<R, D>,
    gateway: GatewaySessionIdentity,
}

impl<A, R, D> ProtectedApiKeyIssuanceController<A, R, D> {
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

impl<A, R, D> ApiKeyIssuanceController for ProtectedApiKeyIssuanceController<A, R, D>
where
    A: ApiKeyIssuanceAuthority + Send + 'static,
    R: AuthenticationRootAuthority + Send + 'static,
    D: SecretGenerationDecryptor + Send + 'static,
{
    fn issue_api_key(
        &mut self,
        request: &CreateApiKeyRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateApiKeyResponse, ApiKeyIssuanceError> {
        let (issuance_key, smb_verifier_key, smb_verifier_generation) = self
            .roots
            .load_latest()
            .map(AuthenticationRuntimeKeys::into_api_key_issuance_parts)
            .map_err(map_loading_error)?;
        let smb_verifier_cipher =
            crate::SmbVerifierCipher::new(smb_verifier_key, smb_verifier_generation)
                .map_err(|_| ApiKeyIssuanceError::Material)?;
        issue_api_key_with(
            &mut self.authority,
            &issuance_key,
            &smb_verifier_cipher,
            self.gateway,
            request,
            headers,
            now,
        )
    }
}

const fn map_loading_error(error: AuthenticationRootLoadingError) -> ApiKeyIssuanceError {
    match error {
        AuthenticationRootLoadingError::NotFound
        | AuthenticationRootLoadingError::NotRecipient
        | AuthenticationRootLoadingError::Unavailable => {
            ApiKeyIssuanceError::Authority(ApiKeyIssuanceAuthorityError::Unavailable)
        }
        AuthenticationRootLoadingError::InvalidInput | AuthenticationRootLoadingError::Failed => {
            ApiKeyIssuanceError::Material
        }
    }
}
