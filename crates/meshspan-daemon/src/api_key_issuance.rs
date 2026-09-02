// SPDX-License-Identifier: GPL-2.0-only

//! Current-user scoped API-key issuance composed with replicated session authority.

use axum::http::HeaderMap;
use meshspan_api_contract::{CreateApiKeyRequest, CreateApiKeyResponse};
use meshspan_domain::{
    ApiKeyBundle, ApiKeyIssuanceKey, AssuranceLevel, AuthenticationService, UnixMicros,
};
use meshspan_smb::NtlmPasswordVerifier;

use crate::api_key_issuance_model::{
    ApiKeyCommandMaterial, command, context, expiry, method_id, normalize_request, response,
    validate_commit,
};
use crate::{
    ApiKeyIssuanceAuthority, ApiKeyIssuanceError, BrowserRequestProtection,
    BrowserSessionAuthenticator, GatewaySessionIdentity, SmbVerifierBinding, SmbVerifierCipher,
    SmbVerifierEnvelopeKey,
};

/// Complete current-user API-key issuance application service.
pub struct ApiKeyIssuanceService<A> {
    authority: A,
    issuance_key: ApiKeyIssuanceKey,
    smb_verifier_cipher: SmbVerifierCipher,
    gateway: GatewaySessionIdentity,
}

impl<A> ApiKeyIssuanceService<A>
where
    A: ApiKeyIssuanceAuthority,
{
    /// Composes issuance from replicated authority and the current mesh issuance-key generation.
    ///
    /// # Errors
    ///
    /// Rejects a zero SMB verifier root generation.
    pub fn new(
        authority: A,
        issuance_key: ApiKeyIssuanceKey,
        smb_verifier_key: SmbVerifierEnvelopeKey,
        smb_verifier_generation: u64,
        gateway: GatewaySessionIdentity,
    ) -> Result<Self, ApiKeyIssuanceError> {
        Ok(Self {
            authority,
            issuance_key,
            smb_verifier_cipher: SmbVerifierCipher::new(smb_verifier_key, smb_verifier_generation)
                .map_err(|_| ApiKeyIssuanceError::Material)?,
            gateway,
        })
    }

    /// Returns the owned authority for process persistence and shutdown composition.
    #[must_use]
    pub fn into_authority(self) -> A {
        self.authority
    }

    /// Authenticates the current browser and commits or exactly replays one scoped API key.
    ///
    /// # Errors
    ///
    /// Rejects invalid scope/expiry input, stale session evidence, changed retries and
    /// unavailable or malformed replicated authority.
    pub fn issue(
        &mut self,
        request: &CreateApiKeyRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateApiKeyResponse, ApiKeyIssuanceError> {
        issue_api_key_with(
            &mut self.authority,
            &self.issuance_key,
            &self.smb_verifier_cipher,
            self.gateway,
            request,
            headers,
            now,
        )
    }
}

pub(crate) fn issue_api_key_with<A>(
    authority: &mut A,
    issuance_key: &ApiKeyIssuanceKey,
    smb_verifier_cipher: &SmbVerifierCipher,
    gateway: GatewaySessionIdentity,
    request: &CreateApiKeyRequest,
    headers: &HeaderMap,
    now: UnixMicros,
) -> Result<CreateApiKeyResponse, ApiKeyIssuanceError>
where
    A: ApiKeyIssuanceAuthority,
{
    let normalized = normalize_request(request)?;
    let capability = BrowserSessionAuthenticator::new(&*authority, gateway).authenticate(
        headers,
        BrowserRequestProtection::Mutation,
        AssuranceLevel::SingleFactor,
        now,
    )?;
    let key = ApiKeyBundle::derive_issued(
        issuance_key,
        capability.principal_id,
        normalized.operation_id,
    )
    .map_err(|_| ApiKeyIssuanceError::Material)?;
    let method_id = method_id(capability.principal_id, normalized.operation_id)?;
    let smb_verifier_ciphertext = smb_verifier(
        smb_verifier_cipher,
        &key,
        method_id,
        capability.principal_id,
        normalized.service_scope,
        normalized.scope_bits,
    )?;
    let existing = authority.resolve_api_key_issuance(normalized.operation_id)?;
    let occurred_at = existing.map_or(now, |commit| commit.created_at);
    let expires_at = expiry(request, occurred_at)?;
    let command = command(
        request,
        &normalized,
        ApiKeyCommandMaterial {
            key: &key,
            method_id,
            principal_id: capability.principal_id,
            created_at: occurred_at,
            expires_at,
            smb_verifier_ciphertext,
        },
    );
    let context = context(
        normalized.operation_id,
        capability.principal_id,
        &key,
        occurred_at,
    )?;
    let expected_request_digest = command.request_digest(context);
    let commit = match existing {
        Some(commit) => commit,
        None => authority.commit_or_resolve_api_key_issuance(context, &command)?,
    };
    validate_commit(
        commit,
        expected_request_digest,
        method_id,
        capability.principal_id,
    )?;
    response(request, normalized, &key, commit, expires_at)
}

fn smb_verifier(
    cipher: &SmbVerifierCipher,
    key: &ApiKeyBundle,
    method_id: meshspan_domain::AuthenticationMethodId,
    principal_id: meshspan_domain::PrincipalId,
    service_scope: u8,
    scopes: u64,
) -> Result<Option<Vec<u8>>, ApiKeyIssuanceError> {
    if service_scope & AuthenticationService::Smb.scope_bit() == 0 {
        return Ok(None);
    }
    let verifier = NtlmPasswordVerifier::derive(key.expose_encoded().as_str())
        .map_err(|_| ApiKeyIssuanceError::Material)?;
    cipher
        .encrypt(
            SmbVerifierBinding {
                method_id,
                principal_id,
                key_id: key.key_id(),
                service_scope,
                scopes,
            },
            &verifier,
        )
        .map(Some)
        .map_err(|_| ApiKeyIssuanceError::Material)
}
