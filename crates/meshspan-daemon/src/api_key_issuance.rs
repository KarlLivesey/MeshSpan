// SPDX-License-Identifier: GPL-2.0-only

//! Current-user scoped API-key issuance composed with replicated session authority.

use axum::http::HeaderMap;
use meshspan_api_contract::{CreateApiKeyRequest, CreateApiKeyResponse};
use meshspan_domain::{ApiKeyBundle, ApiKeyIssuanceKey, AssuranceLevel, UnixMicros};

use crate::api_key_issuance_model::{
    command, context, expiry, method_id, normalize_request, response, validate_commit,
};
use crate::{
    ApiKeyIssuanceAuthority, ApiKeyIssuanceError, BrowserRequestProtection,
    BrowserSessionAuthenticator, GatewaySessionIdentity,
};

/// Complete current-user API-key issuance application service.
pub struct ApiKeyIssuanceService<A> {
    authority: A,
    issuance_key: ApiKeyIssuanceKey,
    gateway: GatewaySessionIdentity,
}

impl<A> ApiKeyIssuanceService<A>
where
    A: ApiKeyIssuanceAuthority,
{
    /// Composes issuance from replicated authority and the current mesh issuance-key generation.
    #[must_use]
    pub const fn new(
        authority: A,
        issuance_key: ApiKeyIssuanceKey,
        gateway: GatewaySessionIdentity,
    ) -> Self {
        Self {
            authority,
            issuance_key,
            gateway,
        }
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
        let normalized = normalize_request(request)?;
        let capability = BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(
                headers,
                BrowserRequestProtection::Mutation,
                AssuranceLevel::SingleFactor,
                now,
            )?;
        let key = ApiKeyBundle::derive_issued(
            &self.issuance_key,
            capability.principal_id,
            normalized.operation_id,
        )
        .map_err(|_| ApiKeyIssuanceError::Material)?;
        let method_id = method_id(capability.principal_id, normalized.operation_id)?;
        let existing = self
            .authority
            .resolve_api_key_issuance(normalized.operation_id)?;
        let occurred_at = existing.map_or(now, |commit| commit.created_at);
        let expires_at = expiry(request, occurred_at)?;
        let command = command(
            request,
            &normalized,
            &key,
            method_id,
            capability.principal_id,
            occurred_at,
            expires_at,
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
            None => self
                .authority
                .commit_or_resolve_api_key_issuance(context, &command)?,
        };
        validate_commit(
            commit,
            expected_request_digest,
            method_id,
            capability.principal_id,
        )?;
        response(request, normalized, &key, commit, expires_at)
    }
}
