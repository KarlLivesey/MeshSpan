// SPDX-License-Identifier: GPL-2.0-only

//! Current-user authentication-method revocation composed with replicated authority.

use axum::http::HeaderMap;
use meshspan_api_contract::{
    AuthenticationMethodId, RevokeAuthenticationMethodRequest, RevokeAuthenticationMethodResponse,
};
use meshspan_domain::{AssuranceLevel, UnixMicros};

use crate::authentication_method_revocation_model::{
    command, context, method_id, operation_id, response, validate_commit,
};
use crate::{
    AuthenticationMethodRevocationAuthority, AuthenticationMethodRevocationError,
    BrowserRequestProtection, BrowserSessionAuthenticator, GatewaySessionIdentity,
};

/// Complete current-user authentication-method revocation application service.
pub struct AuthenticationMethodRevocationService<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A> AuthenticationMethodRevocationService<A>
where
    A: AuthenticationMethodRevocationAuthority,
{
    /// Composes revocation from replicated authority and a live gateway incarnation.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }

    /// Returns the owned authority for process persistence and shutdown composition.
    #[must_use]
    pub fn into_authority(self) -> A {
        self.authority
    }

    /// Authenticates the current browser and commits or exactly replays one owned revocation.
    ///
    /// # Errors
    ///
    /// Rejects invalid identifiers, stale session evidence, non-owned methods, changed retries and
    /// unavailable or malformed replicated authority.
    pub fn revoke(
        &mut self,
        public_method_id: &AuthenticationMethodId,
        request: &RevokeAuthenticationMethodRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<RevokeAuthenticationMethodResponse, AuthenticationMethodRevocationError> {
        let operation_id = operation_id(request)?;
        let method_id = method_id(public_method_id)?;
        let capability = BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(
                headers,
                BrowserRequestProtection::Mutation,
                AssuranceLevel::SingleFactor,
                now,
            )?;
        let existing = self
            .authority
            .resolve_authentication_method_revocation(operation_id)?;
        let occurred_at = existing.map_or(now, |commit| commit.revoked_at);
        let command = command(request, method_id, capability.principal_id)?;
        let context = context(
            operation_id,
            capability.principal_id,
            method_id,
            occurred_at,
        )?;
        let expected_request_digest = command.request_digest(context);
        let commit = match existing {
            Some(commit) => commit,
            None => self
                .authority
                .commit_or_resolve_authentication_method_revocation(context, &command)?,
        };
        validate_commit(
            commit,
            expected_request_digest,
            method_id,
            capability.principal_id,
        )?;
        response(request, commit)
    }
}
