// SPDX-License-Identifier: GPL-2.0-only

//! Current-user recovery-code issuance composed with replicated session authority.

use axum::http::HeaderMap;
use meshspan_api_contract::{CreateRecoveryCodesRequest, CreateRecoveryCodesResponse};
use meshspan_domain::{AssuranceLevel, RecoveryCodeIssuanceKey, UnixMicros};

use crate::recovery_code_issuance_model::{
    command, context, derive_codes, method_id, operation_id, response, validate_commit,
};
use crate::{
    BrowserRequestProtection, BrowserSessionAuthenticator, GatewaySessionIdentity,
    RecoveryCodeIssuanceAuthority, RecoveryCodeIssuanceError,
};

/// Complete current-user recovery-code issuance application service.
pub struct RecoveryCodeIssuanceService<A> {
    authority: A,
    issuance_key: RecoveryCodeIssuanceKey,
    gateway: GatewaySessionIdentity,
}

impl<A> RecoveryCodeIssuanceService<A>
where
    A: RecoveryCodeIssuanceAuthority,
{
    /// Composes issuance from replicated authority and the current mesh issuance-key generation.
    #[must_use]
    pub const fn new(
        authority: A,
        issuance_key: RecoveryCodeIssuanceKey,
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

    /// Authenticates the current browser and commits or exactly replays one replacement set.
    ///
    /// # Errors
    ///
    /// Rejects malformed input, insufficient assurance, changed retries and unavailable or
    /// malformed replicated authority.
    pub fn issue(
        &mut self,
        request: &CreateRecoveryCodesRequest,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<CreateRecoveryCodesResponse, RecoveryCodeIssuanceError> {
        let operation_id = operation_id(request)?;
        let capability = BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(
                headers,
                BrowserRequestProtection::Mutation,
                AssuranceLevel::MultiFactor,
                now,
            )?;
        let codes = derive_codes(&self.issuance_key, capability.principal_id, operation_id)?;
        let method_id = method_id(capability.principal_id, operation_id)?;
        let existing = self
            .authority
            .resolve_recovery_code_issuance(operation_id)?;
        let occurred_at = existing.map_or(now, |commit| commit.created_at);
        let command = command(request, &codes, method_id, capability.principal_id)?;
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
                .commit_or_resolve_recovery_code_issuance(context, &command)?,
        };
        validate_commit(
            commit,
            expected_request_digest,
            method_id,
            capability.principal_id,
        )?;
        response(request, &codes, commit)
    }
}
