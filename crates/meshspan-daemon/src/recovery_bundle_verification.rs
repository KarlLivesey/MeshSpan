// SPDX-License-Identifier: GPL-2.0-only

//! Manager-authenticated transition proving an exact offline recovery bundle was saved.

use std::path::PathBuf;

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{ConfirmRecoveryBundleRequest, ConfirmRecoveryBundleResponse};
use meshspan_domain::{AuditEventId, MeshId, OperationId, PrincipalId, UnixMicros, uuid_v8};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, ConfirmRecoveryBundleSaved, MeshRecoveryAuthority,
    RecoveryBundleState,
};
use meshspan_recovery_bundle::RecoveryChallenge;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::create_mesh_setup::{format_uuid, parse_uuid};
use crate::{
    BrowserRequestProtection, BrowserSessionAuthenticator, BrowserSessionAuthority,
    FileApiAuthenticationError, GatewaySessionIdentity, IdentityAdministrator,
    NativeApiKeyAuthenticator, NativeApiKeyAuthority, PendingRecoveryBundle,
    PendingRecoveryBundleError,
};

const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.recovery-bundle-verification.audit-id.v1\0";

/// Exact durable evidence returned for one recovery-bundle verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryBundleVerificationCommit {
    /// Canonical semantic request digest accepted by consensus.
    pub request_digest: [u8; 32],
    /// Non-zero result digest retained for exact replay.
    pub result_digest: [u8; 32],
    /// Verified recovery authority at the command's exact committed revision.
    pub authority: MeshRecoveryAuthority,
}

/// Replicated reads and consensus mutation needed by save verification.
pub trait RecoveryBundleVerificationAuthority:
    BrowserSessionAuthority + NativeApiKeyAuthority
{
    /// Reports current system-manager authority.
    ///
    /// # Errors
    ///
    /// Fails closed when the current role projection cannot be trusted.
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, RecoveryBundleVerificationAuthorityError>;

    /// Returns the current exact public recovery authority for one mesh.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable or corrupt committed state.
    fn recovery_authority(
        &self,
        mesh_id: MeshId,
    ) -> Result<Option<MeshRecoveryAuthority>, RecoveryBundleVerificationAuthorityError>;

    /// Resolves one prior save-verification operation.
    ///
    /// # Errors
    ///
    /// Rejects another command family or malformed retained evidence.
    fn resolve_recovery_bundle_verification(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<RecoveryBundleVerificationCommit>, RecoveryBundleVerificationAuthorityError>;

    /// Commits or exactly resolves one save-verification command through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never invents success from transport outcome.
    fn commit_or_resolve_recovery_bundle_verification(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<RecoveryBundleVerificationCommit, RecoveryBundleVerificationAuthorityError>;
}

/// Synchronous manager-only controller executed on Tokio's bounded blocking pool.
pub trait RecoveryBundleVerificationController: Send + 'static {
    /// Authenticates and proves current manager authority before body consumption.
    ///
    /// # Errors
    ///
    /// Rejects missing, ambiguous, stale or insufficient credentials and unavailable authority.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, RecoveryBundleVerificationError>;

    /// Verifies or exactly replays one bundle save and removes only its matching pending file.
    ///
    /// # Errors
    ///
    /// Rejects invalid proof, changed retries, unavailable consensus and unsafe local evidence.
    fn confirm_saved(
        &mut self,
        administrator: IdentityAdministrator,
        request: ConfirmRecoveryBundleRequest,
    ) -> Result<ConfirmRecoveryBundleResponse, RecoveryBundleVerificationError>;
}

/// Complete recovery-bundle save-verification application service.
pub struct RecoveryBundleVerificationService<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
    pending_bundle_path: PathBuf,
}

impl<A> RecoveryBundleVerificationService<A> {
    /// Binds current authentication, replicated authority and exact local pending-bundle location.
    #[must_use]
    pub fn new(
        authority: A,
        gateway: GatewaySessionIdentity,
        pending_bundle_path: PathBuf,
    ) -> Self {
        Self {
            authority,
            gateway,
            pending_bundle_path,
        }
    }

    #[cfg(test)]
    pub(crate) fn into_authority(self) -> A {
        self.authority
    }
}

impl<A> RecoveryBundleVerificationController for RecoveryBundleVerificationService<A>
where
    A: RecoveryBundleVerificationAuthority + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, RecoveryBundleVerificationError> {
        let has_authorization = headers.contains_key(AUTHORIZATION);
        if has_authorization && headers.contains_key(COOKIE) {
            return Err(RecoveryBundleVerificationError::Unauthenticated);
        }
        let principal_id = if has_authorization {
            NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
                .authenticate_principal(headers, now)
                .map_err(map_file_authentication_error)?
        } else {
            BrowserSessionAuthenticator::new(&self.authority, self.gateway)
                .authenticate(
                    headers,
                    BrowserRequestProtection::Mutation,
                    meshspan_domain::AssuranceLevel::SingleFactor,
                    now,
                )
                .map_err(map_browser_authentication_error)?
                .principal_id
        };
        if !self
            .authority
            .is_system_manager(principal_id, now)
            .map_err(map_authority_error)?
        {
            return Err(RecoveryBundleVerificationError::Forbidden);
        }
        Ok(IdentityAdministrator { principal_id, now })
    }

    fn confirm_saved(
        &mut self,
        administrator: IdentityAdministrator,
        request: ConfirmRecoveryBundleRequest,
    ) -> Result<ConfirmRecoveryBundleResponse, RecoveryBundleVerificationError> {
        let operation_id = domain_operation(&request.operation_id)?;
        let mesh_id = domain_mesh(&request.mesh_id)?;
        let challenge = RecoveryChallenge::parse(&request.recovery_challenge)
            .map_err(|_| RecoveryBundleVerificationError::InvalidInput)?;
        let existing = self
            .authority
            .resolve_recovery_bundle_verification(operation_id)
            .map_err(map_authority_error)?;
        let current = self
            .authority
            .recovery_authority(mesh_id)
            .map_err(map_authority_error)?
            .ok_or(RecoveryBundleVerificationError::Conflict)?;
        validate_operation_target(existing.as_ref(), &current, mesh_id)?;
        let occurred_at = existing
            .as_ref()
            .and_then(|commit| commit.authority.verified_at)
            .unwrap_or(administrator.now);
        let command =
            AuthoritativeCommand::ConfirmRecoveryBundleSaved(ConfirmRecoveryBundleSaved {
                mesh_id,
                bundle_digest: current.bundle_digest,
                save_challenge_commitment: challenge.commitment(),
            });
        let context = command_context(operation_id, administrator, occurred_at)?;
        let expected_digest = command.request_digest(context);
        let commit = match existing {
            Some(value) => value,
            None => self
                .authority
                .commit_or_resolve_recovery_bundle_verification(context, &command)
                .map_err(map_authority_error)?,
        };
        validate_commit(&commit, expected_digest, mesh_id, current.bundle_digest)?;
        PendingRecoveryBundle::remove_if_matches(
            &self.pending_bundle_path,
            mesh_id,
            commit.authority.bundle_digest,
        )
        .map_err(|error| map_pending_bundle_error(&error))?;
        let verified_at = commit
            .authority
            .verified_at
            .ok_or(RecoveryBundleVerificationError::Failed)?;
        Ok(ConfirmRecoveryBundleResponse {
            operation_id: request.operation_id,
            mesh_id: format_uuid(mesh_id.as_bytes()),
            verified_at_epoch_micros: verified_at.get(),
            revision: commit.authority.revision.get(),
        })
    }
}

fn validate_operation_target(
    existing: Option<&RecoveryBundleVerificationCommit>,
    current: &MeshRecoveryAuthority,
    requested_mesh_id: MeshId,
) -> Result<(), RecoveryBundleVerificationError> {
    if current.mesh_id != requested_mesh_id {
        return Err(RecoveryBundleVerificationError::Failed);
    }
    match existing {
        Some(commit)
            if commit.authority.mesh_id == requested_mesh_id
                && commit.authority.bundle_digest == current.bundle_digest =>
        {
            Ok(())
        }
        None if current.state == RecoveryBundleState::Pending => Ok(()),
        Some(_) | None => Err(RecoveryBundleVerificationError::Conflict),
    }
}

fn validate_commit(
    commit: &RecoveryBundleVerificationCommit,
    expected_request_digest: [u8; 32],
    mesh_id: MeshId,
    bundle_digest: [u8; 32],
) -> Result<(), RecoveryBundleVerificationError> {
    if commit.request_digest != expected_request_digest
        || commit.result_digest == [0; 32]
        || commit.authority.mesh_id != mesh_id
        || commit.authority.bundle_digest != bundle_digest
        || commit.authority.state != RecoveryBundleState::Verified
        || commit.authority.verified_by.is_none()
        || commit.authority.verified_at.is_none()
        || commit.authority.revision.get() == 0
    {
        Err(RecoveryBundleVerificationError::Conflict)
    } else {
        Ok(())
    }
}

fn domain_operation(
    value: &meshspan_api_contract::OperationId,
) -> Result<OperationId, RecoveryBundleVerificationError> {
    OperationId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| RecoveryBundleVerificationError::InvalidInput)?,
    )
    .map_err(|_| RecoveryBundleVerificationError::InvalidInput)
}

fn domain_mesh(value: &str) -> Result<MeshId, RecoveryBundleVerificationError> {
    MeshId::from_bytes(
        parse_uuid(value).map_err(|_| RecoveryBundleVerificationError::InvalidInput)?,
    )
    .map_err(|_| RecoveryBundleVerificationError::InvalidInput)
}

fn command_context(
    operation_id: OperationId,
    administrator: IdentityAdministrator,
    occurred_at: UnixMicros,
) -> Result<CommandContext, RecoveryBundleVerificationError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(administrator.principal_id.as_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map(uuid_v8)
        .map_err(|_| RecoveryBundleVerificationError::Failed)?;
    Ok(CommandContext {
        operation_id,
        actor_principal_id: administrator.principal_id,
        audit_event_id: AuditEventId::from_bytes(bytes)
            .map_err(|_| RecoveryBundleVerificationError::Failed)?,
        occurred_at,
        expected_revision: None,
    })
}

fn map_file_authentication_error(
    error: FileApiAuthenticationError,
) -> RecoveryBundleVerificationError {
    match error {
        FileApiAuthenticationError::Rejected => RecoveryBundleVerificationError::Unauthenticated,
        FileApiAuthenticationError::AuthorityUnavailable => {
            RecoveryBundleVerificationError::Unavailable
        }
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => RecoveryBundleVerificationError::Failed,
    }
}

fn map_browser_authentication_error(
    error: crate::BrowserAuthenticationError,
) -> RecoveryBundleVerificationError {
    match error {
        crate::BrowserAuthenticationError::Rejected => {
            RecoveryBundleVerificationError::Unauthenticated
        }
        crate::BrowserAuthenticationError::Authority(
            crate::BrowserSessionAuthorityError::Unavailable,
        ) => RecoveryBundleVerificationError::Unavailable,
        crate::BrowserAuthenticationError::InvalidGateway
        | crate::BrowserAuthenticationError::Authority(
            crate::BrowserSessionAuthorityError::Failed,
        ) => RecoveryBundleVerificationError::Failed,
    }
}

fn map_authority_error(
    error: RecoveryBundleVerificationAuthorityError,
) -> RecoveryBundleVerificationError {
    match error {
        RecoveryBundleVerificationAuthorityError::Unavailable => {
            RecoveryBundleVerificationError::Unavailable
        }
        RecoveryBundleVerificationAuthorityError::Conflict => {
            RecoveryBundleVerificationError::Conflict
        }
        RecoveryBundleVerificationAuthorityError::Failed => RecoveryBundleVerificationError::Failed,
    }
}

fn map_pending_bundle_error(error: &PendingRecoveryBundleError) -> RecoveryBundleVerificationError {
    match error {
        PendingRecoveryBundleError::Conflict => RecoveryBundleVerificationError::Conflict,
        PendingRecoveryBundleError::File | PendingRecoveryBundleError::Bundle(_) => {
            RecoveryBundleVerificationError::Failed
        }
    }
}

/// Closed replicated-authority failure safe for public classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecoveryBundleVerificationAuthorityError {
    /// Current consensus projection or leader is unavailable.
    #[error("recovery-bundle verification authority is unavailable")]
    Unavailable,
    /// Proof, mesh, operation or command conflicts with committed state.
    #[error("recovery-bundle verification operation conflicts")]
    Conflict,
    /// Persisted evidence or an invariant failed closed.
    #[error("recovery-bundle verification authority failed closed")]
    Failed,
}

/// Closed manager-only recovery-bundle verification outcome.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecoveryBundleVerificationError {
    /// Public identifiers or challenge are invalid.
    #[error("recovery-bundle verification input is invalid")]
    InvalidInput,
    /// No current credential was accepted.
    #[error("recovery-bundle verification authentication was rejected")]
    Unauthenticated,
    /// The current principal lacks system-manager authority.
    #[error("recovery-bundle verification authority was denied")]
    Forbidden,
    /// Proof, mesh, pending file or operation conflicts with committed state.
    #[error("recovery-bundle verification operation conflicts")]
    Conflict,
    /// Current consensus authority is temporarily unavailable.
    #[error("recovery-bundle verification authority is unavailable")]
    Unavailable,
    /// Persisted evidence, local cleanup or response construction failed closed.
    #[error("recovery-bundle verification failed closed")]
    Failed,
}
