// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-backed authentication authority for public gateway services.

use std::sync::Arc;

use meshspan_cluster::{MetadataAuthorityHandle, MetadataAuthorityRequestError};
use meshspan_domain::{
    ApiKeyId, AssuranceLevel, AuthenticationOperationClass, AuthenticationService, OperationId,
    PrincipalId, RecoveryCodeId, SessionId, UnixMicros,
};
use meshspan_metadata::{
    ApiKeyAuthentication, ApiKeySessionReplay, AuthenticationPolicy, AuthenticationSessionReplay,
    AuthoritativeCommand, AuthoritativeRepository, BrowserSessionAccessRequest, CommandContext,
    CommandReceipt, PasskeySessionReplay, PasskeyVerificationMaterial,
    RecoveryCodeVerificationMaterial, RepositoryError, SessionAccessDecision,
    SessionRevocationReplay, TotpVerificationMaterial,
};

use crate::{
    BrowserSessionAuthority, BrowserSessionAuthorityError, NativeApiKeyAuthority,
    NativeApiKeyAuthorityError, SessionAuthority, SessionAuthorityError, SessionCommit,
    SessionRevocationAuthority, SessionRevocationAuthorityError, SessionRevocationCommit,
    StepUpSessionAuthority,
};

/// Current authentication reads plus consensus-owned authentication mutations.
///
/// The repository is a dedicated SQLite connection used only through immutable query methods.
/// The consensus reactor owns a separate writer connection. Public API controllers invoke this
/// adapter on Tokio's blocking pool, so waiting for the asynchronous reactor does not block an
/// executor worker.
pub struct ConsensusAuthenticationAuthority {
    reader: AuthoritativeRepository,
    authority: MetadataAuthorityHandle,
    runtime: tokio::runtime::Handle,
    network: Option<Arc<crate::private_consensus_runtime::PrivateConsensusRuntime>>,
}

impl ConsensusAuthenticationAuthority {
    /// Binds one read connection and one consensus mutation ingress.
    #[must_use]
    pub const fn new(
        reader: AuthoritativeRepository,
        authority: MetadataAuthorityHandle,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            reader,
            authority,
            runtime,
            network: None,
        }
    }

    /// Binds the authority with authenticated leader forwarding for non-leader gateways.
    #[must_use]
    pub(crate) const fn new_routable(
        reader: AuthoritativeRepository,
        authority: MetadataAuthorityHandle,
        runtime: tokio::runtime::Handle,
        network: Arc<crate::private_consensus_runtime::PrivateConsensusRuntime>,
    ) -> Self {
        Self {
            reader,
            authority,
            runtime,
            network: Some(network),
        }
    }

    pub(crate) const fn reader(&self) -> &AuthoritativeRepository {
        &self.reader
    }

    pub(crate) fn commit_authoritative(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        match self
            .runtime
            .block_on(self.authority.commit_or_resolve(context, command.clone()))
        {
            Err(MetadataAuthorityRequestError::NotLeader { leader_id }) => {
                match self.network.as_ref() {
                    Some(network) => {
                        self.runtime
                            .block_on(crate::metadata_forwarding::forward_to_authority(
                                network,
                                &self.reader,
                                leader_id,
                                context,
                                command,
                            ))
                    }
                    None => Err(MetadataAuthorityRequestError::NotLeader { leader_id }),
                }
            }
            outcome => outcome,
        }
    }
}

impl SessionAuthority for ConsensusAuthenticationAuthority {
    fn authenticate_api_key(
        &self,
        key_id: ApiKeyId,
        digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<Option<ApiKeyAuthentication>, SessionAuthorityError> {
        self.reader
            .authenticate_api_key(
                digest,
                AuthenticationService::Https,
                AuthenticationService::Https.api_key_login_scope(),
                now,
            )
            .map(|authentication| authentication.filter(|value| value.key_id == key_id))
            .map_err(|error| map_session_repository_error(&error))
    }

    fn passkey_verification_material(
        &self,
        credential_id: &[u8],
        now: UnixMicros,
    ) -> Result<Option<PasskeyVerificationMaterial>, SessionAuthorityError> {
        self.reader
            .passkey_verification_material(credential_id, AuthenticationService::Https, now)
            .map_err(|error| map_session_repository_error(&error))
    }

    fn totp_verification_materials(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<Vec<TotpVerificationMaterial>, SessionAuthorityError> {
        self.reader
            .totp_verification_materials(principal_id, AuthenticationService::Https, now)
            .map_err(|error| map_session_repository_error(&error))
    }

    fn recovery_code_verification_material(
        &self,
        principal_id: PrincipalId,
        code_id: RecoveryCodeId,
        digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<Option<RecoveryCodeVerificationMaterial>, SessionAuthorityError> {
        self.reader
            .recovery_code_verification_material(
                principal_id,
                code_id,
                digest,
                AuthenticationService::Https,
                now,
            )
            .map_err(|error| map_session_repository_error(&error))
    }

    fn session_policy(&self) -> Result<AuthenticationPolicy, SessionAuthorityError> {
        self.reader
            .authentication_policy(
                AuthenticationService::Https,
                AuthenticationOperationClass::SessionEstablishment,
            )
            .map_err(|error| map_session_repository_error(&error))
    }

    fn resolve_api_key_session(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ApiKeySessionReplay>, SessionAuthorityError> {
        self.reader
            .resolve_api_key_session(operation_id)
            .map_err(|error| map_session_repository_error(&error))
    }

    fn resolve_passkey_session(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<PasskeySessionReplay>, SessionAuthorityError> {
        self.reader
            .resolve_passkey_session(operation_id)
            .map_err(|error| map_session_repository_error(&error))
    }

    fn resolve_authentication_session(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<AuthenticationSessionReplay>, SessionAuthorityError> {
        self.reader
            .resolve_authentication_session(operation_id)
            .map_err(|error| map_session_repository_error(&error))
    }

    fn commit_or_resolve(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<SessionCommit, SessionAuthorityError> {
        self.commit_authoritative(context, command)
            .map(|receipt| SessionCommit {
                result_digest: receipt.result_digest,
            })
            .map_err(map_session_authority_error)
    }
}

impl BrowserSessionAuthority for ConsensusAuthenticationAuthority {
    fn evaluate_browser_session(
        &self,
        request: BrowserSessionAccessRequest,
    ) -> Result<SessionAccessDecision, BrowserSessionAuthorityError> {
        self.reader
            .evaluate_browser_session_access(request)
            .map_err(|error| map_browser_repository_error(&error))
    }
}

impl NativeApiKeyAuthority for ConsensusAuthenticationAuthority {
    fn authenticate_native_api_key(
        &self,
        key_id: ApiKeyId,
        digest: [u8; 32],
        required_assurance: AssuranceLevel,
        now: UnixMicros,
    ) -> Result<Option<ApiKeyAuthentication>, NativeApiKeyAuthorityError> {
        self.reader
            .authenticate_api_key_for_operation(
                digest,
                AuthenticationService::HeadlessApi,
                AuthenticationService::HeadlessApi.api_key_login_scope(),
                required_assurance,
                now,
            )
            .map(|authentication| authentication.filter(|value| value.key_id == key_id))
            .map_err(|error| map_native_repository_error(&error))
    }
}

impl StepUpSessionAuthority for ConsensusAuthenticationAuthority {
    fn resolve_step_up_session(
        &self,
        operation_id: OperationId,
        source_session_id: SessionId,
        source_token_digest: [u8; 32],
        source_csrf_digest: [u8; 32],
    ) -> Result<Option<AuthenticationSessionReplay>, SessionAuthorityError> {
        self.reader
            .resolve_step_up_session(
                operation_id,
                source_session_id,
                source_token_digest,
                source_csrf_digest,
            )
            .map_err(|error| map_session_repository_error(&error))
    }
}

impl SessionRevocationAuthority for ConsensusAuthenticationAuthority {
    fn resolve_revocation(
        &self,
        operation_id: OperationId,
        session_id: SessionId,
        token_digest: [u8; 32],
        csrf_digest: [u8; 32],
    ) -> Result<Option<SessionRevocationReplay>, SessionRevocationAuthorityError> {
        self.reader
            .resolve_session_revocation(operation_id, session_id, token_digest, csrf_digest)
            .map_err(|error| map_revocation_repository_error(&error))
    }

    fn commit_or_resolve_revocation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<SessionRevocationCommit, SessionRevocationAuthorityError> {
        self.commit_authoritative(context, command)
            .map(|receipt| SessionRevocationCommit {
                result_digest: receipt.result_digest,
            })
            .map_err(map_revocation_authority_error)
    }
}

fn map_session_repository_error(error: &RepositoryError) -> SessionAuthorityError {
    if repository_is_unavailable(error) {
        SessionAuthorityError::Unavailable
    } else if matches!(error, RepositoryError::OperationConflict) {
        SessionAuthorityError::Conflict
    } else {
        SessionAuthorityError::Failed
    }
}

fn map_browser_repository_error(error: &RepositoryError) -> BrowserSessionAuthorityError {
    if repository_is_unavailable(error) {
        BrowserSessionAuthorityError::Unavailable
    } else {
        BrowserSessionAuthorityError::Failed
    }
}

fn map_native_repository_error(error: &RepositoryError) -> NativeApiKeyAuthorityError {
    if repository_is_unavailable(error) {
        NativeApiKeyAuthorityError::Unavailable
    } else {
        NativeApiKeyAuthorityError::Failed
    }
}

fn map_revocation_repository_error(error: &RepositoryError) -> SessionRevocationAuthorityError {
    if repository_is_unavailable(error) {
        SessionRevocationAuthorityError::Unavailable
    } else if matches!(error, RepositoryError::OperationConflict) {
        SessionRevocationAuthorityError::Conflict
    } else {
        SessionRevocationAuthorityError::Failed
    }
}

fn repository_is_unavailable(error: &RepositoryError) -> bool {
    matches!(
        error,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_)
    )
}

fn map_session_authority_error(error: MetadataAuthorityRequestError) -> SessionAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => SessionAuthorityError::Unavailable,
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            SessionAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            SessionAuthorityError::Failed
        }
    }
}

fn map_revocation_authority_error(
    error: MetadataAuthorityRequestError,
) -> SessionRevocationAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            SessionRevocationAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            SessionRevocationAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            SessionRevocationAuthorityError::Failed
        }
    }
}
