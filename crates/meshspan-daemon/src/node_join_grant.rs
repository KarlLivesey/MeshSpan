// SPDX-License-Identifier: GPL-2.0-only

//! Manager-authenticated, exactly replayable node join-grant issuance.

use std::collections::BTreeSet;

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{
    CreateNodeJoinGrantRequest, CreateNodeJoinGrantResponse, NodeJoinRole,
};
use meshspan_domain::{
    AssuranceLevel, AuditEventId, DurationMicros, JoinGrantBundle, JoinGrantId, MeshId,
    OperationId, PrincipalId, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, IssueJoinGrant, JoinGrantRecord, JoinRoles,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::create_mesh_setup::parse_uuid;
use crate::{
    AuthenticationRootAuthority, AuthenticationRootLoadingError, AuthenticationRootLoadingService,
    AuthenticationRuntimeKeys, BrowserAuthenticationError, BrowserRequestProtection,
    BrowserSessionAuthenticator, BrowserSessionAuthority, FileApiAuthenticationError,
    GatewaySessionIdentity, IdentityAdministrator, NativeApiKeyAuthenticator,
    NativeApiKeyAuthority, SecretGenerationDecryptor,
};

const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.enrolment.join-grant-audit-id.v1\0";
const MICROS_PER_SECOND: u64 = 1_000_000;

/// Exact durable evidence for one administrator-issued join grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeJoinGrantIssuanceCommit {
    /// Original semantic request digest.
    pub request_digest: [u8; 32],
    /// Durable result digest.
    pub result_digest: [u8; 32],
    /// Immutable committed grant facts.
    pub record: JoinGrantRecord,
}

/// Replicated reads and mutation required by node join-grant issuance.
pub trait NodeJoinGrantIssuanceAuthority: BrowserSessionAuthority + NativeApiKeyAuthority {
    /// Reports whether one current principal has system-manager authority.
    ///
    /// # Errors
    ///
    /// Fails closed when current role authority is unavailable or corrupt.
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, NodeJoinGrantIssuanceAuthorityError>;

    /// Returns the one intrinsic mesh identity served by this root authority.
    ///
    /// # Errors
    ///
    /// Fails closed when mesh identity state is unavailable or malformed.
    fn local_mesh_id(&self) -> Result<Option<MeshId>, NodeJoinGrantIssuanceAuthorityError>;

    /// Resolves one exact previously committed issuance operation.
    ///
    /// # Errors
    ///
    /// Rejects another command family or malformed durable evidence.
    fn resolve_join_grant_issuance(
        &self,
        operation_id: OperationId,
        join_grant_id: JoinGrantId,
    ) -> Result<Option<NodeJoinGrantIssuanceCommit>, NodeJoinGrantIssuanceAuthorityError>;

    /// Commits or exactly resolves one issuance through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never reports success without durable evidence.
    fn commit_or_resolve_join_grant_issuance(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<NodeJoinGrantIssuanceCommit, NodeJoinGrantIssuanceAuthorityError>;
}

/// HTTP-facing join-grant operations with authentication separated from body consumption.
pub trait NodeJoinGrantIssuanceController: Send + 'static {
    /// Authenticates current system-manager authority before reading a request body.
    ///
    /// # Errors
    ///
    /// Rejects malformed, revoked, stale or insufficient credentials and unavailable authority.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, NodeJoinGrantIssuanceError>;

    /// Issues or exactly replays one bounded self-contained invitation.
    ///
    /// # Errors
    ///
    /// Rejects invalid policy, changed retries, unavailable authority or invalid evidence.
    fn issue(
        &mut self,
        administrator: IdentityAdministrator,
        request: CreateNodeJoinGrantRequest,
    ) -> Result<CreateNodeJoinGrantResponse, NodeJoinGrantIssuanceError>;
}

/// Live service which retains neither the authentication root nor its derived issuance key.
pub struct NodeJoinGrantIssuanceService<A, R, D> {
    authority: A,
    roots: AuthenticationRootLoadingService<R, D>,
    gateway: GatewaySessionIdentity,
    gateway_certificate_fingerprint: [u8; 32],
}

impl<A, R, D> NodeJoinGrantIssuanceService<A, R, D> {
    /// Binds one gateway identity, its public certificate pin and current replicated authority.
    #[must_use]
    pub const fn new(
        authority: A,
        root_authority: R,
        decryptor: D,
        gateway: GatewaySessionIdentity,
        gateway_certificate_fingerprint: [u8; 32],
    ) -> Self {
        Self {
            authority,
            roots: AuthenticationRootLoadingService::new(root_authority, decryptor),
            gateway,
            gateway_certificate_fingerprint,
        }
    }
}

impl<A, R, D> NodeJoinGrantIssuanceController for NodeJoinGrantIssuanceService<A, R, D>
where
    A: NodeJoinGrantIssuanceAuthority + Send + 'static,
    R: AuthenticationRootAuthority + Send + 'static,
    D: SecretGenerationDecryptor + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, NodeJoinGrantIssuanceError> {
        let principal_id = authenticate_principal(&self.authority, self.gateway, headers, now)?;
        if !self.authority.is_system_manager(principal_id, now)? {
            return Err(NodeJoinGrantIssuanceError::Forbidden);
        }
        Ok(IdentityAdministrator { principal_id, now })
    }

    fn issue(
        &mut self,
        administrator: IdentityAdministrator,
        request: CreateNodeJoinGrantRequest,
    ) -> Result<CreateNodeJoinGrantResponse, NodeJoinGrantIssuanceError> {
        let normalized = NormalizedJoinGrant::new(&request)?;
        let mesh_id = self
            .authority
            .local_mesh_id()?
            .ok_or(NodeJoinGrantIssuanceError::Unavailable)?;
        let issuance_key = self
            .roots
            .load_latest()
            .map(AuthenticationRuntimeKeys::into_join_grant_issuance_key)
            .map_err(map_root_loading_error)?;
        let invitation = JoinGrantBundle::derive_issued(
            &issuance_key,
            mesh_id,
            administrator.principal_id,
            normalized.operation_id,
            &request.enrolment_endpoint,
            self.gateway_certificate_fingerprint,
        )
        .map_err(|_| NodeJoinGrantIssuanceError::Failed)?;
        let existing = self
            .authority
            .resolve_join_grant_issuance(normalized.operation_id, invitation.join_grant_id())?;
        let occurred_at = existing.map_or(administrator.now, |commit| commit.record.created_at);
        let expires_at = occurred_at
            .checked_add(DurationMicros::new(
                u64::from(request.valid_for_seconds) * MICROS_PER_SECOND,
            ))
            .ok_or(NodeJoinGrantIssuanceError::InvalidInput)?;
        let command = AuthoritativeCommand::IssueJoinGrant(IssueJoinGrant {
            join_grant_id: invitation.join_grant_id(),
            secret_digest: invitation.secret_digest(),
            allowed_roles: normalized.roles,
            maximum_uses: request.maximum_uses,
            expires_at,
        });
        let context = command_context(
            normalized.operation_id,
            administrator.principal_id,
            invitation.join_grant_id(),
            occurred_at,
        )?;
        let expected_digest = command.request_digest(context);
        let commit = existing.map_or_else(
            || {
                self.authority
                    .commit_or_resolve_join_grant_issuance(context, &command)
            },
            Ok,
        )?;
        validate_commit(
            commit,
            expected_digest,
            administrator.principal_id,
            normalized.roles,
            request.maximum_uses,
            expires_at,
        )?;
        Ok(CreateNodeJoinGrantResponse {
            operation_id: request.operation_id,
            join_code: invitation.expose_encoded().to_string(),
            expires_at_epoch_micros: expires_at.get(),
            allowed_roles: normalized.api_roles,
            maximum_uses: request.maximum_uses,
        })
    }
}

struct NormalizedJoinGrant {
    operation_id: OperationId,
    api_roles: Vec<NodeJoinRole>,
    roles: JoinRoles,
}

impl NormalizedJoinGrant {
    fn new(request: &CreateNodeJoinGrantRequest) -> Result<Self, NodeJoinGrantIssuanceError> {
        let operation_id = OperationId::from_bytes(
            parse_uuid(request.operation_id.as_str())
                .map_err(|_| NodeJoinGrantIssuanceError::InvalidInput)?,
        )
        .map_err(|_| NodeJoinGrantIssuanceError::InvalidInput)?;
        let role_set = request
            .allowed_roles
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if role_set.is_empty() || role_set.len() != request.allowed_roles.len() {
            return Err(NodeJoinGrantIssuanceError::InvalidInput);
        }
        let api_roles = role_set.into_iter().collect::<Vec<_>>();
        let bits = api_roles.iter().fold(0_u8, |bits, role| {
            bits | match role {
                NodeJoinRole::Storage => JoinRoles::STORAGE,
                NodeJoinRole::Gateway => JoinRoles::GATEWAY,
                NodeJoinRole::MetadataEligible => JoinRoles::METADATA_ELIGIBLE,
            }
        });
        let roles = JoinRoles::new(bits).map_err(|_| NodeJoinGrantIssuanceError::InvalidInput)?;
        Ok(Self {
            operation_id,
            api_roles,
            roles,
        })
    }
}

fn authenticate_principal<A>(
    authority: &A,
    gateway: GatewaySessionIdentity,
    headers: &HeaderMap,
    now: UnixMicros,
) -> Result<PrincipalId, NodeJoinGrantIssuanceError>
where
    A: BrowserSessionAuthority + NativeApiKeyAuthority,
{
    if headers.contains_key(AUTHORIZATION) {
        if headers.contains_key(COOKIE) {
            return Err(NodeJoinGrantIssuanceError::Unauthenticated);
        }
        return NativeApiKeyAuthenticator::new(authority, gateway)
            .authenticate_principal(headers, now)
            .map_err(map_native_authentication_error);
    }
    BrowserSessionAuthenticator::new(authority, gateway)
        .authenticate(
            headers,
            BrowserRequestProtection::Mutation,
            AssuranceLevel::SingleFactor,
            now,
        )
        .map(|capability| capability.principal_id)
        .map_err(map_browser_authentication_error)
}

fn command_context(
    operation_id: OperationId,
    principal_id: PrincipalId,
    join_grant_id: JoinGrantId,
    occurred_at: UnixMicros,
) -> Result<CommandContext, NodeJoinGrantIssuanceError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(principal_id.as_bytes());
    digest.update(join_grant_id.as_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map(uuid_v8)
        .map_err(|_| NodeJoinGrantIssuanceError::Failed)?;
    Ok(CommandContext {
        operation_id,
        actor_principal_id: principal_id,
        audit_event_id: AuditEventId::from_bytes(bytes)
            .map_err(|_| NodeJoinGrantIssuanceError::Failed)?,
        occurred_at,
        expected_revision: None,
    })
}

fn validate_commit(
    commit: NodeJoinGrantIssuanceCommit,
    expected_digest: [u8; 32],
    principal_id: PrincipalId,
    roles: JoinRoles,
    maximum_uses: u16,
    expires_at: UnixMicros,
) -> Result<(), NodeJoinGrantIssuanceError> {
    if commit.request_digest != expected_digest {
        return Err(NodeJoinGrantIssuanceError::Conflict);
    }
    if commit.result_digest == [0; 32]
        || commit.record.issued_by != principal_id
        || commit.record.allowed_roles != roles
        || commit.record.maximum_uses != maximum_uses
        || commit.record.expires_at != expires_at
        || commit.record.created_at >= expires_at
    {
        return Err(NodeJoinGrantIssuanceError::Failed);
    }
    Ok(())
}

const fn map_root_loading_error(
    error: AuthenticationRootLoadingError,
) -> NodeJoinGrantIssuanceError {
    match error {
        AuthenticationRootLoadingError::NotFound
        | AuthenticationRootLoadingError::NotRecipient
        | AuthenticationRootLoadingError::Unavailable => NodeJoinGrantIssuanceError::Unavailable,
        AuthenticationRootLoadingError::InvalidInput | AuthenticationRootLoadingError::Failed => {
            NodeJoinGrantIssuanceError::Failed
        }
    }
}

const fn map_browser_authentication_error(
    error: BrowserAuthenticationError,
) -> NodeJoinGrantIssuanceError {
    match error {
        BrowserAuthenticationError::Rejected => NodeJoinGrantIssuanceError::Unauthenticated,
        BrowserAuthenticationError::InvalidGateway => NodeJoinGrantIssuanceError::Failed,
        BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Unavailable) => {
            NodeJoinGrantIssuanceError::Unavailable
        }
        BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Failed) => {
            NodeJoinGrantIssuanceError::Failed
        }
    }
}

const fn map_native_authentication_error(
    error: FileApiAuthenticationError,
) -> NodeJoinGrantIssuanceError {
    match error {
        FileApiAuthenticationError::Rejected => NodeJoinGrantIssuanceError::Unauthenticated,
        FileApiAuthenticationError::AuthorityUnavailable => NodeJoinGrantIssuanceError::Unavailable,
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => NodeJoinGrantIssuanceError::Failed,
    }
}

/// Closed replicated-authority failure for join-grant issuance.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NodeJoinGrantIssuanceAuthorityError {
    /// Current authority cannot be reached.
    #[error("node join-grant authority is unavailable")]
    Unavailable,
    /// Operation identity is bound to different input.
    #[error("node join-grant authority reports a conflict")]
    Conflict,
    /// Durable state or evidence failed validation.
    #[error("node join-grant authority failed closed")]
    Failed,
}

/// Stable join-grant issuance failure containing no invitation material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NodeJoinGrantIssuanceError {
    /// Public operation, endpoint, role or lifetime input is invalid.
    #[error("node join-grant request is invalid")]
    InvalidInput,
    /// Authentication was absent, malformed, stale or revoked.
    #[error("node join-grant authentication was rejected")]
    Unauthenticated,
    /// Current principal is not a system manager.
    #[error("node join-grant authority was denied")]
    Forbidden,
    /// Operation identity is bound to different semantic input.
    #[error("node join-grant operation conflicts with committed state")]
    Conflict,
    /// Current replicated or protected-key authority is unavailable.
    #[error("node join-grant authority is unavailable")]
    Unavailable,
    /// Key material, durable evidence or an invariant failed closed.
    #[error("node join-grant issuance failed closed")]
    Failed,
}

impl From<NodeJoinGrantIssuanceAuthorityError> for NodeJoinGrantIssuanceError {
    fn from(error: NodeJoinGrantIssuanceAuthorityError) -> Self {
        match error {
            NodeJoinGrantIssuanceAuthorityError::Unavailable => Self::Unavailable,
            NodeJoinGrantIssuanceAuthorityError::Conflict => Self::Conflict,
            NodeJoinGrantIssuanceAuthorityError::Failed => Self::Failed,
        }
    }
}
