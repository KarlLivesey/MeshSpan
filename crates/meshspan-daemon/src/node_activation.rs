// SPDX-License-Identifier: GPL-2.0-only

//! Certificate-bound completion of staged node admission.

use meshspan_domain::{AuditEventId, NodeId, OperationId, UnixMicros, uuid_v8};
use meshspan_metadata::{
    ActivateNode, AuthoritativeCommand, CommandContext, JoinRoles, NodeActivationCandidate,
    NodeActivationRecord,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.enrolment.activate-audit-id.v1\0";

/// Private-protocol facts authenticated before one activation mutation is attempted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeActivationRequest {
    /// Exact-retry identity supplied before consensus.
    pub operation_id: OperationId,
    /// Node claimed by `NodeHello` and proven by the mTLS certificate binding.
    pub node_id: NodeId,
    /// Positive process incarnation from the negotiated hello.
    pub incarnation: u64,
    /// SHA-256 fingerprint of the authenticated peer leaf certificate.
    pub certificate_fingerprint: [u8; 32],
    /// Exact admitted role set presented by the node.
    pub roles: JoinRoles,
    /// Digest of every validated protocol, feature and component capability.
    pub capability_digest: [u8; 32],
    /// Set only after the staged private endpoint passed an authenticated reachability probe.
    pub endpoint_probe_passed: bool,
    /// Leader-authoritative activation instant.
    pub occurred_at: UnixMicros,
}

/// Exact consensus evidence for one node activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeActivationCommit {
    /// Original semantic request digest.
    pub request_digest: [u8; 32],
    /// Durable result digest.
    pub result_digest: [u8; 32],
    /// Activated node facts read back from metadata.
    pub record: NodeActivationRecord,
}

/// Replicated authority needed by the private node-activation boundary.
pub trait NodeActivationAuthority {
    /// Returns the exact staged admission for the authenticated node.
    ///
    /// # Errors
    ///
    /// Fails closed when admission state is unavailable or malformed.
    fn activation_candidate(
        &self,
        node_id: NodeId,
    ) -> Result<Option<NodeActivationCandidate>, NodeActivationAuthorityError>;

    /// Resolves one exact prior activation operation.
    ///
    /// # Errors
    ///
    /// Rejects malformed or unrelated durable evidence.
    fn resolve_activation(
        &self,
        operation_id: OperationId,
        node_id: NodeId,
    ) -> Result<Option<NodeActivationCommit>, NodeActivationAuthorityError>;

    /// Commits or exactly resolves one activation through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never reports uncommitted success.
    fn commit_or_resolve_activation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<NodeActivationCommit, NodeActivationAuthorityError>;
}

/// Validates private-session evidence and commits one exact activation.
pub struct NodeActivationService<A> {
    authority: A,
}

impl<A> NodeActivationService<A> {
    /// Binds the service to one replaceable consensus authority.
    #[must_use]
    pub const fn new(authority: A) -> Self {
        Self { authority }
    }
}

impl<A> NodeActivationService<A>
where
    A: NodeActivationAuthority,
{
    /// Activates one admitted node only after all transport evidence agrees.
    ///
    /// # Errors
    ///
    /// Rejects identity, certificate, role, capability, reachability and replay mismatches.
    pub fn activate(
        &mut self,
        request: NodeActivationRequest,
    ) -> Result<NodeActivationCommit, NodeActivationError> {
        if request.incarnation == 0
            || request.certificate_fingerprint == [0; 32]
            || request.capability_digest == [0; 32]
            || !request.endpoint_probe_passed
        {
            return Err(NodeActivationError::Rejected);
        }
        let candidate = self
            .authority
            .activation_candidate(request.node_id)?
            .ok_or(NodeActivationError::Rejected)?;
        if candidate.incarnation != request.incarnation
            || candidate.certificate_fingerprint != request.certificate_fingerprint
            || candidate.roles != request.roles
        {
            return Err(NodeActivationError::Rejected);
        }
        let context = command_context(&request, &candidate)?;
        let command = AuthoritativeCommand::ActivateNode(ActivateNode {
            node_id: request.node_id,
            incarnation: request.incarnation,
            private_endpoint: candidate.private_endpoint,
            capability_digest: request.capability_digest,
        });
        let expected_digest = command.request_digest(context);
        let commit = self
            .authority
            .resolve_activation(request.operation_id, request.node_id)?
            .map_or_else(
                || {
                    self.authority
                        .commit_or_resolve_activation(context, &command)
                },
                Ok,
            )?;
        if commit.request_digest != expected_digest
            || commit.result_digest == [0; 32]
            || commit.record.node_id != request.node_id
            || commit.record.incarnation != request.incarnation
            || commit.record.capability_digest != request.capability_digest
        {
            return Err(NodeActivationError::Conflict);
        }
        Ok(commit)
    }
}

fn command_context(
    request: &NodeActivationRequest,
    candidate: &NodeActivationCandidate,
) -> Result<CommandContext, NodeActivationError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(request.operation_id.as_bytes());
    digest.update(request.node_id.as_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map(uuid_v8)
        .map_err(|_| NodeActivationError::Failed)?;
    Ok(CommandContext {
        operation_id: request.operation_id,
        actor_principal_id: candidate.authorised_by,
        audit_event_id: AuditEventId::from_bytes(bytes).map_err(|_| NodeActivationError::Failed)?,
        occurred_at: request.occurred_at,
        expected_revision: None,
    })
}

/// Closed replicated-authority failure for node activation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NodeActivationAuthorityError {
    /// Current authority cannot be reached.
    #[error("node activation authority is unavailable")]
    Unavailable,
    /// Operation identity is bound to different input.
    #[error("node activation authority reports a conflict")]
    Conflict,
    /// Admission or active state rejected the transition.
    #[error("node activation authority rejected the transition")]
    Rejected,
    /// Durable evidence failed validation.
    #[error("node activation authority failed closed")]
    Failed,
}

/// Stable private node-activation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NodeActivationError {
    /// Authenticated identity, admission or reachability evidence did not agree.
    #[error("node activation was rejected")]
    Rejected,
    /// Exact operation identity was reused with changed input.
    #[error("node activation conflicts with committed state")]
    Conflict,
    /// The current authority cannot complete the transition.
    #[error("node activation authority is unavailable")]
    Unavailable,
    /// Durable state or an internal invariant failed closed.
    #[error("node activation failed closed")]
    Failed,
}

impl From<NodeActivationAuthorityError> for NodeActivationError {
    fn from(error: NodeActivationAuthorityError) -> Self {
        match error {
            NodeActivationAuthorityError::Unavailable => Self::Unavailable,
            NodeActivationAuthorityError::Conflict => Self::Conflict,
            NodeActivationAuthorityError::Rejected => Self::Rejected,
            NodeActivationAuthorityError::Failed => Self::Failed,
        }
    }
}
