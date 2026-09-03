// SPDX-License-Identifier: GPL-2.0-only

//! Idempotent authoritative checkpoints for one fenced ACME order machine.

use meshspan_acme::{AcmeMachineAction, AcmeOrderMachine};
use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AuditEventId, CertificateOrderId, OperationId, PrincipalId, Revision, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CertificateOrderClaim, CheckpointCertificateOrder, CommandContext,
    CommandReceipt, EntityKind, RepositoryError, SecretGenerationReference,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::ConsensusAuthenticationAuthority;

const OPERATION_ID_DOMAIN: &[u8] = b"meshspan.acme-checkpoint.operation.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.acme-checkpoint.audit.v1\0";

/// Exact inputs required to persist one restart-safe ACME transition.
pub struct CertificateOrderCheckpoint<'a> {
    /// Durable order identity.
    pub order_id: CertificateOrderId,
    /// Exact still-live worker claim.
    pub claim: CertificateOrderClaim,
    /// Immutable encrypted leaf-key generation used by every worker attempt.
    pub certificate_key: SecretGenerationReference,
    /// Validated state whose next side effect has not yet run.
    pub machine: &'a AcmeOrderMachine,
}

/// Exact durable checkpoint receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateOrderCheckpointCommit {
    /// SHA-256 digest of the complete versioned checkpoint bytes.
    pub checkpoint_digest: [u8; 32],
    /// Authoritative revision containing this state.
    pub revision: Revision,
}

/// Consensus boundary required by checkpoint publication.
pub trait CertificateOrderCheckpointAuthority {
    /// Resolves an exact previous checkpoint submission before another mutation attempt.
    ///
    /// # Errors
    ///
    /// Fails closed when operation evidence cannot be trusted.
    fn resolve_certificate_order_checkpoint(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderCheckpointAuthorityError>;

    /// Commits or resolves one exact checkpoint command.
    ///
    /// # Errors
    ///
    /// Never reports success without an exact durable receipt.
    fn checkpoint_certificate_order(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, CertificateOrderCheckpointAuthorityError>;
}

impl CertificateOrderCheckpointAuthority for ConsensusAuthenticationAuthority {
    fn resolve_certificate_order_checkpoint(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderCheckpointAuthorityError> {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn checkpoint_certificate_order(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, CertificateOrderCheckpointAuthorityError> {
        self.commit_authoritative(context, command)
            .map_err(map_authority_error)
    }
}

/// Stateless authoritative ACME checkpoint service.
pub struct CertificateOrderCheckpointService<A> {
    authority: A,
}

impl<A> CertificateOrderCheckpointService<A> {
    /// Binds checkpoint persistence to one consensus authority.
    #[must_use]
    pub const fn new(authority: A) -> Self {
        Self { authority }
    }
}

impl<A: CertificateOrderCheckpointAuthority> CertificateOrderCheckpointService<A> {
    /// Persists one validated incomplete state under its exact live claim.
    ///
    /// Identifiers are derived from the actor, occurrence instant, checkpoint digest and fence.
    /// Repeating the exact submission resolves without another write; advancing the machine
    /// creates a new operation.
    ///
    /// # Errors
    ///
    /// Rejects expired or contradictory claims, completed machines, invalid leaf-key references,
    /// malformed checkpoint output, authority failure and any substituted durable receipt.
    pub fn checkpoint(
        &self,
        actor_principal_id: PrincipalId,
        now: UnixMicros,
        input: &CertificateOrderCheckpoint<'_>,
    ) -> Result<CertificateOrderCheckpointCommit, CertificateOrderCheckpointError> {
        validate_input(now, input)?;
        let checkpoint = input.machine.encode_checkpoint()?;
        let checkpoint_digest: [u8; 32] = Sha256::digest(&checkpoint).into();
        let operation_id = derived_operation_id(actor_principal_id, now, input, checkpoint_digest)?;
        let audit_event_id = derived_audit_id(actor_principal_id, now, input, checkpoint_digest)?;
        let command =
            AuthoritativeCommand::CheckpointCertificateOrder(CheckpointCertificateOrder {
                order_id: input.order_id,
                claim_generation: input.claim.generation,
                worker_node_id: input.claim.worker_node_id,
                worker_incarnation: input.claim.worker_incarnation,
                fence: input.claim.fence,
                certificate_key: input.certificate_key,
                checkpoint,
            });
        let context = CommandContext {
            operation_id,
            actor_principal_id,
            audit_event_id,
            occurred_at: now,
            expected_revision: None,
        };
        let expected_request_digest = command.request_digest(context);
        let receipt = match self
            .authority
            .resolve_certificate_order_checkpoint(operation_id)?
        {
            Some(receipt) => receipt,
            None => self
                .authority
                .checkpoint_certificate_order(context, &command)?,
        };
        validate_receipt(
            receipt,
            operation_id,
            expected_request_digest,
            input.order_id,
        )?;
        Ok(CertificateOrderCheckpointCommit {
            checkpoint_digest,
            revision: receipt.committed_revision,
        })
    }
}

fn validate_input(
    now: UnixMicros,
    input: &CertificateOrderCheckpoint<'_>,
) -> Result<(), CertificateOrderCheckpointError> {
    let action = input.machine.action()?;
    if input.claim.generation == 0
        || input.claim.worker_incarnation == 0
        || input.claim.fence == 0
        || input.claim.lease_expires_at <= now
        || input.machine.order_epoch() != input.claim.fence
        || input.certificate_key.secret_id != input.order_id.as_bytes()
        || input.certificate_key.generation != 1
        || matches!(action, AcmeMachineAction::Complete { .. })
    {
        Err(CertificateOrderCheckpointError::InvalidInput)
    } else {
        Ok(())
    }
}

fn derived_operation_id(
    actor_principal_id: PrincipalId,
    now: UnixMicros,
    input: &CertificateOrderCheckpoint<'_>,
    checkpoint_digest: [u8; 32],
) -> Result<OperationId, CertificateOrderCheckpointError> {
    OperationId::from_bytes(derived_id(
        OPERATION_ID_DOMAIN,
        actor_principal_id,
        now,
        input,
        checkpoint_digest,
    )?)
    .map_err(CertificateOrderCheckpointError::from)
}

fn derived_audit_id(
    actor_principal_id: PrincipalId,
    now: UnixMicros,
    input: &CertificateOrderCheckpoint<'_>,
    checkpoint_digest: [u8; 32],
) -> Result<AuditEventId, CertificateOrderCheckpointError> {
    AuditEventId::from_bytes(derived_id(
        AUDIT_ID_DOMAIN,
        actor_principal_id,
        now,
        input,
        checkpoint_digest,
    )?)
    .map_err(CertificateOrderCheckpointError::from)
}

fn derived_id(
    domain: &[u8],
    actor_principal_id: PrincipalId,
    now: UnixMicros,
    input: &CertificateOrderCheckpoint<'_>,
    checkpoint_digest: [u8; 32],
) -> Result<[u8; 16], CertificateOrderCheckpointError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(actor_principal_id.as_bytes());
    digest.update(now.get().to_be_bytes());
    digest.update(input.order_id.as_bytes());
    digest.update(input.claim.generation.to_be_bytes());
    digest.update(input.claim.worker_node_id.as_bytes());
    digest.update(input.claim.worker_incarnation.to_be_bytes());
    digest.update(input.claim.fence.to_be_bytes());
    digest.update(input.certificate_key.secret_id);
    digest.update(input.certificate_key.generation.to_be_bytes());
    digest.update(checkpoint_digest);
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| CertificateOrderCheckpointError::InvalidInput)?;
    Ok(uuid_v8(bytes))
}

fn validate_receipt(
    receipt: CommandReceipt,
    operation_id: OperationId,
    expected_request_digest: [u8; 32],
    order_id: CertificateOrderId,
) -> Result<(), CertificateOrderCheckpointError> {
    if receipt.operation_id != operation_id
        || receipt.request_digest != expected_request_digest
        || receipt.result_digest == [0; 32]
        || receipt.committed_revision == Revision::ZERO
        || receipt.entity.kind != EntityKind::CertificateOrder
        || receipt.entity.id != order_id.as_bytes()
    {
        Err(CertificateOrderCheckpointError::Conflict)
    } else {
        Ok(())
    }
}

fn map_repository_error(error: &RepositoryError) -> CertificateOrderCheckpointAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            CertificateOrderCheckpointAuthorityError::Unavailable
        }
        _ => CertificateOrderCheckpointAuthorityError::Failed,
    }
}

const fn map_authority_error(
    error: MetadataAuthorityRequestError,
) -> CertificateOrderCheckpointAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            CertificateOrderCheckpointAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            CertificateOrderCheckpointAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            CertificateOrderCheckpointAuthorityError::Failed
        }
    }
}

/// Closed checkpoint-authority failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CertificateOrderCheckpointAuthorityError {
    /// Current metadata authority cannot safely answer or commit.
    #[error("certificate order checkpoint authority is unavailable")]
    Unavailable,
    /// Durable state conflicts with this exact checkpoint.
    #[error("certificate order checkpoint authority conflicts with the request")]
    Conflict,
    /// Authority evidence is malformed or violated the contract.
    #[error("certificate order checkpoint authority failed closed")]
    Failed,
}

/// Closed ACME checkpoint publication failure.
#[derive(Debug, Error)]
pub enum CertificateOrderCheckpointError {
    /// Claim, leaf-key reference or machine phase is invalid.
    #[error("certificate order checkpoint input is invalid")]
    InvalidInput,
    /// Existing durable operation evidence contradicts this checkpoint.
    #[error("certificate order checkpoint conflicts with durable state")]
    Conflict,
    /// State-machine checkpoint validation or encoding failed.
    #[error("certificate order checkpoint state is invalid")]
    Machine(#[from] meshspan_acme::AcmeMachineError),
    /// Derived operation or audit identity was invalid.
    #[error("certificate order checkpoint identity is invalid")]
    Identifier(#[from] meshspan_domain::IdentifierError),
    /// Consensus-backed authority rejected or could not commit.
    #[error("certificate order checkpoint authority failed")]
    Authority(#[from] CertificateOrderCheckpointAuthorityError),
}
