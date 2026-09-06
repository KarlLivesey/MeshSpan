// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-backed adapter for durable manual DNS challenge tasks.

use std::future::{self, Future};
use std::sync::{Arc, Mutex};

use meshspan_acme::{ManualDnsTask, ManualDnsTaskAuthority, ManualDnsTaskPhase};
use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_contracts::ContractError;
use meshspan_domain::{
    AuditEventId, CertificateOrderId, Clock, OperationId, PrincipalId, Revision, UnixMicros,
    uuid_v8,
};
use meshspan_metadata::{
    AdvanceManualDnsTask, AuthoritativeCommand, CertificateOrderClaim, CommandContext,
    CommandReceipt, EntityKind, ManualDnsTaskPhase as MetadataTaskPhase, RepositoryError,
};
use sha2::{Digest as _, Sha256};

use crate::ConsensusAuthenticationAuthority;

const OPERATION_ID_DOMAIN: &[u8] = b"meshspan.manual-dns-task.operation.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.manual-dns-task.audit.v1\0";

/// Authoritative reads and writes required by manual DNS task publication.
pub trait ManualDnsTaskCommitAuthority {
    /// Checks whether this exact publication already reached the requested phase.
    ///
    /// The retained task and live claim must be checked in one read view. This is
    /// evidence of an existing transition, never a new lease or permission grant.
    ///
    /// # Errors
    ///
    /// Rejects expired/replaced claims, conflicting task identity and corrupt state.
    fn manual_dns_task_transition_satisfied(
        &self,
        now: UnixMicros,
        transition: &AdvanceManualDnsTask,
    ) -> Result<bool, ContractError>;

    /// Resolves a potentially committed task transition after an ambiguous response.
    ///
    /// # Errors
    ///
    /// Fails closed when operation evidence is unavailable or malformed.
    fn resolve_manual_dns_task(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, ContractError>;

    /// Commits one exact task transition.
    ///
    /// # Errors
    ///
    /// Never reports success without an authoritative receipt.
    fn commit_manual_dns_task(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, ContractError>;
}

impl ManualDnsTaskCommitAuthority for ConsensusAuthenticationAuthority {
    fn manual_dns_task_transition_satisfied(
        &self,
        now: UnixMicros,
        transition: &AdvanceManualDnsTask,
    ) -> Result<bool, ContractError> {
        self.reader()
            .manual_dns_task_transition_satisfied(now, transition)
            .map_err(|error| map_repository_error(&error))
    }

    fn resolve_manual_dns_task(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, ContractError> {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn commit_manual_dns_task(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, ContractError> {
        self.commit_authoritative(context, command)
            .map_err(map_authority_error)
    }
}

/// Cloneable single-worker handle for manual DNS transitions over one SQLite reader.
///
/// The certificate loop runs on a blocking worker, so this lock never encloses an asynchronous
/// suspension. It exists only because a resumable challenge must own its authority independently
/// from the factory that creates later orders.
#[derive(Clone)]
pub struct SharedManualDnsTaskAuthority {
    inner: Arc<Mutex<ConsensusAuthenticationAuthority>>,
}

impl SharedManualDnsTaskAuthority {
    /// Wraps one independently opened consensus reader for serial certificate work.
    #[must_use]
    pub fn new(authority: ConsensusAuthenticationAuthority) -> Self {
        Self {
            inner: Arc::new(Mutex::new(authority)),
        }
    }
}

impl ManualDnsTaskCommitAuthority for SharedManualDnsTaskAuthority {
    fn manual_dns_task_transition_satisfied(
        &self,
        now: UnixMicros,
        transition: &AdvanceManualDnsTask,
    ) -> Result<bool, ContractError> {
        self.inner
            .lock()
            .map_err(|_| ContractError::Unavailable)?
            .manual_dns_task_transition_satisfied(now, transition)
    }

    fn resolve_manual_dns_task(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, ContractError> {
        self.inner
            .lock()
            .map_err(|_| ContractError::Unavailable)?
            .resolve_manual_dns_task(operation_id)
    }

    fn commit_manual_dns_task(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, ContractError> {
        self.inner
            .lock()
            .map_err(|_| ContractError::Unavailable)?
            .commit_manual_dns_task(context, command)
    }
}

/// Binds one claimed order to its consensus-backed manual DNS task stream.
pub struct ConsensusManualDnsTaskAuthority<A, C> {
    authority: A,
    clock: C,
    order_id: CertificateOrderId,
    claim: CertificateOrderClaim,
    actor_principal_id: PrincipalId,
}

impl<A, C> ConsensusManualDnsTaskAuthority<A, C> {
    /// Creates an adapter for one exact current order claim.
    #[must_use]
    pub const fn new(
        authority: A,
        clock: C,
        order_id: CertificateOrderId,
        claim: CertificateOrderClaim,
        actor_principal_id: PrincipalId,
    ) -> Self {
        Self {
            authority,
            clock,
            order_id,
            claim,
            actor_principal_id,
        }
    }
}

impl<A, C> ManualDnsTaskAuthority for ConsensusManualDnsTaskAuthority<A, C>
where
    A: ManualDnsTaskCommitAuthority + Send + Sync,
    C: Clock + Send + Sync,
{
    fn advance(
        &self,
        task: &ManualDnsTask,
    ) -> impl Future<Output = Result<(), ContractError>> + Send {
        future::ready(self.advance_sync(task))
    }
}

impl<A: ManualDnsTaskCommitAuthority, C: Clock> ConsensusManualDnsTaskAuthority<A, C> {
    fn advance_sync(&self, task: &ManualDnsTask) -> Result<(), ContractError> {
        if task.order_epoch != self.claim.fence || task.task_digest == [0; 32] {
            return Err(ContractError::Stale);
        }
        let now = self.clock.now();
        let transition = self.transition(task);
        if self
            .authority
            .manual_dns_task_transition_satisfied(now, &transition)?
        {
            return Ok(());
        }
        let operation_id = derived_id(OPERATION_ID_DOMAIN, task, now)?;
        let audit_event_id = AuditEventId::from_bytes(derived_bytes(AUDIT_ID_DOMAIN, task, now))
            .map_err(|_| ContractError::InvalidInput)?;
        let command = AuthoritativeCommand::AdvanceManualDnsTask(transition);
        let context = CommandContext {
            operation_id,
            actor_principal_id: self.actor_principal_id,
            audit_event_id,
            occurred_at: now,
            expected_revision: None,
        };
        let expected_digest = command.request_digest(context);
        let receipt = match self.authority.resolve_manual_dns_task(operation_id)? {
            Some(receipt) => receipt,
            None => self.authority.commit_manual_dns_task(context, &command)?,
        };
        validate_receipt(receipt, operation_id, expected_digest, self.order_id)
    }

    fn transition(&self, task: &ManualDnsTask) -> AdvanceManualDnsTask {
        AdvanceManualDnsTask {
            task_digest: task.task_digest,
            order_id: self.order_id,
            claim_generation: self.claim.generation,
            worker_node_id: self.claim.worker_node_id,
            worker_incarnation: self.claim.worker_incarnation,
            fence: self.claim.fence,
            record_name: task.record_name.clone(),
            record_value: task.record_value.clone(),
            expires_at: task.expires_at,
            phase: match task.phase {
                ManualDnsTaskPhase::AwaitingPublication => MetadataTaskPhase::AwaitingPublication,
                ManualDnsTaskPhase::PublicationObserved => MetadataTaskPhase::PublicationObserved,
                ManualDnsTaskPhase::AwaitingRemoval => MetadataTaskPhase::AwaitingRemoval,
                ManualDnsTaskPhase::Complete => MetadataTaskPhase::Complete,
            },
        }
    }
}

fn derived_id(
    domain: &[u8],
    task: &ManualDnsTask,
    now: meshspan_domain::UnixMicros,
) -> Result<OperationId, ContractError> {
    OperationId::from_bytes(derived_bytes(domain, task, now))
        .map_err(|_| ContractError::InvalidInput)
}

fn derived_bytes(
    domain: &[u8],
    task: &ManualDnsTask,
    now: meshspan_domain::UnixMicros,
) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(task.task_digest);
    digest.update([phase_code(task.phase)]);
    digest.update(now.get().to_be_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    uuid_v8(bytes)
}

const fn phase_code(phase: ManualDnsTaskPhase) -> u8 {
    match phase {
        ManualDnsTaskPhase::AwaitingPublication => 1,
        ManualDnsTaskPhase::PublicationObserved => 2,
        ManualDnsTaskPhase::AwaitingRemoval => 3,
        ManualDnsTaskPhase::Complete => 4,
    }
}

fn validate_receipt(
    receipt: CommandReceipt,
    operation_id: OperationId,
    request_digest: [u8; 32],
    order_id: CertificateOrderId,
) -> Result<(), ContractError> {
    if receipt.operation_id != operation_id
        || receipt.request_digest != request_digest
        || receipt.result_digest == [0; 32]
        || receipt.committed_revision == Revision::ZERO
        || receipt.entity.kind != EntityKind::CertificateOrder
        || receipt.entity.id != order_id.as_bytes()
    {
        return Err(ContractError::Conflict);
    }
    Ok(())
}

fn map_repository_error(error: &RepositoryError) -> ContractError {
    match error {
        RepositoryError::InvalidCommand => ContractError::Stale,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            ContractError::Unavailable
        }
        _ => ContractError::InternalContract,
    }
}

const fn map_authority_error(error: MetadataAuthorityRequestError) -> ContractError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => ContractError::Unavailable,
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            ContractError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            ContractError::InternalContract
        }
    }
}
