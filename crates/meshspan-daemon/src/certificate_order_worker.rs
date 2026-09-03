// SPDX-License-Identifier: GPL-2.0-only

//! Bounded race-safe admission of due ACME orders to one fenced worker.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AuditEventId, CertificateOrderId, DurationMicros, EntropyError, NodeId, OperationId,
    RandomSource, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AcmeConfigurationRecord, AuthoritativeCommand, CertificateOrderCheckpointRecord,
    CertificateOrderClaim, CertificateOrderRecord, CertificateOrderState, ClaimCertificateOrder,
    CommandContext, CommandReceipt, DueCertificateOrderCursor, EntityKind, Page, PageLimit,
    RepositoryError,
};
use thiserror::Error;

use crate::ConsensusAuthenticationAuthority;

const MAXIMUM_CLAIM_LEASE_MICROS: u64 = 15 * 60 * 1_000_000;

/// Authoritative reads and mutation needed to assign one ACME order.
pub trait CertificateOrderWorkerAuthority {
    /// Returns one bounded stable page of orders eligible for a claim at `now`.
    ///
    /// # Errors
    ///
    /// Fails closed for invalid bounds, corrupt state or unavailable persistence.
    fn due_certificate_orders(
        &self,
        now: UnixMicros,
        after: Option<&DueCertificateOrderCursor>,
        limit: PageLimit,
    ) -> Result<Page<CertificateOrderRecord, DueCertificateOrderCursor>, RepositoryError>;

    /// Reloads one exact order after a claim race.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed persisted lifecycle state.
    fn certificate_order(
        &self,
        order_id: CertificateOrderId,
    ) -> Result<Option<CertificateOrderRecord>, RepositoryError>;

    /// Loads the complete immutable configuration bound to the order.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed configuration or secret references.
    fn acme_configuration(
        &self,
        config_id: meshspan_domain::AcmeConfigurationId,
    ) -> Result<Option<AcmeConfigurationRecord>, RepositoryError>;

    /// Loads any restart point retained for this order.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed, substituted or incomplete checkpoint state.
    fn certificate_order_checkpoint(
        &self,
        order_id: CertificateOrderId,
    ) -> Result<Option<CertificateOrderCheckpointRecord>, RepositoryError>;

    /// Commits or resolves one exact fenced claim through consensus.
    ///
    /// # Errors
    ///
    /// Never reports success without an exact durable receipt.
    fn commit_certificate_order_claim(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError>;
}

impl CertificateOrderWorkerAuthority for ConsensusAuthenticationAuthority {
    fn due_certificate_orders(
        &self,
        now: UnixMicros,
        after: Option<&DueCertificateOrderCursor>,
        limit: PageLimit,
    ) -> Result<Page<CertificateOrderRecord, DueCertificateOrderCursor>, RepositoryError> {
        self.reader().due_certificate_orders(now, after, limit)
    }

    fn certificate_order(
        &self,
        order_id: CertificateOrderId,
    ) -> Result<Option<CertificateOrderRecord>, RepositoryError> {
        self.reader().certificate_order(order_id)
    }

    fn acme_configuration(
        &self,
        config_id: meshspan_domain::AcmeConfigurationId,
    ) -> Result<Option<AcmeConfigurationRecord>, RepositoryError> {
        self.reader().acme_configuration(config_id)
    }

    fn certificate_order_checkpoint(
        &self,
        order_id: CertificateOrderId,
    ) -> Result<Option<CertificateOrderCheckpointRecord>, RepositoryError> {
        self.reader().certificate_order_checkpoint(order_id)
    }

    fn commit_certificate_order_claim(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        self.commit_authoritative(context, command)
    }
}

/// Fully claimed inputs needed to prepare or resume an ACME order machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateOrderAssignment {
    /// Exact post-claim order projection.
    pub order: CertificateOrderRecord,
    /// Complete immutable ACME configuration.
    pub configuration: AcmeConfigurationRecord,
    /// Prior restart point, which may belong to a superseded fence.
    pub checkpoint: Option<CertificateOrderCheckpointRecord>,
}

/// Stateless bounded order dispatcher for one daemon incarnation.
pub struct CertificateOrderDispatcher<'a, Authority, Random> {
    authority: &'a Authority,
    random: &'a mut Random,
    worker_node_id: NodeId,
    worker_incarnation: u64,
}

impl<'a, Authority, Random> CertificateOrderDispatcher<'a, Authority, Random> {
    /// Binds one authenticated worker identity to current replicated authority.
    #[must_use]
    pub const fn new(
        authority: &'a Authority,
        random: &'a mut Random,
        worker_node_id: NodeId,
        worker_incarnation: u64,
    ) -> Self {
        Self {
            authority,
            random,
            worker_node_id,
            worker_incarnation,
        }
    }
}

impl<Authority, Random> CertificateOrderDispatcher<'_, Authority, Random>
where
    Authority: CertificateOrderWorkerAuthority,
    Random: RandomSource,
{
    /// Claims the first still-actionable order from one bounded page.
    ///
    /// Contended rows are re-read. A row demonstrably won by another worker is skipped, while an
    /// unexplained rejection fails closed. The returned configuration and checkpoint are loaded
    /// only after the exact claim receipt is proven.
    ///
    /// # Errors
    ///
    /// Rejects invalid identity, lease or page bounds; unavailable consensus; malformed durable
    /// state; entropy failure; and any receipt or post-claim projection contradiction.
    pub fn claim_next(
        &mut self,
        now: UnixMicros,
        lease_duration: DurationMicros,
        after: Option<&DueCertificateOrderCursor>,
        page_items: usize,
    ) -> Result<Option<CertificateOrderAssignment>, CertificateOrderDispatchError> {
        validate_request(self.worker_incarnation, lease_duration)?;
        let lease_expires_at = now
            .checked_add(lease_duration)
            .ok_or(CertificateOrderDispatchError::InvalidInput)?;
        let page =
            self.authority
                .due_certificate_orders(now, after, PageLimit::new(page_items)?)?;
        for candidate in page.items {
            if let Some(assignment) = self.claim_candidate(now, lease_expires_at, candidate)? {
                return Ok(Some(assignment));
            }
        }
        Ok(None)
    }

    fn claim_candidate(
        &mut self,
        now: UnixMicros,
        lease_expires_at: UnixMicros,
        candidate: CertificateOrderRecord,
    ) -> Result<Option<CertificateOrderAssignment>, CertificateOrderDispatchError> {
        if !ready_at(&candidate, now) {
            return Err(CertificateOrderDispatchError::InvalidProjection);
        }
        let configuration = self
            .authority
            .acme_configuration(candidate.config_id)?
            .ok_or(CertificateOrderDispatchError::InvalidProjection)?;
        if configuration.config_id != candidate.config_id {
            return Err(CertificateOrderDispatchError::InvalidProjection);
        }
        let claim_generation = candidate
            .attempt_count
            .checked_add(1)
            .ok_or(CertificateOrderDispatchError::Capacity)?;
        let (operation_id, audit_event_id, fence) = random_claim_identity(self.random)?;
        let context = CommandContext {
            operation_id,
            actor_principal_id: configuration.configured_by,
            audit_event_id,
            occurred_at: now,
            expected_revision: None,
        };
        let claim = CertificateOrderClaim {
            generation: claim_generation,
            worker_node_id: self.worker_node_id,
            worker_incarnation: self.worker_incarnation,
            fence,
            lease_expires_at,
        };
        let command = AuthoritativeCommand::ClaimCertificateOrder(ClaimCertificateOrder {
            order_id: candidate.order_id,
            claim_generation,
            worker_node_id: claim.worker_node_id,
            worker_incarnation: claim.worker_incarnation,
            fence: claim.fence,
            lease_expires_at: claim.lease_expires_at,
        });
        let receipt = match self
            .authority
            .commit_certificate_order_claim(context, &command)
        {
            Ok(receipt) => receipt,
            Err(MetadataAuthorityRequestError::Rejected) => {
                return self.resolve_rejected_race(now, &candidate);
            }
            Err(error) => return Err(error.into()),
        };
        validate_claim_receipt(receipt, context, &command, candidate.order_id)?;
        let order = self
            .authority
            .certificate_order(candidate.order_id)?
            .ok_or(CertificateOrderDispatchError::InvalidProjection)?;
        if order.state != CertificateOrderState::Claimed
            || order.config_id != candidate.config_id
            || order.attempt_count != claim_generation
            || order.claim != Some(claim)
            || order.revision != receipt.committed_revision
        {
            return Err(CertificateOrderDispatchError::InvalidProjection);
        }
        let checkpoint = self
            .authority
            .certificate_order_checkpoint(order.order_id)?;
        if checkpoint
            .as_ref()
            .is_some_and(|value| value.order_id != order.order_id)
        {
            return Err(CertificateOrderDispatchError::InvalidProjection);
        }
        Ok(Some(CertificateOrderAssignment {
            order,
            configuration,
            checkpoint,
        }))
    }

    fn resolve_rejected_race(
        &self,
        now: UnixMicros,
        candidate: &CertificateOrderRecord,
    ) -> Result<Option<CertificateOrderAssignment>, CertificateOrderDispatchError> {
        let current = self.authority.certificate_order(candidate.order_id)?;
        if current.as_ref().is_none_or(|record| !ready_at(record, now)) {
            Ok(None)
        } else {
            Err(CertificateOrderDispatchError::Authority(
                MetadataAuthorityRequestError::Rejected,
            ))
        }
    }
}

fn validate_request(
    worker_incarnation: u64,
    lease_duration: DurationMicros,
) -> Result<(), CertificateOrderDispatchError> {
    if worker_incarnation == 0
        || lease_duration.get() == 0
        || lease_duration.get() > MAXIMUM_CLAIM_LEASE_MICROS
    {
        Err(CertificateOrderDispatchError::InvalidInput)
    } else {
        Ok(())
    }
}

fn ready_at(order: &CertificateOrderRecord, now: UnixMicros) -> bool {
    if order.next_attempt_at > now {
        return false;
    }
    match (order.state, order.claim) {
        (CertificateOrderState::Queued, None) => true,
        (CertificateOrderState::Claimed, Some(claim)) => claim.lease_expires_at <= now,
        _ => false,
    }
}

fn validate_claim_receipt(
    receipt: CommandReceipt,
    context: CommandContext,
    command: &AuthoritativeCommand,
    order_id: CertificateOrderId,
) -> Result<(), CertificateOrderDispatchError> {
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.result_digest == [0; 32]
        || receipt.committed_revision == meshspan_domain::Revision::ZERO
        || receipt.entity.kind != EntityKind::CertificateOrder
        || receipt.entity.id != order_id.as_bytes()
    {
        Err(CertificateOrderDispatchError::InvalidReceipt)
    } else {
        Ok(())
    }
}

fn random_claim_identity(
    random: &mut impl RandomSource,
) -> Result<(OperationId, AuditEventId, u64), CertificateOrderDispatchError> {
    let mut bytes = [0_u8; 40];
    random.fill_bytes(&mut bytes)?;
    let operation_bytes = copy_identifier(&bytes[..16])?;
    let audit_bytes = copy_identifier(&bytes[16..32])?;
    let operation = uuid_v8(operation_bytes);
    let audit = uuid_v8(audit_bytes);
    let fence = u64::from_be_bytes(
        bytes[32..]
            .try_into()
            .map_err(|_| CertificateOrderDispatchError::InvalidInput)?,
    );
    if operation == audit || fence == 0 {
        return Err(CertificateOrderDispatchError::InvalidInput);
    }
    Ok((
        OperationId::from_bytes(operation)
            .map_err(|_| CertificateOrderDispatchError::InvalidInput)?,
        AuditEventId::from_bytes(audit).map_err(|_| CertificateOrderDispatchError::InvalidInput)?,
        fence,
    ))
}

fn copy_identifier(value: &[u8]) -> Result<[u8; 16], CertificateOrderDispatchError> {
    value
        .try_into()
        .map_err(|_| CertificateOrderDispatchError::InvalidInput)
}

/// Closed failures from bounded ACME order admission.
#[derive(Debug, Error)]
pub enum CertificateOrderDispatchError {
    /// Worker identity, lease or page input is invalid.
    #[error("certificate order dispatch input is invalid")]
    InvalidInput,
    /// Selected and point-read authoritative state contradicted itself.
    #[error("certificate order dispatch projection is invalid")]
    InvalidProjection,
    /// A durable receipt did not exactly identify the attempted claim.
    #[error("certificate order claim receipt is invalid")]
    InvalidReceipt,
    /// Attempt counters or identifiers exceeded their representation.
    #[error("certificate order dispatch capacity was exceeded")]
    Capacity,
    /// Authoritative ACME metadata could not be read safely.
    #[error("certificate order dispatch metadata failed")]
    Repository(#[from] RepositoryError),
    /// Consensus did not durably accept or resolve the claim.
    #[error("certificate order dispatch authority failed")]
    Authority(#[from] MetadataAuthorityRequestError),
    /// A cryptographically unpredictable claim identity could not be generated.
    #[error("certificate order dispatch entropy failed")]
    Entropy(#[from] EntropyError),
}
