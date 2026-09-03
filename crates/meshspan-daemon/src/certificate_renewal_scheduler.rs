// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic, race-safe scheduling of replacement ACME certificate orders.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AuditEventId, CertificateOrderId, DurationMicros, OperationId, Revision, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CertificateOrderRecord, CertificateOrderState,
    CertificateRenewalCandidate, CommandContext, CommandReceipt, DueCertificateRenewalCursor,
    EntityKind, Page, PageLimit, QueueCertificateOrder, RepositoryError,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::ConsensusAuthenticationAuthority;

const MAXIMUM_RENEWAL_LEAD_MICROS: u64 = 180 * 24 * 60 * 60 * 1_000_000;
const ORDER_ID_DOMAIN: &[u8] = b"meshspan.certificate-renewal.order.v1\0";
const OPERATION_ID_DOMAIN: &[u8] = b"meshspan.certificate-renewal.operation.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.certificate-renewal.audit.v1\0";

/// Authoritative reads and mutation required by the automatic renewal scheduler.
pub trait CertificateRenewalAuthority {
    /// Returns a bounded page of latest certificate generations whose renewal window is open.
    ///
    /// # Errors
    ///
    /// Fails closed for corrupt state or unavailable persistence.
    fn due_certificate_renewals(
        &self,
        renew_by: UnixMicros,
        after: Option<&DueCertificateRenewalCursor>,
        limit: PageLimit,
    ) -> Result<Page<CertificateRenewalCandidate, DueCertificateRenewalCursor>, RepositoryError>;

    /// Loads a deterministic replacement after an ambiguous or contended commit.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed persisted lifecycle state.
    fn certificate_order(
        &self,
        order_id: CertificateOrderId,
    ) -> Result<Option<CertificateOrderRecord>, RepositoryError>;

    /// Commits or resolves one exact replacement order through consensus.
    ///
    /// # Errors
    ///
    /// Never reports success without a durable command receipt.
    fn commit_certificate_renewal(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError>;
}

impl CertificateRenewalAuthority for ConsensusAuthenticationAuthority {
    fn due_certificate_renewals(
        &self,
        renew_by: UnixMicros,
        after: Option<&DueCertificateRenewalCursor>,
        limit: PageLimit,
    ) -> Result<Page<CertificateRenewalCandidate, DueCertificateRenewalCursor>, RepositoryError>
    {
        self.reader()
            .due_certificate_renewals(renew_by, after, limit)
    }

    fn certificate_order(
        &self,
        order_id: CertificateOrderId,
    ) -> Result<Option<CertificateOrderRecord>, RepositoryError> {
        self.reader().certificate_order(order_id)
    }

    fn commit_certificate_renewal(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        self.commit_authoritative(context, command)
    }
}

/// Exact replacement order durably admitted for automatic renewal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateRenewalScheduleCommit {
    /// Expiring completed order that caused renewal.
    pub source_order_id: CertificateOrderId,
    /// Stable replacement identity derived from the source generation.
    pub replacement_order_id: CertificateOrderId,
    /// Revision containing the replacement order.
    pub revision: Revision,
}

/// Stateless certificate-renewal scheduler.
pub struct CertificateRenewalScheduler<'a, A> {
    authority: &'a A,
}

impl<'a, A> CertificateRenewalScheduler<'a, A> {
    /// Binds renewal scheduling to current replicated authority.
    #[must_use]
    pub const fn new(authority: &'a A) -> Self {
        Self { authority }
    }
}

impl<A> CertificateRenewalScheduler<'_, A>
where
    A: CertificateRenewalAuthority,
{
    /// Schedules at most one due replacement from a bounded page.
    ///
    /// The replacement order identity depends only on the completed source generation. Competing
    /// voters therefore propose the same identity, while the repository suppresses all due reads
    /// once any replacement for that configuration is actionable.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive lead time, time overflow, malformed projections, contradictory
    /// receipts and unavailable consensus.
    pub fn schedule_next(
        &self,
        now: UnixMicros,
        renewal_lead: DurationMicros,
        after: Option<&DueCertificateRenewalCursor>,
        page_items: usize,
    ) -> Result<Option<CertificateRenewalScheduleCommit>, CertificateRenewalScheduleError> {
        if now.get() < 0
            || renewal_lead.get() == 0
            || renewal_lead.get() > MAXIMUM_RENEWAL_LEAD_MICROS
        {
            return Err(CertificateRenewalScheduleError::InvalidInput);
        }
        let renew_by = now
            .checked_add(renewal_lead)
            .ok_or(CertificateRenewalScheduleError::InvalidInput)?;
        let page = self.authority.due_certificate_renewals(
            renew_by,
            after,
            PageLimit::new(page_items)?,
        )?;
        let Some(candidate) = page.items.into_iter().next() else {
            return Ok(None);
        };
        if candidate.revision == Revision::ZERO {
            return Err(CertificateRenewalScheduleError::InvalidProjection);
        }
        let replacement_order_id = derived_order_id(candidate)?;
        let context = CommandContext {
            operation_id: derived_operation_id(OPERATION_ID_DOMAIN, candidate, now)?,
            actor_principal_id: candidate.configured_by,
            audit_event_id: derived_audit_id(candidate, now)?,
            occurred_at: now,
            expected_revision: None,
        };
        let command = AuthoritativeCommand::QueueCertificateOrder(QueueCertificateOrder {
            order_id: replacement_order_id,
            config_id: candidate.config_id,
            next_attempt_at: now,
        });
        let receipt = match self.authority.commit_certificate_renewal(context, &command) {
            Ok(receipt) => receipt,
            Err(MetadataAuthorityRequestError::Rejected) => {
                return self.resolve_race(candidate, replacement_order_id);
            }
            Err(error) => return Err(error.into()),
        };
        validate_receipt(receipt, context, &command, replacement_order_id)?;
        let replacement = self
            .authority
            .certificate_order(replacement_order_id)?
            .ok_or(CertificateRenewalScheduleError::InvalidProjection)?;
        validate_replacement(
            &replacement,
            candidate,
            now,
            Some(receipt.committed_revision),
        )?;
        Ok(Some(CertificateRenewalScheduleCommit {
            source_order_id: candidate.source_order_id,
            replacement_order_id,
            revision: replacement.revision,
        }))
    }

    fn resolve_race(
        &self,
        candidate: CertificateRenewalCandidate,
        replacement_order_id: CertificateOrderId,
    ) -> Result<Option<CertificateRenewalScheduleCommit>, CertificateRenewalScheduleError> {
        let Some(replacement) = self.authority.certificate_order(replacement_order_id)? else {
            return Err(CertificateRenewalScheduleError::Authority(
                MetadataAuthorityRequestError::Rejected,
            ));
        };
        validate_replacement(&replacement, candidate, replacement.next_attempt_at, None)?;
        Ok(Some(CertificateRenewalScheduleCommit {
            source_order_id: candidate.source_order_id,
            replacement_order_id,
            revision: replacement.revision,
        }))
    }
}

fn validate_replacement(
    replacement: &CertificateOrderRecord,
    candidate: CertificateRenewalCandidate,
    expected_attempt_at: UnixMicros,
    expected_revision: Option<Revision>,
) -> Result<(), CertificateRenewalScheduleError> {
    if replacement.config_id != candidate.config_id
        || replacement.state != CertificateOrderState::Queued
        || replacement.next_attempt_at != expected_attempt_at
        || replacement.attempt_count != 0
        || replacement.certificate.is_some()
        || replacement.claim.is_some()
        || replacement.revision == Revision::ZERO
        || expected_revision.is_some_and(|revision| replacement.revision != revision)
    {
        Err(CertificateRenewalScheduleError::InvalidProjection)
    } else {
        Ok(())
    }
}

fn validate_receipt(
    receipt: CommandReceipt,
    context: CommandContext,
    command: &AuthoritativeCommand,
    replacement_order_id: CertificateOrderId,
) -> Result<(), CertificateRenewalScheduleError> {
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.result_digest == [0; 32]
        || receipt.committed_revision == Revision::ZERO
        || receipt.entity.kind != EntityKind::CertificateOrder
        || receipt.entity.id != replacement_order_id.as_bytes()
    {
        Err(CertificateRenewalScheduleError::InvalidReceipt)
    } else {
        Ok(())
    }
}

fn derived_order_id(
    candidate: CertificateRenewalCandidate,
) -> Result<CertificateOrderId, CertificateRenewalScheduleError> {
    CertificateOrderId::from_bytes(uuid_v8(derived_prefix(ORDER_ID_DOMAIN, candidate, None)))
        .map_err(Into::into)
}

fn derived_operation_id(
    domain: &[u8],
    candidate: CertificateRenewalCandidate,
    now: UnixMicros,
) -> Result<OperationId, CertificateRenewalScheduleError> {
    OperationId::from_bytes(uuid_v8(derived_prefix(domain, candidate, Some(now))))
        .map_err(Into::into)
}

fn derived_audit_id(
    candidate: CertificateRenewalCandidate,
    now: UnixMicros,
) -> Result<AuditEventId, CertificateRenewalScheduleError> {
    AuditEventId::from_bytes(uuid_v8(derived_prefix(
        AUDIT_ID_DOMAIN,
        candidate,
        Some(now),
    )))
    .map_err(Into::into)
}

fn derived_prefix(
    domain: &[u8],
    candidate: CertificateRenewalCandidate,
    now: Option<UnixMicros>,
) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(candidate.source_order_id.as_bytes());
    digest.update(candidate.config_id.as_bytes());
    digest.update(candidate.not_after.get().to_be_bytes());
    if let Some(now) = now {
        digest.update(now.get().to_be_bytes());
    }
    let digest = digest.finalize();
    let mut prefix = [0_u8; 16];
    prefix.copy_from_slice(&digest[..16]);
    prefix
}

/// Closed automatic certificate-renewal scheduling failure.
#[derive(Debug, Error)]
pub enum CertificateRenewalScheduleError {
    /// Lead time, page size or authority time is invalid.
    #[error("certificate renewal scheduling input is invalid")]
    InvalidInput,
    /// Durable candidate or replacement state contradicts the scheduler contract.
    #[error("certificate renewal projection is invalid")]
    InvalidProjection,
    /// Consensus returned a receipt which does not prove the exact replacement command.
    #[error("certificate renewal receipt is invalid")]
    InvalidReceipt,
    /// Durable identity construction failed.
    #[error("certificate renewal identity is invalid")]
    Identifier(#[from] meshspan_domain::IdentifierError),
    /// Renewal reads failed closed.
    #[error("certificate renewal repository failed")]
    Repository(#[from] RepositoryError),
    /// Consensus could not safely admit or resolve the replacement.
    #[error("certificate renewal authority failed")]
    Authority(#[from] MetadataAuthorityRequestError),
}
