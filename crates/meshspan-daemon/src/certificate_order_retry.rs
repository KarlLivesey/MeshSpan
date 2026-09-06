// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic fenced retry scheduling for failed ACME order attempts.

use meshspan_domain::{AuditEventId, OperationId, PrincipalId, Revision, UnixMicros, uuid_v8};
use meshspan_metadata::{
    AuthoritativeCommand, CertificateOrderCompletion, CommandContext, CommandReceipt,
    CompleteCertificateOrder, EntityKind,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{
    CertificateOrderAssignment, CertificateOrderCompletionAuthority,
    CertificateOrderCompletionAuthorityError,
};

const FAILURE_DIGEST_DOMAIN: &[u8] = b"meshspan.acme-retry.failure.v1\0";
const OPERATION_ID_DOMAIN: &[u8] = b"meshspan.acme-retry.operation.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.acme-retry.audit.v1\0";
const SECOND_MICROS: u64 = 1_000_000;
const MAXIMUM_BACKOFF_MICROS: u64 = 6 * 60 * 60 * SECOND_MICROS;

/// Redacted failure family used to select an automatic retry cadence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateOrderFailureClass {
    /// Resolver, connection or peer availability failed.
    Transport,
    /// The remote ACME exchange violated or rejected the protocol.
    Protocol,
    /// HTTP-01 or DNS-01 publication/probing did not complete.
    Challenge,
    /// The downloaded terminal certificate failed semantic or trust validation.
    Certificate,
}

impl CertificateOrderFailureClass {
    const fn code(self) -> u8 {
        match self {
            Self::Transport => 1,
            Self::Protocol => 2,
            Self::Challenge => 3,
            Self::Certificate => 4,
        }
    }

    const fn base_delay_micros(self) -> u64 {
        match self {
            Self::Transport => 30 * SECOND_MICROS,
            Self::Challenge => 2 * 60 * SECOND_MICROS,
            Self::Protocol => 5 * 60 * SECOND_MICROS,
            Self::Certificate => 15 * 60 * SECOND_MICROS,
        }
    }
}

/// Exact authoritative retry outcome for observability and worker wake-up scheduling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateOrderRetryCommit {
    /// Stable redacted digest retained on the completed attempt.
    pub failure_digest: [u8; 32],
    /// Earliest authority-agreed next attempt.
    pub retry_at: UnixMicros,
    /// Revision that durably returned the order to its queue.
    pub revision: Revision,
}

/// Fenced retry application service over the existing certificate-order authority.
pub struct CertificateOrderRetryService<A> {
    authority: A,
}

/// One scheduling decision; fresh attempts additionally bind the consumed retirement proof.
#[derive(Clone, Copy)]
struct RetryPlan {
    failure_class: CertificateOrderFailureClass,
    retry_after: Option<UnixMicros>,
    retired_checkpoint_digest: Option<[u8; 32]>,
}

impl<A> CertificateOrderRetryService<A> {
    /// Binds retry policy to one authoritative certificate-order store.
    #[must_use]
    pub const fn new(authority: A) -> Self {
        Self { authority }
    }
}

impl<A> CertificateOrderRetryService<A>
where
    A: CertificateOrderCompletionAuthority,
{
    /// Returns a live claim to the queue using bounded exponential backoff and stable jitter.
    ///
    /// A valid later `retry_after` supplied by the CA wins over the local delay. Only local
    /// exponential backoff is capped; shortening the authority's deadline would violate its
    /// rate limit. The queued deadline stays visible through existing order administration.
    ///
    /// # Errors
    ///
    /// Rejects stale claims and times, overflow, contradictory replay receipts and unavailable or
    /// malformed authority evidence.
    pub fn retry(
        &self,
        actor_principal_id: PrincipalId,
        failed_at: UnixMicros,
        assignment: &CertificateOrderAssignment,
        failure_class: CertificateOrderFailureClass,
        retry_after: Option<UnixMicros>,
    ) -> Result<CertificateOrderRetryCommit, CertificateOrderRetryError> {
        self.schedule(
            actor_principal_id,
            failed_at,
            assignment,
            RetryPlan {
                failure_class,
                retry_after,
                retired_checkpoint_digest: None,
            },
        )
    }

    /// Queues a fresh CA order only after exact cleanup has reached a durable retired state.
    /// The authority consumes that checkpoint and schedules the retry in one transaction.
    ///
    /// # Errors
    ///
    /// Rejects incomplete retirement, stale claims, substituted checkpoints and failed commits.
    pub fn restart(
        &self,
        actor_principal_id: PrincipalId,
        failed_at: UnixMicros,
        assignment: &CertificateOrderAssignment,
        machine: &meshspan_acme::AcmeOrderMachine,
    ) -> Result<CertificateOrderRetryCommit, CertificateOrderRetryError> {
        let Ok(meshspan_acme::AcmeMachineAction::Retired { reason }) = machine.action() else {
            return Err(CertificateOrderRetryError::InvalidInput);
        };
        let failure_class = match reason {
            meshspan_acme::AcmeOrderRetirementReason::PublicationExpired => {
                CertificateOrderFailureClass::Challenge
            }
            meshspan_acme::AcmeOrderRetirementReason::AuthorizationRejected
            | meshspan_acme::AcmeOrderRetirementReason::OrderRejected => {
                CertificateOrderFailureClass::Protocol
            }
        };
        let checkpoint = machine
            .encode_checkpoint()
            .map_err(|_| CertificateOrderRetryError::InvalidInput)?;
        self.schedule(
            actor_principal_id,
            failed_at,
            assignment,
            RetryPlan {
                failure_class,
                retry_after: machine
                    .poll_not_before()
                    .filter(|instant| *instant > failed_at),
                retired_checkpoint_digest: Some(Sha256::digest(checkpoint).into()),
            },
        )
    }

    fn schedule(
        &self,
        actor_principal_id: PrincipalId,
        failed_at: UnixMicros,
        assignment: &CertificateOrderAssignment,
        plan: RetryPlan,
    ) -> Result<CertificateOrderRetryCommit, CertificateOrderRetryError> {
        let claim = assignment
            .order
            .claim
            .ok_or(CertificateOrderRetryError::InvalidInput)?;
        if assignment.order.attempt_count == 0
            || failed_at.get() < 0
            || claim.lease_expires_at <= failed_at
            || plan.retry_after.is_some_and(|instant| instant <= failed_at)
        {
            return Err(CertificateOrderRetryError::InvalidInput);
        }
        let retry_at = calculate_retry_at(
            failed_at,
            assignment.order.order_id.as_bytes(),
            assignment.order.attempt_count,
            plan.failure_class,
            plan.retry_after,
        )?;
        let failure_digest = derived_digest(
            FAILURE_DIGEST_DOMAIN,
            assignment,
            claim,
            failed_at,
            retry_at,
            plan,
        );
        let operation_id = OperationId::from_bytes(uuid_v8(prefix(derived_digest(
            OPERATION_ID_DOMAIN,
            assignment,
            claim,
            failed_at,
            retry_at,
            plan,
        ))))?;
        let command = AuthoritativeCommand::CompleteCertificateOrder(CompleteCertificateOrder {
            order_id: assignment.order.order_id,
            claim_generation: claim.generation,
            worker_node_id: claim.worker_node_id,
            worker_incarnation: claim.worker_incarnation,
            fence: claim.fence,
            outcome: match plan.retired_checkpoint_digest {
                Some(retired_checkpoint_digest) => CertificateOrderCompletion::Restart {
                    failure_digest,
                    retry_at,
                    retired_checkpoint_digest,
                },
                None => CertificateOrderCompletion::Retry {
                    failure_digest,
                    retry_at,
                },
            },
        });
        let context = CommandContext {
            operation_id,
            actor_principal_id,
            audit_event_id: AuditEventId::from_bytes(uuid_v8(prefix(derived_digest(
                AUDIT_ID_DOMAIN,
                assignment,
                claim,
                failed_at,
                retry_at,
                plan,
            ))))?,
            occurred_at: failed_at,
            expected_revision: None,
        };
        let expected_request_digest = command.request_digest(context);
        let receipt = match self
            .authority
            .resolve_certificate_order_completion(operation_id)?
        {
            Some(receipt) => receipt,
            None => self
                .authority
                .complete_certificate_order(context, &command)?,
        };
        validate_receipt(receipt, operation_id, expected_request_digest, assignment)?;
        Ok(CertificateOrderRetryCommit {
            failure_digest,
            retry_at,
            revision: receipt.committed_revision,
        })
    }
}

fn calculate_retry_at(
    failed_at: UnixMicros,
    order_id: [u8; 16],
    attempt_count: u64,
    failure_class: CertificateOrderFailureClass,
    retry_after: Option<UnixMicros>,
) -> Result<UnixMicros, CertificateOrderRetryError> {
    let exponent = u32::try_from(attempt_count.saturating_sub(1).min(16))
        .map_err(|_| CertificateOrderRetryError::InvalidInput)?;
    let base = failure_class
        .base_delay_micros()
        .saturating_mul(1_u64.checked_shl(exponent).unwrap_or(u64::MAX))
        .min(MAXIMUM_BACKOFF_MICROS);
    let mut jitter_digest = Sha256::new();
    jitter_digest.update(b"meshspan.acme-retry.jitter.v1\0");
    jitter_digest.update(order_id);
    jitter_digest.update(attempt_count.to_be_bytes());
    jitter_digest.update([failure_class.code()]);
    let jitter_bytes: [u8; 8] = jitter_digest.finalize()[..8]
        .try_into()
        .map_err(|_| CertificateOrderRetryError::InvalidInput)?;
    let jitter_limit = base / 5;
    let jitter = u64::from_be_bytes(jitter_bytes) % jitter_limit.saturating_add(1);
    let local_delay = base.saturating_add(jitter).min(MAXIMUM_BACKOFF_MICROS);
    let failed_at_micros =
        u64::try_from(failed_at.get()).map_err(|_| CertificateOrderRetryError::InvalidInput)?;
    let requested_retry = retry_after
        .map(UnixMicros::get)
        .map(u64::try_from)
        .transpose()
        .map_err(|_| CertificateOrderRetryError::InvalidInput)?;
    let local_retry = failed_at_micros
        .checked_add(local_delay)
        .ok_or(CertificateOrderRetryError::InvalidInput)?;
    let retry_at = requested_retry.map_or(local_retry, |value| value.max(local_retry));
    Ok(UnixMicros::new(
        i64::try_from(retry_at).map_err(|_| CertificateOrderRetryError::InvalidInput)?,
    ))
}

fn derived_digest(
    domain: &[u8],
    assignment: &CertificateOrderAssignment,
    claim: meshspan_metadata::CertificateOrderClaim,
    failed_at: UnixMicros,
    retry_at: UnixMicros,
    plan: RetryPlan,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(assignment.order.order_id.as_bytes());
    digest.update(assignment.configuration.config_id.as_bytes());
    digest.update(assignment.order.attempt_count.to_be_bytes());
    digest.update(claim.generation.to_be_bytes());
    digest.update(claim.worker_node_id.as_bytes());
    digest.update(claim.worker_incarnation.to_be_bytes());
    digest.update(claim.fence.to_be_bytes());
    digest.update(failed_at.get().to_be_bytes());
    digest.update(retry_at.get().to_be_bytes());
    digest.update([plan.failure_class.code()]);
    if let Some(checkpoint_digest) = plan.retired_checkpoint_digest {
        digest.update(b"restart\0");
        digest.update(checkpoint_digest);
    }
    digest.finalize().into()
}

fn prefix(digest: [u8; 32]) -> [u8; 16] {
    let mut prefix = [0_u8; 16];
    prefix.copy_from_slice(&digest[..16]);
    prefix
}

fn validate_receipt(
    receipt: CommandReceipt,
    operation_id: OperationId,
    expected_request_digest: [u8; 32],
    assignment: &CertificateOrderAssignment,
) -> Result<(), CertificateOrderRetryError> {
    if receipt.operation_id != operation_id
        || receipt.request_digest != expected_request_digest
        || receipt.request_digest == [0; 32]
        || receipt.result_digest == [0; 32]
        || receipt.committed_revision == Revision::ZERO
        || receipt.entity.kind != EntityKind::CertificateOrder
        || receipt.entity.id != assignment.order.order_id.as_bytes()
    {
        Err(CertificateOrderRetryError::Conflict)
    } else {
        Ok(())
    }
}

/// Closed certificate-order retry failure.
#[derive(Debug, Error)]
pub enum CertificateOrderRetryError {
    /// Claim, attempt count, time or retry guidance is invalid.
    #[error("certificate order retry input is invalid")]
    InvalidInput,
    /// Existing durable evidence contradicts this retry.
    #[error("certificate order retry conflicts with durable state")]
    Conflict,
    /// Durable operation identity construction failed.
    #[error("certificate order retry identity is invalid")]
    Identifier(#[from] meshspan_domain::IdentifierError),
    /// Consensus-backed authority rejected or could not commit.
    #[error("certificate order retry authority failed")]
    Authority(#[from] CertificateOrderCompletionAuthorityError),
}
