// SPDX-License-Identifier: GPL-2.0-only

//! One-step ACME execution composed with authoritative post-step checkpointing.

use meshspan_acme::{
    AcmeChallengeExecution, AcmeStepExecutor, AcmeStepOutcome, AcmeTransport, AcmeWorkerError,
};
use meshspan_contracts::{CertificateChallenge, RequestContext};
use meshspan_domain::{Clock, PrincipalId, UnixMicros};
use thiserror::Error;

use crate::{
    CertificateOrderAssignment, CertificateOrderCheckpoint, CertificateOrderCheckpointAuthority,
    CertificateOrderCheckpointCommit, CertificateOrderCheckpointError,
    CertificateOrderCheckpointService, PreparedCertificateOrder,
};

mod publication;

/// Durable result of executing exactly one current machine action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateOrderStepResult {
    /// External visibility is not yet proven; the same action remains current.
    Pending,
    /// One event advanced and the resulting next-action state is authoritative.
    Checkpointed(CertificateOrderCheckpointCommit),
    /// The terminal machine state yielded certificate-chain bytes for validation.
    ReadyForCompletion {
        /// Bounded CA response bytes still requiring chain/name/key/lifetime validation.
        certificate_chain: Vec<u8>,
    },
}

/// Stateful in-process execution of one already-prepared certificate order.
pub struct CertificateOrderExecution<T, C> {
    assignment: CertificateOrderAssignment,
    machine: meshspan_acme::AcmeOrderMachine,
    certificate_key: meshspan_certificates::ExternalCertificateRequestKey,
    certificate_key_reference: meshspan_metadata::SecretGenerationReference,
    csr_der: Vec<u8>,
    executor: AcmeStepExecutor<T, meshspan_acme::AcmeAccountKey, C>,
    publication_visible: bool,
}

impl<T, C> CertificateOrderExecution<T, C> {
    /// Composes protected prepared state with selected in-process transport and challenge provider.
    #[must_use]
    pub fn new(prepared: PreparedCertificateOrder, transport: T, challenge: C) -> Self {
        Self {
            assignment: prepared.assignment,
            machine: prepared.machine,
            certificate_key: prepared.certificate_key,
            certificate_key_reference: prepared.certificate_key_reference,
            csr_der: prepared.csr_der,
            executor: AcmeStepExecutor::new(transport, prepared.account_key, challenge),
            publication_visible: false,
        }
    }

    /// Returns the current pure state machine without exposing secret material.
    #[must_use]
    pub const fn machine(&self) -> &meshspan_acme::AcmeOrderMachine {
        &self.machine
    }

    /// Returns the order-bound leaf key for final certificate/key validation and publication.
    #[must_use]
    pub const fn certificate_key(&self) -> &meshspan_certificates::ExternalCertificateRequestKey {
        &self.certificate_key
    }

    /// Returns the claimed order and immutable configuration projection.
    #[must_use]
    pub const fn assignment(&self) -> &CertificateOrderAssignment {
        &self.assignment
    }

    /// Separates the in-process transport and challenge provider after terminal completion.
    #[must_use]
    pub fn into_runtime_parts(self) -> (T, C) {
        let (transport, _account_key, challenge) = self.executor.into_parts();
        (transport, challenge)
    }
}

impl<T, C> CertificateOrderExecution<T, C>
where
    T: AcmeTransport,
    C: CertificateChallenge,
{
    /// Executes one action and checkpoints incomplete progress before further side effects.
    ///
    /// Downloaded chains instead pass to terminal validation and its atomic completion command.
    /// Until that commits, recovery retains the prior download checkpoint, never an unvalidated
    /// terminal certificate. Re-downloading after interruption does not create another CA order.
    /// The caller's clock is read again after external IO: a late response never advances local
    /// state, and a successful checkpoint uses receipt time rather than request-start time.
    ///
    /// # Errors
    ///
    /// Rejects stale execution deadlines or configuration revisions, ACME transport/protocol/
    /// challenge failures, invalid transitions and any failed authoritative checkpoint.
    pub async fn execute_step<A: CertificateOrderCheckpointAuthority>(
        &mut self,
        checkpoint_service: &CertificateOrderCheckpointService<A>,
        actor_principal_id: PrincipalId,
        clock: &impl Clock,
        context: RequestContext,
        challenge_expires_at: UnixMicros,
    ) -> Result<CertificateOrderStepResult, CertificateOrderExecutionError> {
        let now = clock.now();
        let claim = self
            .assignment
            .order
            .claim
            .ok_or(CertificateOrderExecutionError::InvalidInput)?;
        if now.get() < 0
            || context.deadline > claim.lease_expires_at
            || context.expected_revision != Some(self.assignment.configuration.revision)
            || challenge_expires_at > claim.lease_expires_at
        {
            return Err(CertificateOrderExecutionError::InvalidInput);
        }
        if context.deadline <= now || challenge_expires_at <= now {
            return Err(CertificateOrderExecutionError::DeadlineElapsed);
        }
        if let Some(candidate) = self.prepare_publication(context, challenge_expires_at)? {
            return self.checkpoint_candidate(
                checkpoint_service,
                actor_principal_id,
                now,
                candidate,
            );
        }
        if self.needs_publication_restore()? {
            return self
                .restore_publication(clock, context, challenge_expires_at)
                .await;
        }
        if self
            .machine
            .poll_not_before()
            .is_some_and(|instant| now < instant)
        {
            return Ok(CertificateOrderStepResult::Pending);
        }
        let action = self.machine.action()?;
        let remaining_micros = u64::try_from(context.deadline.get() - now.get())
            .map_err(|_| CertificateOrderExecutionError::InvalidInput)?;
        // The worker owns the deadline, even when a replaceable transport/provider does not.
        // Only the external action is cancellable here; authoritative checkpointing is not.
        let outcome = tokio::time::timeout(
            std::time::Duration::from_micros(remaining_micros),
            self.executor.execute(
                &action,
                AcmeChallengeExecution {
                    context,
                    challenge_expires_at,
                    publication: self.machine.publication(),
                    csr_der: &self.csr_der,
                },
            ),
        )
        .await
        .map_err(|_| CertificateOrderExecutionError::DeadlineElapsed)??;
        let received_at = clock.now();
        if received_at < now {
            return Err(CertificateOrderExecutionError::InvalidInput);
        }
        if received_at >= context.deadline {
            return Err(CertificateOrderExecutionError::DeadlineElapsed);
        }
        let (event, retry_after) = match outcome {
            AcmeStepOutcome::Pending => return Ok(CertificateOrderStepResult::Pending),
            AcmeStepOutcome::Complete(certificate_chain) => {
                return Ok(CertificateOrderStepResult::ReadyForCompletion { certificate_chain });
            }
            AcmeStepOutcome::Advanced(event) => (event, None),
            AcmeStepOutcome::AdvancedWithRetry { event, retry_after } => (event, Some(retry_after)),
        };
        let publication_visible = matches!(
            event,
            meshspan_acme::AcmeMachineEvent::ChallengePublished { .. }
        );
        let mut candidate = self.machine.clone();
        candidate.advance_with_retry(event, received_at, retry_after)?;
        if let meshspan_acme::AcmeMachineAction::Complete { certificate } = candidate.action()? {
            return Ok(CertificateOrderStepResult::ReadyForCompletion {
                certificate_chain: certificate,
            });
        }
        let result = self.checkpoint_candidate(
            checkpoint_service,
            actor_principal_id,
            received_at,
            candidate,
        )?;
        self.publication_visible |= publication_visible;
        Ok(result)
    }

    fn checkpoint_candidate<A: CertificateOrderCheckpointAuthority>(
        &mut self,
        checkpoint_service: &CertificateOrderCheckpointService<A>,
        actor_principal_id: PrincipalId,
        now: UnixMicros,
        candidate: meshspan_acme::AcmeOrderMachine,
    ) -> Result<CertificateOrderStepResult, CertificateOrderExecutionError> {
        let checkpoint = checkpoint_service.checkpoint(
            actor_principal_id,
            now,
            &CertificateOrderCheckpoint {
                order_id: self.assignment.order.order_id,
                claim: self
                    .assignment
                    .order
                    .claim
                    .ok_or(CertificateOrderExecutionError::InvalidInput)?,
                certificate_key: self.certificate_key_reference,
                machine: &candidate,
            },
        )?;
        // An unsuccessful or ambiguous commit must not become executable local state.
        self.machine = candidate;
        Ok(CertificateOrderStepResult::Checkpointed(checkpoint))
    }
}

/// Closed failure from one composed ACME worker step.
#[derive(Debug, Error)]
pub enum CertificateOrderExecutionError {
    /// The owned deadline elapsed before a response could safely advance the machine.
    #[error("certificate order execution deadline elapsed")]
    DeadlineElapsed,
    /// Claim, deadline, expiry or configuration revision is stale or contradictory.
    #[error("certificate order execution input is invalid")]
    InvalidInput,
    /// The pure state machine rejected its current action or returned event.
    #[error("certificate order execution state is invalid")]
    Machine(#[from] meshspan_acme::AcmeMachineError),
    /// The bounded in-process ACME executor failed.
    #[error("certificate order execution step failed")]
    Worker(#[from] AcmeWorkerError),
    /// The advanced state could not be committed authoritatively.
    #[error("certificate order execution checkpoint failed")]
    Checkpoint(#[from] CertificateOrderCheckpointError),
}
