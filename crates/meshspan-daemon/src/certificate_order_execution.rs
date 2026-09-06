// SPDX-License-Identifier: GPL-2.0-only

//! One-step ACME execution composed with authoritative post-step checkpointing.

use meshspan_acme::{
    AcmeChallengeExecution, AcmeStepExecutor, AcmeStepOutcome, AcmeTransport, AcmeWorkerError,
};
use meshspan_contracts::{CertificateChallenge, RequestContext};
use meshspan_domain::{PrincipalId, UnixMicros};
use thiserror::Error;

use crate::{
    CertificateOrderAssignment, CertificateOrderCheckpoint, CertificateOrderCheckpointAuthority,
    CertificateOrderCheckpointCommit, CertificateOrderCheckpointError,
    CertificateOrderCheckpointService, PreparedCertificateOrder,
};

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
    ///
    /// # Errors
    ///
    /// Rejects stale execution deadlines or configuration revisions, ACME transport/protocol/
    /// challenge failures, invalid transitions and any failed authoritative checkpoint.
    pub async fn execute_step<A: CertificateOrderCheckpointAuthority>(
        &mut self,
        checkpoint_service: &CertificateOrderCheckpointService<A>,
        actor_principal_id: PrincipalId,
        now: UnixMicros,
        context: RequestContext,
        challenge_expires_at: UnixMicros,
    ) -> Result<CertificateOrderStepResult, CertificateOrderExecutionError> {
        let claim = self
            .assignment
            .order
            .claim
            .ok_or(CertificateOrderExecutionError::InvalidInput)?;
        if context.deadline <= now
            || context.deadline > claim.lease_expires_at
            || context.expected_revision != Some(self.assignment.configuration.revision)
            || challenge_expires_at <= now
            || challenge_expires_at > claim.lease_expires_at
        {
            return Err(CertificateOrderExecutionError::InvalidInput);
        }
        let action = self.machine.action()?;
        let outcome = self
            .executor
            .execute(
                &action,
                AcmeChallengeExecution {
                    context,
                    challenge_expires_at,
                    csr_der: &self.csr_der,
                },
            )
            .await?;
        match outcome {
            AcmeStepOutcome::Pending => Ok(CertificateOrderStepResult::Pending),
            AcmeStepOutcome::Complete(certificate_chain) => {
                Ok(CertificateOrderStepResult::ReadyForCompletion { certificate_chain })
            }
            AcmeStepOutcome::Advanced(event) => {
                self.machine.advance(event)?;
                if let meshspan_acme::AcmeMachineAction::Complete { certificate } =
                    self.machine.action()?
                {
                    return Ok(CertificateOrderStepResult::ReadyForCompletion {
                        certificate_chain: certificate,
                    });
                }
                let checkpoint = checkpoint_service.checkpoint(
                    actor_principal_id,
                    now,
                    &CertificateOrderCheckpoint {
                        order_id: self.assignment.order.order_id,
                        claim,
                        certificate_key: self.certificate_key_reference,
                        machine: &self.machine,
                    },
                )?;
                Ok(CertificateOrderStepResult::Checkpointed(checkpoint))
            }
        }
    }
}

/// Closed failure from one composed ACME worker step.
#[derive(Debug, Error)]
pub enum CertificateOrderExecutionError {
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
