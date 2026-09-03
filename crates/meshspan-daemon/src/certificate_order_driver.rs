// SPDX-License-Identifier: GPL-2.0-only

//! Bounded execution of one prepared ACME order through completion or durable retry.

use meshspan_acme::{AcmeTransport, AcmeWorkerError};
use meshspan_contracts::{CertificateChallenge, ContractVersion, RequestContext};
use meshspan_domain::{
    Clock, DurationMicros, OperationId, PrincipalId, RandomSource, UnixMicros, uuid_v8,
};
use thiserror::Error;

use crate::{
    CertificateOrderCheckpointAuthority, CertificateOrderCheckpointService,
    CertificateOrderCompletionAuthority, CertificateOrderCompletionCommit,
    CertificateOrderCompletionService, CertificateOrderExecution, CertificateOrderExecutionError,
    CertificateOrderFailureClass, CertificateOrderResultError, CertificateOrderResultService,
    CertificateOrderRetryCommit, CertificateOrderRetryError, CertificateOrderRetryService,
    CertificateOrderStepResult,
};

const MAXIMUM_STEPS_PER_DRIVE: usize = 64;
const MAXIMUM_REQUEST_TIMEOUT_MICROS: u64 = 5 * 60 * 1_000_000;

/// Resource policy for one bounded pass over a prepared ACME order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateOrderDrivePolicy {
    request_timeout: DurationMicros,
    maximum_steps: usize,
}

impl CertificateOrderDrivePolicy {
    /// Creates a finite worker policy.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive request timeouts and step budgets.
    pub fn new(
        request_timeout: DurationMicros,
        maximum_steps: usize,
    ) -> Result<Self, CertificateOrderDriverError> {
        if request_timeout.get() == 0
            || request_timeout.get() > MAXIMUM_REQUEST_TIMEOUT_MICROS
            || maximum_steps == 0
            || maximum_steps > MAXIMUM_STEPS_PER_DRIVE
        {
            return Err(CertificateOrderDriverError::InvalidInput);
        }
        Ok(Self {
            request_timeout,
            maximum_steps,
        })
    }
}

/// Authoritative outcome from one bounded worker pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateOrderDriveOutcome {
    /// External challenge or CA state is not yet observable; retry the same live execution later.
    Pending,
    /// The step budget was consumed after every transition was durably checkpointed.
    Yielded {
        /// Number of remote or challenge steps executed in this pass.
        steps: usize,
    },
    /// The validated certificate generation was atomically published to encrypted recipients.
    Completed(CertificateOrderCompletionCommit),
    /// A typed external failure durably returned the claimed order to its retry queue.
    Retried {
        /// Redacted failure family controlling retry cadence.
        failure_class: CertificateOrderFailureClass,
        /// Exact authoritative retry commit.
        commit: CertificateOrderRetryCommit,
    },
}

/// Composes step execution, checkpointing, terminal validation and retry for one order.
pub struct CertificateOrderDriver<A, R, C> {
    checkpoint: CertificateOrderCheckpointService<A>,
    completion: CertificateOrderCompletionService<A, R>,
    retry: CertificateOrderRetryService<A>,
    result: CertificateOrderResultService,
    operation_random: R,
    clock: C,
    actor_principal_id: PrincipalId,
    policy: CertificateOrderDrivePolicy,
}

impl<A, R, C> CertificateOrderDriver<A, R, C>
where
    A: Clone,
    R: Clone,
{
    /// Binds one worker identity to durable authority, trusted roots, time and entropy.
    #[must_use]
    pub fn new(
        authority: A,
        random: R,
        clock: C,
        actor_principal_id: PrincipalId,
        policy: CertificateOrderDrivePolicy,
        result: CertificateOrderResultService,
    ) -> Self {
        Self {
            checkpoint: CertificateOrderCheckpointService::new(authority.clone()),
            completion: CertificateOrderCompletionService::new(authority.clone(), random.clone()),
            retry: CertificateOrderRetryService::new(authority),
            result,
            operation_random: random,
            clock,
            actor_principal_id,
            policy,
        }
    }
}

impl<A, R, C> CertificateOrderDriver<A, R, C>
where
    A: CertificateOrderCheckpointAuthority + CertificateOrderCompletionAuthority,
    R: Clone + RandomSource,
    C: Clock,
{
    /// Drives a prepared order until it blocks, completes, fails externally or reaches its budget.
    ///
    /// Every successful transition is checkpointed before the next action. Retry is limited to
    /// typed transport, protocol, challenge and certificate failures; local authority ambiguity
    /// fails closed rather than overwriting a possibly committed result.
    ///
    /// # Errors
    ///
    /// Rejects stale time/fences, invalid state, unavailable authority, contradictory receipts,
    /// entropy failure and unusable trust configuration.
    pub async fn drive<T, Challenge>(
        &mut self,
        execution: &mut CertificateOrderExecution<T, Challenge>,
    ) -> Result<CertificateOrderDriveOutcome, CertificateOrderDriverError>
    where
        T: AcmeTransport,
        Challenge: CertificateChallenge,
    {
        for completed_steps in 0..self.policy.maximum_steps {
            let now = self.clock.now();
            let context = self.request_context(execution, now)?;
            let challenge_expires_at = execution
                .assignment()
                .order
                .claim
                .ok_or(CertificateOrderDriverError::InvalidInput)?
                .lease_expires_at;
            let step = execution
                .execute_step(
                    &self.checkpoint,
                    self.actor_principal_id,
                    now,
                    context,
                    challenge_expires_at,
                )
                .await;
            match step {
                Ok(CertificateOrderStepResult::Pending) => {
                    return Ok(CertificateOrderDriveOutcome::Pending);
                }
                Ok(CertificateOrderStepResult::Checkpointed(_)) => {
                    if completed_steps + 1 == self.policy.maximum_steps {
                        return Ok(CertificateOrderDriveOutcome::Yielded {
                            steps: completed_steps + 1,
                        });
                    }
                }
                Ok(CertificateOrderStepResult::ReadyForCompletion { certificate_chain }) => {
                    return self.complete_or_retry(execution, now, &certificate_chain);
                }
                Err(error) => return self.execution_failure(execution, now, error),
            }
        }
        Err(CertificateOrderDriverError::InvalidInput)
    }

    fn request_context<T, Challenge>(
        &mut self,
        execution: &CertificateOrderExecution<T, Challenge>,
        now: UnixMicros,
    ) -> Result<RequestContext, CertificateOrderDriverError> {
        let claim = execution
            .assignment()
            .order
            .claim
            .ok_or(CertificateOrderDriverError::InvalidInput)?;
        let latest_deadline = claim
            .lease_expires_at
            .get()
            .checked_sub(1)
            .ok_or(CertificateOrderDriverError::InvalidInput)?;
        let requested_deadline = now
            .checked_add(self.policy.request_timeout)
            .ok_or(CertificateOrderDriverError::InvalidInput)?
            .get();
        let deadline = UnixMicros::new(requested_deadline.min(latest_deadline));
        if now.get() < 0 || deadline <= now {
            return Err(CertificateOrderDriverError::InvalidInput);
        }
        let mut bytes = [0_u8; 16];
        self.operation_random.fill_bytes(&mut bytes)?;
        Ok(RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes(uuid_v8(bytes))?,
            deadline,
            expected_revision: Some(execution.assignment().configuration.revision),
        })
    }

    fn execution_failure<T, Challenge>(
        &self,
        execution: &CertificateOrderExecution<T, Challenge>,
        now: UnixMicros,
        error: CertificateOrderExecutionError,
    ) -> Result<CertificateOrderDriveOutcome, CertificateOrderDriverError> {
        let failure_class = match error {
            CertificateOrderExecutionError::Worker(AcmeWorkerError::Transport) => {
                CertificateOrderFailureClass::Transport
            }
            CertificateOrderExecutionError::Worker(AcmeWorkerError::Protocol) => {
                CertificateOrderFailureClass::Protocol
            }
            CertificateOrderExecutionError::Worker(AcmeWorkerError::Challenge) => {
                CertificateOrderFailureClass::Challenge
            }
            other => return Err(other.into()),
        };
        self.retry(execution, now, failure_class)
    }

    fn complete_or_retry<T, Challenge>(
        &mut self,
        execution: &CertificateOrderExecution<T, Challenge>,
        now: UnixMicros,
        certificate_chain: &[u8],
    ) -> Result<CertificateOrderDriveOutcome, CertificateOrderDriverError> {
        match self.result.complete(
            &mut self.completion,
            self.actor_principal_id,
            now,
            execution,
            certificate_chain,
        ) {
            Ok(commit) => Ok(CertificateOrderDriveOutcome::Completed(commit)),
            Err(
                CertificateOrderResultError::InvalidCertificate
                | CertificateOrderResultError::Validation(_),
            ) => self.retry(execution, now, CertificateOrderFailureClass::Certificate),
            Err(error) => Err(error.into()),
        }
    }

    fn retry<T, Challenge>(
        &self,
        execution: &CertificateOrderExecution<T, Challenge>,
        now: UnixMicros,
        failure_class: CertificateOrderFailureClass,
    ) -> Result<CertificateOrderDriveOutcome, CertificateOrderDriverError> {
        let commit = self.retry.retry(
            self.actor_principal_id,
            now,
            execution.assignment(),
            failure_class,
            None,
        )?;
        Ok(CertificateOrderDriveOutcome::Retried {
            failure_class,
            commit,
        })
    }
}

/// Closed failure from composing one prepared certificate-order execution.
#[derive(Debug, Error)]
pub enum CertificateOrderDriverError {
    /// Policy, time, fence or execution input is invalid.
    #[error("certificate order driver input is invalid")]
    InvalidInput,
    /// Secure operation identity entropy is unavailable.
    #[error("certificate order driver entropy is unavailable")]
    Entropy(#[from] meshspan_domain::EntropyError),
    /// Operation identity construction failed.
    #[error("certificate order driver identity is invalid")]
    Identifier(#[from] meshspan_domain::IdentifierError),
    /// Step execution or checkpointing failed without a safe retry classification.
    #[error("certificate order driver execution failed")]
    Execution(#[from] CertificateOrderExecutionError),
    /// Terminal certificate validation or publication failed without a safe retry classification.
    #[error("certificate order driver result failed")]
    Result(#[from] CertificateOrderResultError),
    /// The failed order could not be authoritatively returned to its queue.
    #[error("certificate order driver retry failed")]
    Retry(#[from] CertificateOrderRetryError),
}
