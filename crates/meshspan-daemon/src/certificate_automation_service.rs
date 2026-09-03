// SPDX-License-Identifier: GPL-2.0-only

//! Single-worker composition of ACME renewal, admission, preparation and bounded execution.

use meshspan_acme::AcmeTransport;
use meshspan_contracts::CertificateChallenge;
use meshspan_domain::{Clock, DurationMicros, NodeId, RandomSource};
use meshspan_metadata::DueCertificateOrderCursor;
use thiserror::Error;

use crate::{
    CertificateOrderAssignment, CertificateOrderDispatchError, CertificateOrderDispatcher,
    CertificateOrderDriveOutcome, CertificateOrderDrivePolicy, CertificateOrderDriver,
    CertificateOrderDriverError, CertificateOrderExecution, CertificateOrderPreparationError,
    CertificateOrderPreparationService, CertificateOrderResultService,
    CertificateOrderWorkerAuthority, CertificateRenewalAuthority, CertificateRenewalScheduleCommit,
    CertificateRenewalScheduleError, CertificateRenewalScheduler, PreparedCertificateOrder,
};

const MAXIMUM_ADMISSION_PAGE_ITEMS: usize = 1_000;

type FactoryExecution<F> = CertificateOrderExecution<
    <F as CertificateExecutionFactory>::Transport,
    <F as CertificateExecutionFactory>::Challenge,
>;

/// Scheduling and bounded-execution policy for one daemon certificate worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateAutomationPolicy {
    claim_lease: DurationMicros,
    renewal_lead: DurationMicros,
    admission_page_items: usize,
    drive: CertificateOrderDrivePolicy,
}

impl CertificateAutomationPolicy {
    /// Creates one finite certificate worker policy.
    ///
    /// # Errors
    ///
    /// Rejects empty leases, renewal windows or pages and excessive admission pages.
    pub fn new(
        claim_lease: DurationMicros,
        renewal_lead: DurationMicros,
        admission_page_items: usize,
        drive: CertificateOrderDrivePolicy,
    ) -> Result<Self, CertificateAutomationError> {
        if claim_lease.get() < 2
            || renewal_lead.get() == 0
            || admission_page_items == 0
            || admission_page_items > MAXIMUM_ADMISSION_PAGE_ITEMS
        {
            return Err(CertificateAutomationError::InvalidInput);
        }
        Ok(Self {
            claim_lease,
            renewal_lead,
            admission_page_items,
            drive,
        })
    }
}

/// Protected order preparation boundary used by the runtime composition.
pub trait CertificateOrderPreparer {
    /// Loads or creates protected keys and returns one resumable order machine.
    ///
    /// # Errors
    ///
    /// Fails closed for stale claims, unavailable secrets, invalid checkpoints or failed receipts.
    fn prepare_order(
        &mut self,
        now: meshspan_domain::UnixMicros,
        assignment: CertificateOrderAssignment,
    ) -> Result<PreparedCertificateOrder, CertificateOrderPreparationError>;
}

impl<A, D, R> CertificateOrderPreparer for CertificateOrderPreparationService<A, D, R>
where
    A: crate::CertificateOrderPreparationAuthority,
    D: crate::SecretGenerationDecryptor,
    R: RandomSource,
{
    fn prepare_order(
        &mut self,
        now: meshspan_domain::UnixMicros,
        assignment: CertificateOrderAssignment,
    ) -> Result<PreparedCertificateOrder, CertificateOrderPreparationError> {
        self.prepare(now, assignment)
    }
}

/// Selects the concrete in-process ACME transport and challenge implementation for an order.
pub trait CertificateExecutionFactory {
    /// Direct bounded ACME HTTP transport.
    type Transport: AcmeTransport;
    /// HTTP-01 or DNS-01 publication implementation.
    type Challenge: CertificateChallenge;

    /// Creates execution components from the immutable persisted configuration.
    ///
    /// # Errors
    ///
    /// Rejects unsupported or unavailable provider configuration without contacting the CA.
    fn create_execution(
        &mut self,
        prepared: PreparedCertificateOrder,
    ) -> Result<
        CertificateOrderExecution<Self::Transport, Self::Challenge>,
        CertificateExecutionFactoryError,
    >;
}

/// One observable pass of the certificate automation service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateAutomationOutcome {
    /// No order was active or due.
    Idle {
        /// A replacement order may have been queued immediately before the bounded due read.
        renewal: Option<CertificateRenewalScheduleCommit>,
    },
    /// One claimed order made bounded progress.
    Order {
        /// Replacement order queued during this pass, if any.
        renewal: Option<CertificateRenewalScheduleCommit>,
        /// Durable execution outcome for the active order.
        drive: CertificateOrderDriveOutcome,
    },
}

/// Stateful one-order-at-a-time ACME automation service for one daemon incarnation.
pub struct CertificateAutomationService<A, P, F, R, C>
where
    A: Clone,
    F: CertificateExecutionFactory,
{
    authority: A,
    preparation: P,
    execution_factory: F,
    driver: CertificateOrderDriver<A, R, C>,
    dispatch_random: R,
    clock: C,
    worker_node_id: NodeId,
    worker_incarnation: u64,
    policy: CertificateAutomationPolicy,
    active: Option<FactoryExecution<F>>,
}

/// Inputs with independent ownership needed to construct a certificate automation service.
pub struct CertificateAutomationComponents<A, P, F, R, C> {
    /// Consensus-backed authority used by renewal and order admission.
    pub authority: A,
    /// Independently owned consensus reader used by checkpoint, retry and completion driving.
    pub driver_authority: A,
    /// Protected key and checkpoint preparation capability.
    pub preparation: P,
    /// Concrete transport/challenge selector.
    pub execution_factory: F,
    /// Cryptographic operation entropy.
    pub random: R,
    /// Authority-aligned clock.
    pub clock: C,
    /// Exact local worker node.
    pub worker_node_id: NodeId,
    /// Restart incarnation fencing old workers.
    pub worker_incarnation: u64,
    /// Bounded scheduling and execution policy.
    pub policy: CertificateAutomationPolicy,
    /// Explicit CA trust-path validator.
    pub result: CertificateOrderResultService,
}

impl<A, P, F, R, C> CertificateAutomationService<A, P, F, R, C>
where
    A: Clone,
    F: CertificateExecutionFactory,
    R: Clone,
    C: Clone,
{
    /// Composes one daemon-local fenced certificate worker.
    #[must_use]
    pub fn new(components: CertificateAutomationComponents<A, P, F, R, C>) -> Self {
        let driver = CertificateOrderDriver::new(
            components.driver_authority,
            components.random.clone(),
            components.clock.clone(),
            components.policy.drive,
            components.result,
        );
        Self {
            authority: components.authority,
            preparation: components.preparation,
            execution_factory: components.execution_factory,
            driver,
            dispatch_random: components.random,
            clock: components.clock,
            worker_node_id: components.worker_node_id,
            worker_incarnation: components.worker_incarnation,
            policy: components.policy,
            active: None,
        }
    }
}

impl<A, P, F, R, C> CertificateAutomationService<A, P, F, R, C>
where
    A: Clone
        + CertificateOrderWorkerAuthority
        + CertificateRenewalAuthority
        + crate::CertificateOrderCheckpointAuthority
        + crate::CertificateOrderCompletionAuthority,
    P: CertificateOrderPreparer,
    F: CertificateExecutionFactory,
    R: Clone + RandomSource,
    C: Clone + Clock,
{
    /// Runs one bounded scheduling and execution pass without overlapping certificate orders.
    ///
    /// # Errors
    ///
    /// Fails closed for invalid time, entropy, persisted projections, provider configuration,
    /// consensus ambiguity, stale fencing or terminal validation failures.
    pub async fn run_once(
        &mut self,
    ) -> Result<CertificateAutomationOutcome, CertificateAutomationError> {
        let now = self.clock.now();
        let renewal = CertificateRenewalScheduler::new(&self.authority).schedule_next(
            now,
            self.policy.renewal_lead,
            None,
            self.policy.admission_page_items,
        )?;
        if self.active.is_none() {
            self.active = self.claim_and_prepare(now)?;
        }
        let Some(active) = self.active.as_mut() else {
            return Ok(CertificateAutomationOutcome::Idle { renewal });
        };
        let drive = self.driver.drive(active).await?;
        if matches!(
            drive,
            CertificateOrderDriveOutcome::Completed(_)
                | CertificateOrderDriveOutcome::Retried { .. }
        ) {
            self.active = None;
        }
        Ok(CertificateAutomationOutcome::Order { renewal, drive })
    }

    fn claim_and_prepare(
        &mut self,
        now: meshspan_domain::UnixMicros,
    ) -> Result<Option<FactoryExecution<F>>, CertificateAutomationError> {
        let assignment = CertificateOrderDispatcher::new(
            &self.authority,
            &mut self.dispatch_random,
            self.worker_node_id,
            self.worker_incarnation,
        )
        .claim_next(
            now,
            self.policy.claim_lease,
            Option::<&DueCertificateOrderCursor>::None,
            self.policy.admission_page_items,
        )?;
        let Some(assignment) = assignment else {
            return Ok(None);
        };
        let prepared = self.preparation.prepare_order(now, assignment)?;
        Ok(Some(self.execution_factory.create_execution(prepared)?))
    }
}

/// Closed execution-factory failure without provider secrets or remote diagnostics.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CertificateExecutionFactoryError {
    /// Persisted provider selection or settings are invalid.
    #[error("certificate execution provider configuration is invalid")]
    InvalidConfiguration,
    /// Configured in-process provider is temporarily unavailable.
    #[error("certificate execution provider is unavailable")]
    Unavailable,
}

/// Closed failure from one certificate automation pass.
#[derive(Debug, Error)]
pub enum CertificateAutomationError {
    /// Worker policy or identity is invalid.
    #[error("certificate automation input is invalid")]
    InvalidInput,
    /// Renewal admission failed.
    #[error("certificate renewal scheduling failed")]
    Renewal(#[from] CertificateRenewalScheduleError),
    /// Due-order dispatch failed.
    #[error("certificate order dispatch failed")]
    Dispatch(#[from] CertificateOrderDispatchError),
    /// Protected order preparation failed.
    #[error("certificate order preparation failed")]
    Preparation(#[from] CertificateOrderPreparationError),
    /// Concrete challenge or transport construction failed.
    #[error("certificate execution construction failed")]
    Factory(#[from] CertificateExecutionFactoryError),
    /// Bounded execution, completion or retry failed.
    #[error("certificate order driving failed")]
    Driver(#[from] CertificateOrderDriverError),
}
