// SPDX-License-Identifier: GPL-2.0-only

//! Bounded storage-target scrub execution with authoritative completion evidence.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_contracts::{
    BoundedBytes, ContractError, ScrubObservation, ScrubOutcome, ScrubPage, StorageProvider,
};
use meshspan_domain::{TargetId, UnixMicros, WorkId};
use meshspan_metadata::{
    AuthoritativeCommand, ClaimMaintenanceWork, CommandContext, CommandReceipt, CommitScrubPass,
    CommitTargetReconciliation, CompleteMaintenanceWork, LocalDatabase, LocalScrubProgress,
    LocalScrubProgressError, LocalScrubProgressUpdate, MaintenanceEffectReference,
    MaintenanceWorkCompletion,
};
use thiserror::Error;

use crate::{
    ConsensusAuthenticationAuthority, MaintenanceMetadataAuthority, ScrubFindingSchedulingError,
    ScrubFindingSink,
};

/// Exact identities and execution bounds for one already-selected scrub job.
pub struct StorageScrubExecution {
    /// Idempotency, actor, audit and time context for the claim command.
    pub claim_context: CommandContext,
    /// Independent context for the complete-pass effect.
    pub effect_context: CommandContext,
    /// Independent context for the exact work-completion link.
    pub completion_context: CommandContext,
    /// Next fenced claim generation selected from authoritative job state.
    pub claim: ClaimMaintenanceWork,
    /// Storage target bound into the scrub work subject.
    pub target_id: TargetId,
    /// Exact target generation inspected by the provider.
    pub target_generation: u64,
    /// Maximum observations requested in each provider call.
    pub page_items: usize,
    /// Maximum provider pages consumed by this bounded attempt.
    pub maximum_pages: usize,
    /// Authority-agreed instant attached to physical observations.
    pub observed_at: UnixMicros,
}

/// Validated summary of one complete provider pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageScrubSummary {
    /// Total classified observations.
    pub observation_count: u64,
    /// Bytes independently read and digested.
    pub verified_bytes: u64,
    /// Exact outcome totals ordered as healthy, missing, corrupt, unreadable, unexpected, deferred.
    pub outcome_counts: [u64; 6],
    /// Canonical digest over the target and complete ordered evidence stream.
    pub evidence_digest: [u8; 32],
}

/// Durable evidence returned only after the scrub job becomes terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageScrubExecutionReceipt {
    /// Complete validated pass summary.
    pub summary: StorageScrubSummary,
    /// Authoritative scrub effect.
    pub effect: CommandReceipt,
    /// Terminal maintenance-job receipt linked to `effect`.
    pub completion: CommandReceipt,
}

/// Exact bounded attempt for a restart-safe paged target scrub.
pub struct ResumableStorageScrubExecution {
    /// Idempotency, actor, audit and time context for the claim command.
    pub claim_context: CommandContext,
    /// Independent context for the complete-pass effect, used only at end-of-cycle.
    pub effect_context: CommandContext,
    /// Independent context releasing this claim as continued or terminal.
    pub completion_context: CommandContext,
    /// Next fenced claim generation selected from authoritative job state.
    pub claim: ClaimMaintenanceWork,
    /// Storage target bound into the scrub work subject.
    pub target_id: TargetId,
    /// Exact target generation inspected by the provider.
    pub target_generation: u64,
    /// Maximum observations read and retained by this attempt.
    pub page_items: usize,
    /// Authority-agreed instant attached to physical observations.
    pub observed_at: UnixMicros,
    /// Earliest authority-agreed instant for the next page claim.
    pub continuation_at: UnixMicros,
}

/// Durable outcome of one resumable scrub attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResumableStorageScrubReceipt {
    /// One non-terminal page was durably checkpointed and the claim was released.
    Continued {
        /// Exact local progress after the accepted page.
        progress: LocalScrubProgress,
        /// Authoritative continuation receipt.
        completion: CommandReceipt,
    },
    /// This attempt completed the provider cycle and terminal work effect.
    Completed(StorageScrubExecutionReceipt),
    /// A prior attempt committed the effect; this claim linked it terminally without more IO.
    Recovered {
        /// Previously committed immutable effect.
        effect: MaintenanceEffectReference,
        /// Terminal work-completion receipt from this claim.
        completion: CommandReceipt,
    },
}

/// Reconciliation uses the same bounded physical verification evidence as scrub while committing
/// a distinct authoritative effect and operation kind.
pub type ResumableTargetReconciliationReceipt = ResumableStorageScrubReceipt;

#[derive(Clone, Copy)]
enum VerificationPurpose {
    Scrub,
    Reconciliation,
}

/// Closed failure phases; none claims success without an exact committed effect.
#[derive(Debug, Error)]
pub enum StorageScrubExecutionError {
    /// Claim, effect or completion could not be committed by metadata consensus.
    #[error("scrub metadata authority rejected or could not commit a transition")]
    Authority(#[from] MetadataAuthorityRequestError),
    /// Provider IO failed before a complete evidence stream existed.
    #[error("storage provider could not complete the bounded scrub pass")]
    Physical(#[from] ContractError),
    /// Cross-step identities, timing or execution bounds disagree.
    #[error("scrub execution input contradicts its claim or bounds")]
    InvalidInput,
    /// Provider output was malformed, contradictory or could not make bounded progress.
    #[error("storage provider returned invalid scrub evidence")]
    InvalidEvidence,
    /// The pass exceeded its explicit page bound before reaching the end.
    #[error("storage scrub pass exceeded its configured page bound")]
    PassLimitExceeded,
    /// A validated non-healthy observation could not be safely admitted for follow-up.
    #[error("storage scrub finding could not be scheduled")]
    Finding(#[from] ScrubFindingSchedulingError),
    /// Restart-safe local page progress could not be loaded or advanced.
    #[error("storage scrub progress could not be persisted")]
    Progress(#[from] LocalScrubProgressError),
    /// An already committed authoritative effect could not be queried safely.
    #[error("storage scrub committed-effect recovery failed")]
    Recovery(#[from] meshspan_metadata::RepositoryError),
}

/// Read extension used to close the effect-committed/completion-lost crash window.
pub trait RecoverableMaintenanceAuthority: MaintenanceMetadataAuthority {
    /// Returns the immutable effect already committed for one work item, if any.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed authoritative state or database failure.
    fn effect_reference(
        &self,
        work_id: WorkId,
    ) -> Result<Option<MaintenanceEffectReference>, meshspan_metadata::RepositoryError>;
}

impl RecoverableMaintenanceAuthority for ConsensusAuthenticationAuthority {
    fn effect_reference(
        &self,
        work_id: WorkId,
    ) -> Result<Option<MaintenanceEffectReference>, meshspan_metadata::RepositoryError> {
        self.reader().maintenance_effect_reference(work_id)
    }
}

/// Replaceable restart journal boundary for bounded scrub pages.
pub trait ScrubProgressStore {
    /// Loads or creates one identity-bound initial checkpoint.
    ///
    /// # Errors
    ///
    /// Rejects identity reuse, corruption and durable IO failure.
    fn load_or_create(
        &mut self,
        work_id: WorkId,
        target_id: TargetId,
        target_generation: u64,
        now: UnixMicros,
    ) -> Result<LocalScrubProgress, LocalScrubProgressError>;

    /// Advances one validated page through exact compare-and-set.
    ///
    /// # Errors
    ///
    /// Rejects stale writers, invalid progress and durable IO failure.
    fn advance(
        &mut self,
        expected: &LocalScrubProgress,
        update: &LocalScrubProgressUpdate,
        now: UnixMicros,
    ) -> Result<LocalScrubProgress, LocalScrubProgressError>;
}

impl ScrubProgressStore for LocalDatabase {
    fn load_or_create(
        &mut self,
        work_id: WorkId,
        target_id: TargetId,
        target_generation: u64,
        now: UnixMicros,
    ) -> Result<LocalScrubProgress, LocalScrubProgressError> {
        self.load_or_create_scrub_progress(work_id, target_id, target_generation, now)
    }

    fn advance(
        &mut self,
        expected: &LocalScrubProgress,
        update: &LocalScrubProgressUpdate,
        now: UnixMicros,
    ) -> Result<LocalScrubProgress, LocalScrubProgressError> {
        self.advance_scrub_progress(expected, update, now)
    }
}

/// Replaceable physical page boundary used by scrub orchestration.
pub trait PhysicalStorageScrub {
    /// Independently verifies one bounded stable page of complete shard bytes.
    ///
    /// # Errors
    ///
    /// Rejects malformed cursors/bounds or target-wide IO failure.
    fn scrub_page(
        &mut self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
        observed_at: UnixMicros,
    ) -> Result<ScrubPage, ContractError>;
}

impl<Provider: StorageProvider> PhysicalStorageScrub for Provider {
    fn scrub_page(
        &mut self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
        observed_at: UnixMicros,
    ) -> Result<ScrubPage, ContractError> {
        self.scrub(cursor, limit, observed_at)
    }
}

/// Claims and completes one full provider scrub in bounded pages.
///
/// The function retains only the current page, cursor, counters and digest state. A provider or
/// process failure cannot produce an authoritative success effect. Callers may retry the still-
/// durable job under a newly fenced claim.
///
/// # Errors
///
/// Rejects contradictory execution input, invalid provider evidence, a pass exceeding its
/// explicit bound, provider failure, or a metadata transition that cannot be committed.
pub fn execute_storage_scrub<Authority, Provider, Findings>(
    authority: &Authority,
    provider: &mut Provider,
    findings: &mut Findings,
    execution: &StorageScrubExecution,
) -> Result<StorageScrubExecutionReceipt, StorageScrubExecutionError>
where
    Authority: MaintenanceMetadataAuthority,
    Provider: PhysicalStorageScrub,
    Findings: ScrubFindingSink,
{
    validate_execution(execution)?;
    authority.commit(
        execution.claim_context,
        &AuthoritativeCommand::ClaimMaintenanceWork(execution.claim),
    )?;
    let summary = scrub_all_pages(provider, findings, execution)?;
    let counts = summary.outcome_counts;
    let effect = authority.commit(
        execution.effect_context,
        &AuthoritativeCommand::CommitScrubPass(CommitScrubPass {
            work_id: execution.claim.work_id,
            claim_generation: execution.claim.claim_generation,
            worker_node_id: execution.claim.worker_node_id,
            worker_incarnation: execution.claim.worker_incarnation,
            fence: execution.claim.fence,
            target_id: execution.target_id,
            target_generation: execution.target_generation,
            observation_count: summary.observation_count,
            verified_bytes: summary.verified_bytes,
            healthy_count: counts[0],
            missing_count: counts[1],
            corrupt_count: counts[2],
            unreadable_count: counts[3],
            unexpected_count: counts[4],
            deferred_count: counts[5],
            evidence_digest: summary.evidence_digest,
        }),
    )?;
    let completion = authority.commit(
        execution.completion_context,
        &AuthoritativeCommand::CompleteMaintenanceWork(CompleteMaintenanceWork {
            work_id: execution.claim.work_id,
            claim_generation: execution.claim.claim_generation,
            worker_node_id: execution.claim.worker_node_id,
            worker_incarnation: execution.claim.worker_incarnation,
            fence: execution.claim.fence,
            outcome: MaintenanceWorkCompletion::Succeeded {
                effect_operation_id: effect.operation_id,
                effect_revision: effect.committed_revision,
                effect_result_digest: effect.result_digest,
            },
        }),
    )?;
    Ok(StorageScrubExecutionReceipt {
        summary,
        effect,
        completion,
    })
}

/// Claims and executes at most one restart-safe provider page.
///
/// Non-terminal pages are accumulated in the local compare-and-set journal before the claim is
/// released with an explicit continuation outcome. A crash before that local commit repeats the
/// page and deduplicated findings; a crash after the final authoritative effect is recovered by
/// linking the existing effect from a later claim without repeating provider IO.
///
/// # Errors
///
/// Rejects contradictory execution input, malformed provider evidence, unsafe local progress,
/// finding admission failure and unavailable metadata authority.
pub fn execute_resumable_storage_scrub<Authority, Provider, Findings, Progress>(
    authority: &Authority,
    provider: &mut Provider,
    findings: &mut Findings,
    progress_store: &mut Progress,
    execution: &ResumableStorageScrubExecution,
) -> Result<ResumableStorageScrubReceipt, StorageScrubExecutionError>
where
    Authority: RecoverableMaintenanceAuthority,
    Provider: PhysicalStorageScrub,
    Findings: ScrubFindingSink,
    Progress: ScrubProgressStore,
{
    execute_resumable_storage_verification(
        authority,
        provider,
        findings,
        progress_store,
        execution,
        VerificationPurpose::Scrub,
    )
}

/// Reconciles one returning target through the same restart-safe full-byte inventory walk.
///
/// Non-healthy or no-longer-current entries are fed through the ordinary finding scheduler; the
/// pass records its own authoritative reconciliation effect rather than masquerading as a
/// periodic scrub.
///
/// # Errors
///
/// Rejects invalid claims, malformed provider evidence, unsafe progress, finding admission
/// failure and unavailable metadata authority.
pub fn execute_resumable_target_reconciliation<Authority, Provider, Findings, Progress>(
    authority: &Authority,
    provider: &mut Provider,
    findings: &mut Findings,
    progress_store: &mut Progress,
    execution: &ResumableStorageScrubExecution,
) -> Result<ResumableTargetReconciliationReceipt, StorageScrubExecutionError>
where
    Authority: RecoverableMaintenanceAuthority,
    Provider: PhysicalStorageScrub,
    Findings: ScrubFindingSink,
    Progress: ScrubProgressStore,
{
    execute_resumable_storage_verification(
        authority,
        provider,
        findings,
        progress_store,
        execution,
        VerificationPurpose::Reconciliation,
    )
}

fn execute_resumable_storage_verification<Authority, Provider, Findings, Progress>(
    authority: &Authority,
    provider: &mut Provider,
    findings: &mut Findings,
    progress_store: &mut Progress,
    execution: &ResumableStorageScrubExecution,
    purpose: VerificationPurpose,
) -> Result<ResumableStorageScrubReceipt, StorageScrubExecutionError>
where
    Authority: RecoverableMaintenanceAuthority,
    Provider: PhysicalStorageScrub,
    Findings: ScrubFindingSink,
    Progress: ScrubProgressStore,
{
    validate_resumable_execution(execution)?;
    authority.commit(
        execution.claim_context,
        &AuthoritativeCommand::ClaimMaintenanceWork(execution.claim),
    )?;
    if let Some(effect) = authority.effect_reference(execution.claim.work_id)? {
        let completion = complete_existing_effect(authority, execution, effect)?;
        return Ok(ResumableStorageScrubReceipt::Recovered { effect, completion });
    }
    let progress = progress_store.load_or_create(
        execution.claim.work_id,
        execution.target_id,
        execution.target_generation,
        execution.observed_at,
    )?;
    if progress.complete {
        return commit_completed_progress(authority, execution, &progress, purpose)
            .map(ResumableStorageScrubReceipt::Completed);
    }
    let cursor = progress
        .next_cursor
        .as_deref()
        .map(|bytes| BoundedBytes::copy_from(bytes, 512))
        .transpose()
        .map_err(|_| StorageScrubExecutionError::InvalidEvidence)?;
    let page = provider.scrub_page(cursor.as_ref(), execution.page_items, execution.observed_at)?;
    validate_page(&page, cursor.as_ref(), execution.page_items)?;
    for observation in page.observations.as_slice() {
        if observation.outcome != ScrubOutcome::Healthy {
            findings.record(
                execution.target_id,
                execution.target_generation,
                *observation,
                execution.observed_at,
            )?;
        }
    }
    let update = accumulate_progress(&progress, &page)?;
    let progress = progress_store.advance(&progress, &update, execution.observed_at)?;
    if progress.complete {
        commit_completed_progress(authority, execution, &progress, purpose)
            .map(ResumableStorageScrubReceipt::Completed)
    } else {
        let completion = authority.commit(
            execution.completion_context,
            &AuthoritativeCommand::CompleteMaintenanceWork(CompleteMaintenanceWork {
                work_id: execution.claim.work_id,
                claim_generation: execution.claim.claim_generation,
                worker_node_id: execution.claim.worker_node_id,
                worker_incarnation: execution.claim.worker_incarnation,
                fence: execution.claim.fence,
                outcome: MaintenanceWorkCompletion::Continue {
                    progress_digest: progress_digest(&progress),
                    retry_at: execution.continuation_at,
                },
            }),
        )?;
        Ok(ResumableStorageScrubReceipt::Continued {
            progress,
            completion,
        })
    }
}

fn complete_existing_effect<Authority: MaintenanceMetadataAuthority>(
    authority: &Authority,
    execution: &ResumableStorageScrubExecution,
    effect: MaintenanceEffectReference,
) -> Result<CommandReceipt, StorageScrubExecutionError> {
    authority
        .commit(
            execution.completion_context,
            &AuthoritativeCommand::CompleteMaintenanceWork(CompleteMaintenanceWork {
                work_id: execution.claim.work_id,
                claim_generation: execution.claim.claim_generation,
                worker_node_id: execution.claim.worker_node_id,
                worker_incarnation: execution.claim.worker_incarnation,
                fence: execution.claim.fence,
                outcome: MaintenanceWorkCompletion::Succeeded {
                    effect_operation_id: effect.operation_id,
                    effect_revision: effect.revision,
                    effect_result_digest: effect.result_digest,
                },
            }),
        )
        .map_err(Into::into)
}

fn commit_completed_progress<Authority: MaintenanceMetadataAuthority>(
    authority: &Authority,
    execution: &ResumableStorageScrubExecution,
    progress: &LocalScrubProgress,
    purpose: VerificationPurpose,
) -> Result<StorageScrubExecutionReceipt, StorageScrubExecutionError> {
    let summary = summary_from_progress(progress, purpose)?;
    let counts = summary.outcome_counts;
    let scrub = CommitScrubPass {
        work_id: execution.claim.work_id,
        claim_generation: execution.claim.claim_generation,
        worker_node_id: execution.claim.worker_node_id,
        worker_incarnation: execution.claim.worker_incarnation,
        fence: execution.claim.fence,
        target_id: execution.target_id,
        target_generation: execution.target_generation,
        observation_count: summary.observation_count,
        verified_bytes: summary.verified_bytes,
        healthy_count: counts[0],
        missing_count: counts[1],
        corrupt_count: counts[2],
        unreadable_count: counts[3],
        unexpected_count: counts[4],
        deferred_count: counts[5],
        evidence_digest: summary.evidence_digest,
    };
    let command = match purpose {
        VerificationPurpose::Scrub => AuthoritativeCommand::CommitScrubPass(scrub),
        VerificationPurpose::Reconciliation => {
            AuthoritativeCommand::CommitTargetReconciliation(CommitTargetReconciliation {
                work_id: scrub.work_id,
                claim_generation: scrub.claim_generation,
                worker_node_id: scrub.worker_node_id,
                worker_incarnation: scrub.worker_incarnation,
                fence: scrub.fence,
                target_id: scrub.target_id,
                target_generation: scrub.target_generation,
                observation_count: scrub.observation_count,
                verified_bytes: scrub.verified_bytes,
                healthy_count: scrub.healthy_count,
                missing_count: scrub.missing_count,
                corrupt_count: scrub.corrupt_count,
                unreadable_count: scrub.unreadable_count,
                unexpected_count: scrub.unexpected_count,
                deferred_count: scrub.deferred_count,
                evidence_digest: scrub.evidence_digest,
            })
        }
    };
    let effect = authority.commit(execution.effect_context, &command)?;
    let completion = complete_existing_effect(
        authority,
        execution,
        MaintenanceEffectReference {
            operation_id: effect.operation_id,
            revision: effect.committed_revision,
            result_digest: effect.result_digest,
        },
    )?;
    Ok(StorageScrubExecutionReceipt {
        summary,
        effect,
        completion,
    })
}

fn validate_page(
    page: &ScrubPage,
    current_cursor: Option<&BoundedBytes>,
    page_items: usize,
) -> Result<(), StorageScrubExecutionError> {
    if page.observations.len() > page_items
        || page.next_cursor.as_ref().is_some_and(|next| {
            next.is_empty()
                || current_cursor.is_some_and(|current| current == next)
                || page.observations.is_empty()
        })
    {
        return Err(StorageScrubExecutionError::InvalidEvidence);
    }
    for observation in page.observations.as_slice() {
        validate_observation(*observation)?;
    }
    Ok(())
}

fn accumulate_progress(
    progress: &LocalScrubProgress,
    page: &ScrubPage,
) -> Result<LocalScrubProgressUpdate, StorageScrubExecutionError> {
    let mut observation_count = progress.observation_count;
    let mut verified_bytes = progress.verified_bytes;
    let mut outcome_counts = progress.outcome_counts;
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.storage.scrub-progress-page.v1\0");
    digest.update(&progress.target_id.as_bytes());
    digest.update(&progress.target_generation.to_be_bytes());
    digest.update(&progress.page_index.to_be_bytes());
    digest.update(&progress.rolling_evidence_digest);
    digest.update(
        &u64::try_from(page.observations.len())
            .map_err(|_| StorageScrubExecutionError::InvalidEvidence)?
            .to_be_bytes(),
    );
    for observation in page.observations.as_slice() {
        observation_count = observation_count
            .checked_add(1)
            .ok_or(StorageScrubExecutionError::InvalidEvidence)?;
        let outcome_index = usize::from(outcome_code(observation.outcome) - 1);
        outcome_counts[outcome_index] = outcome_counts[outcome_index]
            .checked_add(1)
            .ok_or(StorageScrubExecutionError::InvalidEvidence)?;
        if matches!(
            observation.outcome,
            ScrubOutcome::Healthy | ScrubOutcome::Corrupt
        ) {
            verified_bytes = verified_bytes
                .checked_add(
                    observation
                        .observed_length
                        .ok_or(StorageScrubExecutionError::InvalidEvidence)?,
                )
                .ok_or(StorageScrubExecutionError::InvalidEvidence)?;
        }
        digest_observation(&mut digest, *observation);
    }
    Ok(LocalScrubProgressUpdate {
        next_cursor: page
            .next_cursor
            .as_ref()
            .map(|cursor| cursor.as_slice().to_vec()),
        observation_count,
        verified_bytes,
        outcome_counts,
        rolling_evidence_digest: digest.finalize().into(),
    })
}

fn summary_from_progress(
    progress: &LocalScrubProgress,
    purpose: VerificationPurpose,
) -> Result<StorageScrubSummary, StorageScrubExecutionError> {
    if !progress.complete || progress.rolling_evidence_digest == [0; 32] {
        return Err(StorageScrubExecutionError::InvalidEvidence);
    }
    let mut digest = blake3::Hasher::new();
    digest.update(match purpose {
        VerificationPurpose::Scrub => b"meshspan.storage.scrub-progress-complete.v1\0",
        VerificationPurpose::Reconciliation => {
            b"meshspan.storage.return-reconciliation-complete.v1\0"
        }
    });
    digest.update(&progress.target_id.as_bytes());
    digest.update(&progress.target_generation.to_be_bytes());
    digest.update(&progress.page_index.to_be_bytes());
    digest.update(&progress.observation_count.to_be_bytes());
    digest.update(&progress.verified_bytes.to_be_bytes());
    for count in progress.outcome_counts {
        digest.update(&count.to_be_bytes());
    }
    digest.update(&progress.rolling_evidence_digest);
    Ok(StorageScrubSummary {
        observation_count: progress.observation_count,
        verified_bytes: progress.verified_bytes,
        outcome_counts: progress.outcome_counts,
        evidence_digest: digest.finalize().into(),
    })
}

fn progress_digest(progress: &LocalScrubProgress) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.storage.scrub-progress-checkpoint.v1\0");
    digest.update(&progress.work_id.as_bytes());
    digest.update(&progress.target_id.as_bytes());
    digest.update(&progress.target_generation.to_be_bytes());
    digest.update(&progress.page_index.to_be_bytes());
    digest.update(&progress.revision.to_be_bytes());
    digest.update(&progress.rolling_evidence_digest);
    if let Some(cursor) = &progress.next_cursor {
        digest.update(cursor);
    }
    digest.finalize().into()
}

fn validate_resumable_execution(
    execution: &ResumableStorageScrubExecution,
) -> Result<(), StorageScrubExecutionError> {
    let claim = execution.claim;
    if execution.target_generation == 0
        || execution.page_items == 0
        || execution.page_items > 1_000
        || execution.claim_context.actor_principal_id != execution.effect_context.actor_principal_id
        || execution.claim_context.actor_principal_id
            != execution.completion_context.actor_principal_id
        || execution.claim_context.operation_id == execution.effect_context.operation_id
        || execution.claim_context.operation_id == execution.completion_context.operation_id
        || execution.effect_context.operation_id == execution.completion_context.operation_id
        || execution.claim_context.audit_event_id == execution.effect_context.audit_event_id
        || execution.claim_context.audit_event_id == execution.completion_context.audit_event_id
        || execution.effect_context.audit_event_id == execution.completion_context.audit_event_id
        || execution.claim_context.occurred_at > execution.observed_at
        || execution.observed_at > execution.effect_context.occurred_at
        || execution.effect_context.occurred_at > execution.completion_context.occurred_at
        || execution.continuation_at <= execution.completion_context.occurred_at
        || execution.claim_context.occurred_at >= claim.lease_expires_at
        || execution.effect_context.occurred_at >= claim.lease_expires_at
        || execution.completion_context.occurred_at >= claim.lease_expires_at
    {
        Err(StorageScrubExecutionError::InvalidInput)
    } else {
        Ok(())
    }
}

fn scrub_all_pages<Provider, Findings>(
    provider: &mut Provider,
    findings: &mut Findings,
    execution: &StorageScrubExecution,
) -> Result<StorageScrubSummary, StorageScrubExecutionError>
where
    Provider: PhysicalStorageScrub,
    Findings: ScrubFindingSink,
{
    let mut accumulator = ScrubAccumulator::new(execution.target_id, execution.target_generation);
    let mut cursor = None;
    for page_index in 0..execution.maximum_pages {
        let page =
            provider.scrub_page(cursor.as_ref(), execution.page_items, execution.observed_at)?;
        if page.observations.len() > execution.page_items {
            return Err(StorageScrubExecutionError::InvalidEvidence);
        }
        accumulator.add_page(page_index, page.observations.as_slice())?;
        for observation in page.observations.as_slice() {
            if observation.outcome != ScrubOutcome::Healthy {
                findings.record(
                    execution.target_id,
                    execution.target_generation,
                    *observation,
                    execution.observed_at,
                )?;
            }
        }
        match page.next_cursor {
            None => return Ok(accumulator.finish()),
            Some(next)
                if next.is_empty()
                    || cursor
                        .as_ref()
                        .is_some_and(|current: &BoundedBytes| current == &next)
                    || page.observations.is_empty() =>
            {
                return Err(StorageScrubExecutionError::InvalidEvidence);
            }
            Some(next) => cursor = Some(next),
        }
    }
    Err(StorageScrubExecutionError::PassLimitExceeded)
}

fn validate_execution(execution: &StorageScrubExecution) -> Result<(), StorageScrubExecutionError> {
    let claim = execution.claim;
    let total_bound = execution.page_items.checked_mul(execution.maximum_pages);
    if execution.target_generation == 0
        || execution.page_items == 0
        || execution.maximum_pages == 0
        || total_bound
            .and_then(|value| u64::try_from(value).ok())
            .is_none()
        || execution.claim_context.actor_principal_id != execution.effect_context.actor_principal_id
        || execution.claim_context.actor_principal_id
            != execution.completion_context.actor_principal_id
        || execution.claim_context.operation_id == execution.effect_context.operation_id
        || execution.claim_context.operation_id == execution.completion_context.operation_id
        || execution.effect_context.operation_id == execution.completion_context.operation_id
        || execution.claim_context.audit_event_id == execution.effect_context.audit_event_id
        || execution.claim_context.audit_event_id == execution.completion_context.audit_event_id
        || execution.effect_context.audit_event_id == execution.completion_context.audit_event_id
        || execution.claim_context.occurred_at > execution.observed_at
        || execution.observed_at > execution.effect_context.occurred_at
        || execution.effect_context.occurred_at > execution.completion_context.occurred_at
        || execution.claim_context.occurred_at >= claim.lease_expires_at
        || execution.effect_context.occurred_at >= claim.lease_expires_at
        || execution.completion_context.occurred_at >= claim.lease_expires_at
    {
        Err(StorageScrubExecutionError::InvalidInput)
    } else {
        Ok(())
    }
}

struct ScrubAccumulator {
    digest: blake3::Hasher,
    observation_count: u64,
    verified_bytes: u64,
    outcome_counts: [u64; 6],
}

impl ScrubAccumulator {
    fn new(target_id: TargetId, target_generation: u64) -> Self {
        let mut digest = blake3::Hasher::new();
        digest.update(b"meshspan.storage.scrub-pass.v1\0");
        digest.update(&target_id.as_bytes());
        digest.update(&target_generation.to_be_bytes());
        Self {
            digest,
            observation_count: 0,
            verified_bytes: 0,
            outcome_counts: [0; 6],
        }
    }

    fn add_page(
        &mut self,
        page_index: usize,
        observations: &[ScrubObservation],
    ) -> Result<(), StorageScrubExecutionError> {
        self.digest.update(
            &u64::try_from(page_index)
                .map_err(|_| StorageScrubExecutionError::InvalidEvidence)?
                .to_be_bytes(),
        );
        self.digest.update(
            &u64::try_from(observations.len())
                .map_err(|_| StorageScrubExecutionError::InvalidEvidence)?
                .to_be_bytes(),
        );
        for observation in observations {
            validate_observation(*observation)?;
            self.observation_count = self
                .observation_count
                .checked_add(1)
                .ok_or(StorageScrubExecutionError::InvalidEvidence)?;
            let outcome_index = usize::from(outcome_code(observation.outcome) - 1);
            self.outcome_counts[outcome_index] = self.outcome_counts[outcome_index]
                .checked_add(1)
                .ok_or(StorageScrubExecutionError::InvalidEvidence)?;
            if matches!(
                observation.outcome,
                ScrubOutcome::Healthy | ScrubOutcome::Corrupt
            ) {
                self.verified_bytes = self
                    .verified_bytes
                    .checked_add(
                        observation
                            .observed_length
                            .ok_or(StorageScrubExecutionError::InvalidEvidence)?,
                    )
                    .ok_or(StorageScrubExecutionError::InvalidEvidence)?;
            }
            digest_observation(&mut self.digest, *observation);
        }
        Ok(())
    }

    fn finish(mut self) -> StorageScrubSummary {
        self.digest.update(b"complete");
        StorageScrubSummary {
            observation_count: self.observation_count,
            verified_bytes: self.verified_bytes,
            outcome_counts: self.outcome_counts,
            evidence_digest: self.digest.finalize().into(),
        }
    }
}

fn validate_observation(observation: ScrubObservation) -> Result<(), StorageScrubExecutionError> {
    let expected = observation
        .expected_length
        .zip(observation.expected_digest)
        .filter(|(length, digest)| *length > 0 && *digest != [0; 32]);
    let observed = observation
        .observed_length
        .zip(observation.observed_digest)
        .filter(|(_, digest)| *digest != [0; 32]);
    let complete_pairs = observation.expected_length.is_some()
        == observation.expected_digest.is_some()
        && observation.observed_length.is_some() == observation.observed_digest.is_some();
    let valid_outcome = match observation.outcome {
        ScrubOutcome::Healthy => expected.is_some() && observed == expected,
        ScrubOutcome::Corrupt => expected.is_some() && observed.is_some() && observed != expected,
        ScrubOutcome::Missing | ScrubOutcome::Unreadable | ScrubOutcome::Deferred => {
            expected.is_some() && observed.is_none()
        }
        ScrubOutcome::Unexpected => expected.is_none() && observed.is_some(),
    };
    if observation.shard.manifest_digest == [0; 32]
        || observation.shard.generation == 0
        || !complete_pairs
        || !valid_outcome
    {
        Err(StorageScrubExecutionError::InvalidEvidence)
    } else {
        Ok(())
    }
}

fn digest_observation(digest: &mut blake3::Hasher, observation: ScrubObservation) {
    digest.update(&observation.shard.manifest_digest);
    digest.update(&observation.shard.stripe_index.to_be_bytes());
    digest.update(&observation.shard.shard_index.to_be_bytes());
    digest.update(&observation.shard.generation.to_be_bytes());
    digest_optional_u64(digest, observation.expected_length);
    digest_optional_bytes(digest, observation.expected_digest);
    digest_optional_u64(digest, observation.observed_length);
    digest_optional_bytes(digest, observation.observed_digest);
    digest.update(&[outcome_code(observation.outcome)]);
}

fn digest_optional_u64(digest: &mut blake3::Hasher, value: Option<u64>) {
    match value {
        Some(value) => {
            digest.update(&[1]);
            digest.update(&value.to_be_bytes());
        }
        None => {
            digest.update(&[0]);
        }
    }
}

fn digest_optional_bytes(digest: &mut blake3::Hasher, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            digest.update(&[1]);
            digest.update(&value);
        }
        None => {
            digest.update(&[0]);
        }
    }
}

const fn outcome_code(outcome: ScrubOutcome) -> u8 {
    match outcome {
        ScrubOutcome::Healthy => 1,
        ScrubOutcome::Missing => 2,
        ScrubOutcome::Corrupt => 3,
        ScrubOutcome::Unreadable => 4,
        ScrubOutcome::Unexpected => 5,
        ScrubOutcome::Deferred => 6,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use meshspan_contracts::{BoundedItems, ShardIdentity};
    use meshspan_domain::{AuditEventId, NodeId, OperationId, PrincipalId, Revision, WorkId};
    use meshspan_metadata::{ApplyDisposition, EntityKind, EntityReference, LogPosition};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn complete_pages_commit_exact_summary_and_completion() -> Result<(), Box<dyn std::error::Error>>
    {
        let authority = RecordingAuthority::default();
        let mut provider = PageProvider::new([
            Ok(page(
                vec![healthy(1), corrupt(2)],
                Some(BoundedBytes::copy_from(&[1], 8)?),
            )?),
            Ok(page(vec![missing(3)], None)?),
        ]);
        let mut findings = RecordingFindings::default();
        let receipt =
            execute_storage_scrub(&authority, &mut provider, &mut findings, &execution(4)?)?;
        assert_eq!(receipt.summary.observation_count, 3);
        assert_eq!(receipt.summary.verified_bytes, 8_193);
        assert_eq!(receipt.summary.outcome_counts, [1, 1, 1, 0, 0, 0]);
        assert_ne!(receipt.summary.evidence_digest, [0; 32]);
        let commands = authority.commands.borrow();
        assert!(matches!(
            commands[0],
            AuthoritativeCommand::ClaimMaintenanceWork(_)
        ));
        let AuthoritativeCommand::CommitScrubPass(effect) = commands[1] else {
            return Err("second command was not the scrub effect".into());
        };
        assert_eq!(effect.observation_count, 3);
        assert_eq!(effect.verified_bytes, 8_193);
        assert_eq!(effect.evidence_digest, receipt.summary.evidence_digest);
        let AuthoritativeCommand::CompleteMaintenanceWork(completion) = commands[2] else {
            return Err("third command was not completion".into());
        };
        assert_eq!(
            completion.outcome,
            MaintenanceWorkCompletion::Succeeded {
                effect_operation_id: receipt.effect.operation_id,
                effect_revision: receipt.effect.committed_revision,
                effect_result_digest: receipt.effect.result_digest,
            }
        );
        assert_eq!(provider.requested_cursors, vec![None, Some(vec![1])]);
        assert_eq!(findings.observations.len(), 2);
        Ok(())
    }

    #[test]
    fn contradictory_provider_evidence_never_commits_effect_or_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = RecordingAuthority::default();
        let mut invalid = healthy(1);
        invalid.observed_digest = Some([99; 32]);
        let mut provider = PageProvider::new([Ok(page(vec![invalid], None)?)]);
        let mut findings = RecordingFindings::default();
        assert!(matches!(
            execute_storage_scrub(&authority, &mut provider, &mut findings, &execution(2)?),
            Err(StorageScrubExecutionError::InvalidEvidence)
        ));
        assert_eq!(authority.commands.borrow().len(), 1);
        assert!(findings.observations.is_empty());
        Ok(())
    }

    #[test]
    fn resumable_attempts_checkpoint_then_complete_without_replaying_pages()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let mut progress = LocalDatabase::open(
            &directory.path().join("local.sqlite3"),
            NodeId::from_bytes([30; 16])?,
            UnixMicros::new(1),
        )?;
        let authority = RecordingAuthority::default();
        let mut provider = PageProvider::new([
            Ok(page(
                vec![healthy(1), corrupt(2)],
                Some(BoundedBytes::copy_from(&[1], 8)?),
            )?),
            Ok(page(vec![missing(3)], None)?),
        ]);
        let mut findings = RecordingFindings::default();
        let first = execute_resumable_storage_scrub(
            &authority,
            &mut provider,
            &mut findings,
            &mut progress,
            &resumable_execution(1, 40, 10)?,
        )?;
        let ResumableStorageScrubReceipt::Continued {
            progress: checkpoint,
            ..
        } = first
        else {
            return Err("first page did not yield a continuation".into());
        };
        assert_eq!(checkpoint.page_index, 1);
        assert_eq!(checkpoint.next_cursor, Some(vec![1]));
        assert_eq!(checkpoint.observation_count, 2);

        let second = execute_resumable_storage_scrub(
            &authority,
            &mut provider,
            &mut findings,
            &mut progress,
            &resumable_execution(2, 50, 20)?,
        )?;
        let ResumableStorageScrubReceipt::Completed(receipt) = second else {
            return Err("final page did not complete the scrub".into());
        };
        assert_eq!(receipt.summary.observation_count, 3);
        assert_eq!(receipt.summary.verified_bytes, 8_193);
        assert_eq!(receipt.summary.outcome_counts, [1, 1, 1, 0, 0, 0]);
        assert_eq!(provider.requested_cursors, vec![None, Some(vec![1])]);
        assert_eq!(findings.observations.len(), 2);
        let commands = authority.commands.borrow();
        let AuthoritativeCommand::CompleteMaintenanceWork(first_completion) = commands[1] else {
            return Err("first attempt did not release its claim".into());
        };
        assert!(matches!(
            first_completion.outcome,
            MaintenanceWorkCompletion::Continue { .. }
        ));
        assert!(matches!(
            commands[3],
            AuthoritativeCommand::CommitScrubPass(_)
        ));
        assert!(matches!(
            commands[4],
            AuthoritativeCommand::CompleteMaintenanceWork(_)
        ));
        Ok(())
    }

    #[test]
    fn returning_target_commits_distinct_reconciliation_effect()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let mut progress = LocalDatabase::open(
            &directory.path().join("local.sqlite3"),
            NodeId::from_bytes([30; 16])?,
            UnixMicros::new(1),
        )?;
        let authority = RecordingAuthority::default();
        let mut provider = PageProvider::new([Ok(page(vec![healthy(1), missing(2)], None)?)]);
        let mut findings = RecordingFindings::default();

        let receipt = execute_resumable_target_reconciliation(
            &authority,
            &mut provider,
            &mut findings,
            &mut progress,
            &resumable_execution(1, 40, 10)?,
        )?;
        let ResumableStorageScrubReceipt::Completed(receipt) = receipt else {
            return Err("single-page return reconciliation did not complete".into());
        };
        assert_eq!(receipt.summary.outcome_counts, [1, 1, 0, 0, 0, 0]);
        assert_eq!(findings.observations, vec![missing(2)]);
        let commands = authority.commands.borrow();
        assert!(matches!(
            commands[1],
            AuthoritativeCommand::CommitTargetReconciliation(_)
        ));
        assert!(matches!(
            commands[2],
            AuthoritativeCommand::CompleteMaintenanceWork(_)
        ));
        Ok(())
    }

    #[derive(Default)]
    struct RecordingFindings {
        observations: Vec<ScrubObservation>,
    }

    impl ScrubFindingSink for RecordingFindings {
        fn record(
            &mut self,
            _target_id: TargetId,
            _target_generation: u64,
            observation: ScrubObservation,
            _observed_at: UnixMicros,
        ) -> Result<(), ScrubFindingSchedulingError> {
            self.observations.push(observation);
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingAuthority {
        commands: RefCell<Vec<AuthoritativeCommand>>,
    }

    impl MaintenanceMetadataAuthority for RecordingAuthority {
        fn commit(
            &self,
            context: CommandContext,
            command: &AuthoritativeCommand,
        ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
            self.commands.borrow_mut().push(command.clone());
            let revision =
                Revision::new(u64::try_from(self.commands.borrow().len()).unwrap_or(u64::MAX));
            Ok(CommandReceipt {
                disposition: ApplyDisposition::Applied,
                operation_id: context.operation_id,
                request_digest: command.request_digest(context),
                result_digest: [u8::try_from(revision.get()).unwrap_or(u8::MAX); 32],
                committed_revision: revision,
                committed_position: LogPosition {
                    index: revision.get(),
                    term: 1,
                },
                applied_position: LogPosition {
                    index: revision.get(),
                    term: 1,
                },
                entity: EntityReference {
                    kind: EntityKind::MaintenanceWork,
                    id: [7; 16],
                },
            })
        }
    }

    impl RecoverableMaintenanceAuthority for RecordingAuthority {
        fn effect_reference(
            &self,
            _work_id: WorkId,
        ) -> Result<Option<MaintenanceEffectReference>, meshspan_metadata::RepositoryError>
        {
            Ok(None)
        }
    }

    struct PageProvider {
        pages: VecDeque<Result<ScrubPage, ContractError>>,
        requested_cursors: Vec<Option<Vec<u8>>>,
    }

    impl PageProvider {
        fn new(pages: impl IntoIterator<Item = Result<ScrubPage, ContractError>>) -> Self {
            Self {
                pages: pages.into_iter().collect(),
                requested_cursors: Vec::new(),
            }
        }
    }

    impl PhysicalStorageScrub for PageProvider {
        fn scrub_page(
            &mut self,
            cursor: Option<&BoundedBytes>,
            _limit: usize,
            _observed_at: UnixMicros,
        ) -> Result<ScrubPage, ContractError> {
            self.requested_cursors
                .push(cursor.map(|value| value.as_slice().to_vec()));
            self.pages
                .pop_front()
                .unwrap_or(Err(ContractError::InternalContract))
        }
    }

    fn execution(
        maximum_pages: usize,
    ) -> Result<StorageScrubExecution, meshspan_domain::IdentifierError> {
        Ok(StorageScrubExecution {
            claim_context: context(1, 10)?,
            effect_context: context(2, 30)?,
            completion_context: context(3, 40)?,
            claim: ClaimMaintenanceWork {
                work_id: WorkId::from_bytes([4; 16])?,
                worker_node_id: NodeId::from_bytes([5; 16])?,
                worker_incarnation: 1,
                claim_generation: 1,
                fence: 6,
                lease_expires_at: UnixMicros::new(100),
            },
            target_id: TargetId::from_bytes([7; 16])?,
            target_generation: 1,
            page_items: 2,
            maximum_pages,
            observed_at: UnixMicros::new(20),
        })
    }

    fn resumable_execution(
        claim_generation: u64,
        seed: u8,
        occurred_at: i64,
    ) -> Result<ResumableStorageScrubExecution, meshspan_domain::IdentifierError> {
        Ok(ResumableStorageScrubExecution {
            claim_context: context(seed, occurred_at)?,
            effect_context: context(seed + 1, occurred_at + 2)?,
            completion_context: context(seed + 2, occurred_at + 3)?,
            claim: ClaimMaintenanceWork {
                work_id: WorkId::from_bytes([4; 16])?,
                worker_node_id: NodeId::from_bytes([5; 16])?,
                worker_incarnation: 1,
                claim_generation,
                fence: 6 + claim_generation,
                lease_expires_at: UnixMicros::new(occurred_at + 100),
            },
            target_id: TargetId::from_bytes([7; 16])?,
            target_generation: 1,
            page_items: 2,
            observed_at: UnixMicros::new(occurred_at + 1),
            continuation_at: UnixMicros::new(occurred_at + 4),
        })
    }

    fn context(
        seed: u8,
        occurred_at: i64,
    ) -> Result<CommandContext, meshspan_domain::IdentifierError> {
        Ok(CommandContext {
            operation_id: OperationId::from_bytes([seed; 16])?,
            actor_principal_id: PrincipalId::from_bytes([8; 16])?,
            audit_event_id: AuditEventId::from_bytes([seed + 10; 16])?,
            occurred_at: UnixMicros::new(occurred_at),
            expected_revision: None,
        })
    }

    fn page(
        observations: Vec<ScrubObservation>,
        next_cursor: Option<BoundedBytes>,
    ) -> Result<ScrubPage, meshspan_contracts::BoundedItemsError> {
        Ok(ScrubPage {
            observations: BoundedItems::new(observations, 2)?,
            next_cursor,
        })
    }

    fn healthy(seed: u8) -> ScrubObservation {
        let length = 4_096;
        let digest = [seed + 20; 32];
        observation(
            seed,
            Some((length, digest)),
            Some((length, digest)),
            ScrubOutcome::Healthy,
        )
    }

    fn corrupt(seed: u8) -> ScrubObservation {
        observation(
            seed,
            Some((4_096, [seed + 20; 32])),
            Some((4_097, [seed + 21; 32])),
            ScrubOutcome::Corrupt,
        )
    }

    fn missing(seed: u8) -> ScrubObservation {
        observation(
            seed,
            Some((4_096, [seed + 20; 32])),
            None,
            ScrubOutcome::Missing,
        )
    }

    fn observation(
        seed: u8,
        expected: Option<(u64, [u8; 32])>,
        observed: Option<(u64, [u8; 32])>,
        outcome: ScrubOutcome,
    ) -> ScrubObservation {
        ScrubObservation {
            shard: ShardIdentity {
                manifest_digest: [seed; 32],
                stripe_index: u64::from(seed),
                shard_index: u16::from(seed),
                generation: 1,
            },
            expected_length: expected.map(|value| value.0),
            expected_digest: expected.map(|value| value.1),
            observed_length: observed.map(|value| value.0),
            observed_digest: observed.map(|value| value.1),
            outcome,
        }
    }
}
