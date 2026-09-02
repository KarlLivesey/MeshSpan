// SPDX-License-Identifier: GPL-2.0-only

//! Bounded storage-target scrub execution with authoritative completion evidence.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_contracts::{
    BoundedBytes, ContractError, ScrubObservation, ScrubOutcome, ScrubPage, StorageProvider,
};
use meshspan_domain::{TargetId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, ClaimMaintenanceWork, CommandContext, CommandReceipt, CommitScrubPass,
    CompleteMaintenanceWork, MaintenanceWorkCompletion,
};
use thiserror::Error;

use crate::{MaintenanceMetadataAuthority, ScrubFindingSchedulingError, ScrubFindingSink};

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
