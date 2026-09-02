// SPDX-License-Identifier: GPL-2.0-only

//! Bounded policy re-evaluation that admits strict stripe improvements as ordinary repairs.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_contracts::{PlacementPolicy, RequestContext};
use meshspan_domain::{
    AuditEventId, EntropyError, OperationId, PrincipalId, RandomSource, Revision, UnixMicros,
    WorkId, uuid_v8,
};
use meshspan_filesystem::{
    ContentCatalogError, DurableContentCatalog, ProtectionConfiguration, ShardRepairCandidate,
    VolumeStripeCursor, VolumeStripePage,
};
use meshspan_metadata::{
    AuthoritativeCommand, ClaimMaintenanceWork, CommandContext, CommandReceipt,
    CommitRebalanceScanPage, CompleteMaintenanceWork, EntityKind, MaintenanceEffectReference,
    MaintenanceWorkCompletion, QueueMaintenanceWork, RebalanceScanCursor, RebalanceScanProgress,
};
use meshspan_work::{WorkDemand, WorkSignals, WorkSubject};
use thiserror::Error;

use crate::{
    ConsensusAuthenticationAuthority, MaintenanceMetadataAuthority, RecoverableMaintenanceAuthority,
};

const MAXIMUM_STRIPES_PER_STEP: usize = 64;

/// Catalogue reads required by a bounded rebalance worker.
pub trait RebalanceCatalogue {
    /// Returns one stable page of complete protected stripes for a volume.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed cursor, incomplete routes or contradictory catalogue state.
    fn volume_stripes(
        &self,
        volume_id: meshspan_domain::VolumeId,
        after: Option<VolumeStripeCursor>,
        limit: usize,
    ) -> Result<VolumeStripePage, ContentCatalogError>;

    /// Resolves the current generation-bound repair candidate for one selected shard route.
    ///
    /// # Errors
    ///
    /// Fails closed when the route or its immutable content evidence is contradictory.
    fn repair_candidate(
        &self,
        receipt: meshspan_contracts::ShardReceipt,
    ) -> Result<Option<ShardRepairCandidate>, ContentCatalogError>;
}

impl RebalanceCatalogue for DurableContentCatalog {
    fn volume_stripes(
        &self,
        volume_id: meshspan_domain::VolumeId,
        after: Option<VolumeStripeCursor>,
        limit: usize,
    ) -> Result<VolumeStripePage, ContentCatalogError> {
        self.current_volume_stripes(volume_id, after, limit)
    }

    fn repair_candidate(
        &self,
        receipt: meshspan_contracts::ShardReceipt,
    ) -> Result<Option<ShardRepairCandidate>, ContentCatalogError> {
        self.shard_repair_candidate(receipt.target_id, receipt.target_generation, receipt.shard)
    }
}

/// Read extensions needed to resume or close an authoritative rebalance scan.
pub trait RebalanceMaintenanceAuthority: RecoverableMaintenanceAuthority {
    /// Returns the latest committed scan checkpoint for one work item.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed state or database failure.
    fn rebalance_progress(
        &self,
        work_id: WorkId,
    ) -> Result<Option<RebalanceScanProgress>, meshspan_metadata::RepositoryError>;
}

impl RebalanceMaintenanceAuthority for ConsensusAuthenticationAuthority {
    fn rebalance_progress(
        &self,
        work_id: WorkId,
    ) -> Result<Option<RebalanceScanProgress>, meshspan_metadata::RepositoryError> {
        self.reader().rebalance_scan_progress(work_id)
    }
}

/// Exact claim, command and timing fences for one bounded rebalance step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RebalanceExecution {
    /// Context claiming the selected work item.
    pub claim_context: CommandContext,
    /// Context committing the scan checkpoint or terminal effect.
    pub scan_context: CommandContext,
    /// Context releasing or terminally completing the claim.
    pub completion_context: CommandContext,
    /// Next fenced claim selected from authoritative job state.
    pub claim: ClaimMaintenanceWork,
    /// Exact rebalance subject selected by the dispatcher.
    pub subject: WorkSubject,
    /// Maximum complete stripes examined in this step.
    pub page_items: usize,
    /// Deadline bound into fixed-revision placement decisions.
    pub planning_deadline: UnixMicros,
    /// Earliest authority-agreed instant for another page.
    pub continuation_at: UnixMicros,
}

/// Durable result of one bounded rebalance step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RebalanceStepReceipt {
    /// Another keyset page remains.
    Continued {
        /// Complete stripes evaluated by this page.
        scanned_stripes: usize,
        /// Strict improvements durably admitted as repair work.
        queued_repairs: usize,
        /// Receipt releasing the current claim.
        completion: CommandReceipt,
    },
    /// The scan finished or a newer configuration superseded it.
    Completed {
        /// Immutable effect recovered or created by this step.
        effect: MaintenanceEffectReference,
        /// Receipt terminally linking the work item to the effect.
        completion: CommandReceipt,
    },
}

/// Closed failures before a rebalance page can claim durable completion.
#[derive(Debug, Error)]
pub enum RebalanceExecutionError {
    /// The local protected-content catalogue was unavailable or contradictory.
    #[error("rebalance could not read a trustworthy protected-content catalogue")]
    Catalogue(#[from] ContentCatalogError),
    /// Fixed-revision placement evidence was malformed.
    #[error("rebalance placement evaluation failed")]
    Placement(#[from] meshspan_contracts::ContractError),
    /// Consensus rejected or could not commit a transition.
    #[error("rebalance metadata transition failed")]
    Authority(#[from] MetadataAuthorityRequestError),
    /// Restart-safe progress or effect recovery failed closed.
    #[error("rebalance progress recovery failed")]
    Recovery(#[from] meshspan_metadata::RepositoryError),
    /// Unique operation, audit or work identities could not be generated.
    #[error("rebalance identities could not be generated")]
    Entropy(#[from] EntropyError),
    /// Input, current policy, route evidence or returned receipt was contradictory.
    #[error("rebalance execution input or evidence was invalid")]
    Invalid,
}

/// Claims and executes one restart-safe page of strict rebalance improvements.
///
/// Every selected move first becomes an ordinary deduplicated repair job. The scan cursor advances
/// only after all jobs from the page are authoritative, so crashes can repeat admission safely.
///
/// # Errors
///
/// Rejects stale/malformed evidence, unsafe policy regression, catalogue failure, entropy failure
/// or any authority receipt which does not exactly bind the requested transition.
pub fn execute_rebalance_step<Authority, Catalogue, Placement, Random>(
    authority: &Authority,
    catalogue: &Catalogue,
    configuration: &ProtectionConfiguration,
    placement: &Placement,
    random: &mut Random,
    execution: &RebalanceExecution,
) -> Result<RebalanceStepReceipt, RebalanceExecutionError>
where
    Authority: RebalanceMaintenanceAuthority,
    Catalogue: RebalanceCatalogue,
    Placement: PlacementPolicy,
    Random: RandomSource,
{
    let (volume_id, subject_revision) = validate_execution(execution, configuration)?;
    commit_exact(
        authority,
        execution.claim_context,
        &AuthoritativeCommand::ClaimMaintenanceWork(execution.claim),
    )?;
    if let Some(effect) = authority.effect_reference(execution.claim.work_id)? {
        return complete(authority, execution, effect);
    }
    let progress = authority.rebalance_progress(execution.claim.work_id)?;
    validate_progress(
        progress,
        execution.claim.work_id,
        volume_id,
        subject_revision,
    )?;
    if configuration.topology_revision() > subject_revision {
        return supersede(
            authority,
            execution,
            progress,
            configuration.topology_revision(),
        );
    }
    let after = progress
        .and_then(|value| value.cursor)
        .map(to_volume_cursor);
    let page = catalogue.volume_stripes(volume_id, after, execution.page_items)?;
    let evaluation = PageEvaluator {
        authority,
        catalogue,
        configuration,
        placement,
        random,
        execution,
        volume_id,
    }
    .evaluate(&page)?;
    commit_page(authority, execution, progress, &page, evaluation)
}

#[derive(Clone, Copy)]
struct PageEvaluation {
    queued_repairs: u16,
    decision_digest: [u8; 32],
}

struct PageEvaluator<'a, Authority, Catalogue, Placement, Random> {
    authority: &'a Authority,
    catalogue: &'a Catalogue,
    configuration: &'a ProtectionConfiguration,
    placement: &'a Placement,
    random: &'a mut Random,
    execution: &'a RebalanceExecution,
    volume_id: meshspan_domain::VolumeId,
}

impl<Authority, Catalogue, Placement, Random>
    PageEvaluator<'_, Authority, Catalogue, Placement, Random>
where
    Authority: MaintenanceMetadataAuthority,
    Catalogue: RebalanceCatalogue,
    Placement: PlacementPolicy,
    Random: RandomSource,
{
    fn evaluate(
        &mut self,
        page: &VolumeStripePage,
    ) -> Result<PageEvaluation, RebalanceExecutionError> {
        let mut queued = 0_u16;
        let mut decisions = blake3::Hasher::new();
        decisions.update(b"meshspan.rebalance-decisions.v1\0");
        for record in page.stripes.as_slice() {
            let current_targets = current_targets(&record.stripe)?;
            let plan = self.configuration.plan_rebalance(
                self.placement,
                RequestContext {
                    contract_version: meshspan_contracts::ContractVersion::V1_0,
                    operation_id: self.execution.scan_context.operation_id,
                    deadline: self.execution.planning_deadline,
                    expected_revision: Some(self.configuration.topology_revision()),
                },
                record.stripe.stripe.coding_layout(),
                &current_targets,
            )?;
            let Some(plan) = plan else {
                continue;
            };
            let receipt = record
                .stripe
                .receipts
                .as_slice()
                .iter()
                .copied()
                .find(|receipt| receipt.shard.shard_index == plan.source_shard_index)
                .ok_or(RebalanceExecutionError::Invalid)?;
            let candidate = self
                .catalogue
                .repair_candidate(receipt)?
                .filter(|candidate| {
                    candidate.volume_id == self.volume_id
                        && candidate.manifest_id == record.content.manifest.manifest_id
                })
                .ok_or(RebalanceExecutionError::Invalid)?;
            let subject = queue_repair(
                self.authority,
                self.random,
                self.execution.claim_context.actor_principal_id,
                self.execution.claim_context.occurred_at,
                candidate,
                plan.current_fully_protected,
            )?;
            decisions.update(&subject.encode());
            queued = queued
                .checked_add(1)
                .ok_or(RebalanceExecutionError::Invalid)?;
        }
        Ok(PageEvaluation {
            queued_repairs: queued,
            decision_digest: decisions.finalize().into(),
        })
    }
}

fn commit_page<Authority: RebalanceMaintenanceAuthority>(
    authority: &Authority,
    execution: &RebalanceExecution,
    progress: Option<RebalanceScanProgress>,
    page: &VolumeStripePage,
    evaluation: PageEvaluation,
) -> Result<RebalanceStepReceipt, RebalanceExecutionError> {
    let (volume_id, topology_revision) = subject(execution.subject)?;
    let after = progress.and_then(|value| value.cursor);
    let next = page.next.map(to_rebalance_cursor);
    let page_digest = page_digest(page, &evaluation);
    let receipt = commit_exact(
        authority,
        execution.scan_context,
        &AuthoritativeCommand::CommitRebalanceScanPage(CommitRebalanceScanPage {
            work_id: execution.claim.work_id,
            claim_generation: execution.claim.claim_generation,
            worker_node_id: execution.claim.worker_node_id,
            worker_incarnation: execution.claim.worker_incarnation,
            fence: execution.claim.fence,
            volume_id,
            topology_revision,
            after,
            next,
            scanned_stripes: u16::try_from(page.stripes.len())
                .map_err(|_| RebalanceExecutionError::Invalid)?,
            queued_repairs: evaluation.queued_repairs,
            superseded_by_revision: None,
            page_digest,
        }),
    )?;
    if next.is_some() {
        let completion = continue_work(authority, execution, receipt.result_digest)?;
        Ok(RebalanceStepReceipt::Continued {
            scanned_stripes: page.stripes.len(),
            queued_repairs: usize::from(evaluation.queued_repairs),
            completion,
        })
    } else {
        let effect = authority
            .effect_reference(execution.claim.work_id)?
            .ok_or(RebalanceExecutionError::Invalid)?;
        complete(authority, execution, effect)
    }
}

fn supersede<Authority: RebalanceMaintenanceAuthority>(
    authority: &Authority,
    execution: &RebalanceExecution,
    progress: Option<RebalanceScanProgress>,
    newer_revision: Revision,
) -> Result<RebalanceStepReceipt, RebalanceExecutionError> {
    let (volume_id, topology_revision) = subject(execution.subject)?;
    commit_exact(
        authority,
        execution.scan_context,
        &AuthoritativeCommand::CommitRebalanceScanPage(CommitRebalanceScanPage {
            work_id: execution.claim.work_id,
            claim_generation: execution.claim.claim_generation,
            worker_node_id: execution.claim.worker_node_id,
            worker_incarnation: execution.claim.worker_incarnation,
            fence: execution.claim.fence,
            volume_id,
            topology_revision,
            after: progress.and_then(|value| value.cursor),
            next: None,
            scanned_stripes: 0,
            queued_repairs: 0,
            superseded_by_revision: Some(newer_revision),
            page_digest: supersession_digest(execution.claim.work_id, newer_revision),
        }),
    )?;
    let effect = authority
        .effect_reference(execution.claim.work_id)?
        .ok_or(RebalanceExecutionError::Invalid)?;
    complete(authority, execution, effect)
}

fn continue_work<Authority: MaintenanceMetadataAuthority>(
    authority: &Authority,
    execution: &RebalanceExecution,
    progress_digest: [u8; 32],
) -> Result<CommandReceipt, RebalanceExecutionError> {
    commit_exact(
        authority,
        execution.completion_context,
        &AuthoritativeCommand::CompleteMaintenanceWork(CompleteMaintenanceWork {
            work_id: execution.claim.work_id,
            claim_generation: execution.claim.claim_generation,
            worker_node_id: execution.claim.worker_node_id,
            worker_incarnation: execution.claim.worker_incarnation,
            fence: execution.claim.fence,
            outcome: MaintenanceWorkCompletion::Continue {
                progress_digest,
                retry_at: execution.continuation_at,
            },
        }),
    )
}

fn complete<Authority: MaintenanceMetadataAuthority>(
    authority: &Authority,
    execution: &RebalanceExecution,
    effect: MaintenanceEffectReference,
) -> Result<RebalanceStepReceipt, RebalanceExecutionError> {
    let completion = commit_exact(
        authority,
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
    )?;
    Ok(RebalanceStepReceipt::Completed { effect, completion })
}

fn queue_repair<Authority: MaintenanceMetadataAuthority>(
    authority: &Authority,
    random: &mut impl RandomSource,
    actor_principal_id: PrincipalId,
    now: UnixMicros,
    candidate: ShardRepairCandidate,
    currently_protected: bool,
) -> Result<WorkSubject, RebalanceExecutionError> {
    let subject = WorkSubject::Repair {
        volume_id: candidate.volume_id,
        manifest_id: candidate.manifest_id,
        stripe_index: candidate.source_receipt.shard.stripe_index,
        shard_index: candidate.source_receipt.shard.shard_index,
        source_generation: candidate.source_layout_generation,
    };
    let context = random_context(random, actor_principal_id, now)?;
    let command = AuthoritativeCommand::QueueMaintenanceWork(QueueMaintenanceWork {
        work_id: random_work_id(random)?,
        deduplication_key: crate::scrub_finding_scheduler::deduplication_key(subject, None, now),
        subject,
        signals: WorkSignals {
            data_unavailable: false,
            remaining_recovery_margin: u16::from(currently_protected),
            protection_debt: u16::from(!currently_protected),
            locality_debt: u16::from(currently_protected),
            instability: 0,
            access_heat: 0,
            created_at: now,
            due_at: Some(now),
        },
        demand: WorkDemand {
            in_flight_bytes: candidate.source_receipt.length,
        },
        next_attempt_at: now,
    });
    commit_exact(authority, context, &command)?;
    Ok(subject)
}

fn validate_execution(
    execution: &RebalanceExecution,
    configuration: &ProtectionConfiguration,
) -> Result<(meshspan_domain::VolumeId, Revision), RebalanceExecutionError> {
    let (volume_id, subject_revision) = subject(execution.subject)?;
    let actors_match = execution.claim_context.actor_principal_id
        == execution.scan_context.actor_principal_id
        && execution.claim_context.actor_principal_id
            == execution.completion_context.actor_principal_id;
    let operations_distinct = execution.claim_context.operation_id
        != execution.scan_context.operation_id
        && execution.claim_context.operation_id != execution.completion_context.operation_id
        && execution.scan_context.operation_id != execution.completion_context.operation_id;
    let audits_distinct = execution.claim_context.audit_event_id
        != execution.scan_context.audit_event_id
        && execution.claim_context.audit_event_id != execution.completion_context.audit_event_id
        && execution.scan_context.audit_event_id != execution.completion_context.audit_event_id;
    if !actors_match
        || !operations_distinct
        || !audits_distinct
        || execution.page_items == 0
        || execution.page_items > MAXIMUM_STRIPES_PER_STEP
        || execution.claim.claim_generation == 0
        || execution.claim.worker_incarnation == 0
        || execution.claim.fence == 0
        || execution.claim_context.occurred_at > execution.scan_context.occurred_at
        || execution.scan_context.occurred_at > execution.completion_context.occurred_at
        || execution.completion_context.occurred_at >= execution.claim.lease_expires_at
        || execution.planning_deadline > execution.claim.lease_expires_at
        || execution.planning_deadline <= execution.scan_context.occurred_at
        || execution.continuation_at <= execution.completion_context.occurred_at
        || configuration.topology_revision() < subject_revision
    {
        Err(RebalanceExecutionError::Invalid)
    } else {
        Ok((volume_id, subject_revision))
    }
}

fn validate_progress(
    progress: Option<RebalanceScanProgress>,
    work_id: WorkId,
    volume_id: meshspan_domain::VolumeId,
    topology_revision: Revision,
) -> Result<(), RebalanceExecutionError> {
    if progress.is_some_and(|progress| {
        progress.work_id != work_id
            || progress.volume_id != volume_id
            || progress.topology_revision != topology_revision
            || progress.complete
    }) {
        Err(RebalanceExecutionError::Invalid)
    } else {
        Ok(())
    }
}

fn subject(
    value: WorkSubject,
) -> Result<(meshspan_domain::VolumeId, Revision), RebalanceExecutionError> {
    match value {
        WorkSubject::Rebalance {
            volume_id,
            topology_revision,
        } if topology_revision != Revision::ZERO => Ok((volume_id, topology_revision)),
        _ => Err(RebalanceExecutionError::Invalid),
    }
}

fn current_targets(
    stripe: &meshspan_filesystem::CommittedProtectedStripe,
) -> Result<Vec<meshspan_domain::TargetId>, RebalanceExecutionError> {
    let mut targets = stripe
        .stripe
        .shards()
        .iter()
        .map(|shard| shard.target_id)
        .collect::<Vec<_>>();
    for receipt in stripe.receipts.as_slice() {
        let target = targets
            .get_mut(usize::from(receipt.shard.shard_index))
            .ok_or(RebalanceExecutionError::Invalid)?;
        *target = receipt.target_id;
    }
    let distinct = targets
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if distinct.len() == targets.len() {
        Ok(targets)
    } else {
        Err(RebalanceExecutionError::Invalid)
    }
}

fn page_digest(page: &VolumeStripePage, evaluation: &PageEvaluation) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.rebalance-page.v1\0");
    for record in page.stripes.as_slice() {
        digest.update(&record.cursor.publication_operation_id.as_bytes());
        digest.update(&record.cursor.stripe_index.to_be_bytes());
        digest.update(&record.content.manifest.root_digest);
    }
    digest.update(&evaluation.queued_repairs.to_be_bytes());
    digest.update(&evaluation.decision_digest);
    digest.update(&[u8::from(page.next.is_some())]);
    digest.finalize().into()
}

fn supersession_digest(work_id: WorkId, newer_revision: Revision) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.rebalance-supersession.v1\0");
    digest.update(&work_id.as_bytes());
    digest.update(&newer_revision.get().to_be_bytes());
    digest.finalize().into()
}

const fn to_volume_cursor(cursor: RebalanceScanCursor) -> VolumeStripeCursor {
    VolumeStripeCursor {
        publication_operation_id: cursor.publication_operation_id,
        stripe_index: cursor.stripe_index,
    }
}

const fn to_rebalance_cursor(cursor: VolumeStripeCursor) -> RebalanceScanCursor {
    RebalanceScanCursor {
        publication_operation_id: cursor.publication_operation_id,
        stripe_index: cursor.stripe_index,
    }
}

fn commit_exact<Authority: MaintenanceMetadataAuthority>(
    authority: &Authority,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<CommandReceipt, RebalanceExecutionError> {
    let receipt = authority.commit(context, command)?;
    if receipt.operation_id != context.operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.result_digest == [0; 32]
        || receipt.entity.kind != EntityKind::MaintenanceWork
    {
        Err(RebalanceExecutionError::Invalid)
    } else {
        Ok(receipt)
    }
}

fn random_context(
    random: &mut impl RandomSource,
    actor_principal_id: PrincipalId,
    now: UnixMicros,
) -> Result<CommandContext, RebalanceExecutionError> {
    let mut bytes = [0_u8; 32];
    random.fill_bytes(&mut bytes)?;
    Ok(CommandContext {
        operation_id: OperationId::from_bytes(uuid_v8(copy_identifier(&bytes[..16])?))
            .map_err(|_| RebalanceExecutionError::Invalid)?,
        actor_principal_id,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(copy_identifier(&bytes[16..])?))
            .map_err(|_| RebalanceExecutionError::Invalid)?,
        occurred_at: now,
        expected_revision: None,
    })
}

fn random_work_id(random: &mut impl RandomSource) -> Result<WorkId, RebalanceExecutionError> {
    let mut bytes = [0_u8; 16];
    random.fill_bytes(&mut bytes)?;
    WorkId::from_bytes(uuid_v8(bytes)).map_err(|_| RebalanceExecutionError::Invalid)
}

fn copy_identifier(bytes: &[u8]) -> Result<[u8; 16], RebalanceExecutionError> {
    bytes
        .try_into()
        .map_err(|_| RebalanceExecutionError::Invalid)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use meshspan_contracts::{BoundedItems, PlacementCandidate};
    use meshspan_domain::{
        EntropyError, FailureScenario, FailureTerm, FaultGroupClassId, HostId, NodeId, TargetId,
        Topology, VolumeId,
    };
    use meshspan_metadata::{ApplyDisposition, EntityReference, LogPosition};

    use super::*;

    #[test]
    fn empty_exact_revision_page_commits_effect_and_terminal_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let volume_id = VolumeId::from_bytes([1; 16])?;
        let authority = RecordingAuthority::default();
        let catalogue = EmptyCatalogue;
        let configuration = configuration(Revision::new(1))?;
        let execution = execution(volume_id)?;
        let mut random = CounterRandom;

        let result = execute_rebalance_step(
            &authority,
            &catalogue,
            &configuration,
            &meshspan_placement::FaultAwarePlacement::new(),
            &mut random,
            &execution,
        )?;

        assert!(matches!(result, RebalanceStepReceipt::Completed { .. }));
        let commands = authority.commands.borrow();
        assert!(matches!(
            commands.as_slice(),
            [
                AuthoritativeCommand::ClaimMaintenanceWork(_),
                AuthoritativeCommand::CommitRebalanceScanPage(_),
                AuthoritativeCommand::CompleteMaintenanceWork(_)
            ]
        ));
        let AuthoritativeCommand::CommitRebalanceScanPage(scan) = commands[1] else {
            return Err("missing terminal scan command".into());
        };
        assert_eq!((scan.scanned_stripes, scan.queued_repairs), (0, 0));
        assert!(scan.next.is_none());
        assert!(scan.superseded_by_revision.is_none());
        Ok(())
    }

    fn configuration(
        revision: Revision,
    ) -> Result<ProtectionConfiguration, Box<dyn std::error::Error>> {
        let class_id = FaultGroupClassId::from_bytes([4; 16])?;
        ProtectionConfiguration::from_untrusted(
            Topology::default(),
            revision,
            revision,
            vec![FailureScenario::new(vec![FailureTerm {
                class_id,
                failure_count: 1,
            }])?],
            vec![PlacementCandidate {
                target_id: TargetId::from_bytes([5; 16])?,
                host_id: HostId::from_bytes([6; 16])?,
                target_generation: 1,
                writable_bytes: 4_096,
                performance_weight: 100,
                availability_cells: BoundedItems::new(Vec::new(), 1)?,
            }],
        )
        .map_err(Into::into)
    }

    fn execution(volume_id: VolumeId) -> Result<RebalanceExecution, Box<dyn std::error::Error>> {
        let actor = PrincipalId::from_bytes([7; 16])?;
        let work_id = WorkId::from_bytes([8; 16])?;
        Ok(RebalanceExecution {
            claim_context: context(10, actor)?,
            scan_context: context(11, actor)?,
            completion_context: context(12, actor)?,
            claim: ClaimMaintenanceWork {
                work_id,
                claim_generation: 1,
                worker_node_id: NodeId::from_bytes([9; 16])?,
                worker_incarnation: 1,
                fence: 2,
                lease_expires_at: UnixMicros::new(100),
            },
            subject: WorkSubject::Rebalance {
                volume_id,
                topology_revision: Revision::new(1),
            },
            page_items: 10,
            planning_deadline: UnixMicros::new(50),
            continuation_at: UnixMicros::new(20),
        })
    }

    fn context(
        seed: u8,
        actor_principal_id: PrincipalId,
    ) -> Result<CommandContext, meshspan_domain::IdentifierError> {
        Ok(CommandContext {
            operation_id: OperationId::from_bytes([seed; 16])?,
            actor_principal_id,
            audit_event_id: AuditEventId::from_bytes([seed.wrapping_add(30); 16])?,
            occurred_at: UnixMicros::new(i64::from(seed)),
            expected_revision: None,
        })
    }

    #[derive(Default)]
    struct RecordingAuthority {
        commands: RefCell<Vec<AuthoritativeCommand>>,
        effect: RefCell<Option<MaintenanceEffectReference>>,
    }

    impl MaintenanceMetadataAuthority for RecordingAuthority {
        fn commit(
            &self,
            context: CommandContext,
            command: &AuthoritativeCommand,
        ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
            self.commands.borrow_mut().push(command.clone());
            let receipt = CommandReceipt {
                disposition: ApplyDisposition::Applied,
                operation_id: context.operation_id,
                request_digest: command.request_digest(context),
                result_digest: [1; 32],
                committed_revision: Revision::new(1),
                committed_position: LogPosition { index: 1, term: 1 },
                applied_position: LogPosition { index: 1, term: 1 },
                entity: EntityReference {
                    kind: EntityKind::MaintenanceWork,
                    id: [2; 16],
                },
            };
            if matches!(command, AuthoritativeCommand::CommitRebalanceScanPage(_)) {
                self.effect.replace(Some(MaintenanceEffectReference {
                    operation_id: receipt.operation_id,
                    revision: receipt.committed_revision,
                    result_digest: receipt.result_digest,
                }));
            }
            Ok(receipt)
        }
    }

    impl RecoverableMaintenanceAuthority for RecordingAuthority {
        fn effect_reference(
            &self,
            _work_id: WorkId,
        ) -> Result<Option<MaintenanceEffectReference>, meshspan_metadata::RepositoryError>
        {
            Ok(*self.effect.borrow())
        }
    }

    impl RebalanceMaintenanceAuthority for RecordingAuthority {
        fn rebalance_progress(
            &self,
            _work_id: WorkId,
        ) -> Result<Option<RebalanceScanProgress>, meshspan_metadata::RepositoryError> {
            Ok(None)
        }
    }

    struct EmptyCatalogue;

    impl RebalanceCatalogue for EmptyCatalogue {
        fn volume_stripes(
            &self,
            _volume_id: VolumeId,
            _after: Option<VolumeStripeCursor>,
            limit: usize,
        ) -> Result<VolumeStripePage, ContentCatalogError> {
            Ok(VolumeStripePage {
                stripes: BoundedItems::new(Vec::new(), limit)
                    .map_err(|_| ContentCatalogError::InvalidInput)?,
                next: None,
            })
        }

        fn repair_candidate(
            &self,
            _receipt: meshspan_contracts::ShardReceipt,
        ) -> Result<Option<ShardRepairCandidate>, ContentCatalogError> {
            Ok(None)
        }
    }

    struct CounterRandom;

    impl RandomSource for CounterRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(1);
            Ok(())
        }
    }
}
