// SPDX-License-Identifier: GPL-2.0-only

//! Own one fenced repair attempt from planning through physical work or durable deferral.

use super::{
    MAINTENANCE_LEASE_MICROS, StorageTargetRuntime, current_stripe_targets,
    random_maintenance_context, random_operation_id,
};
use crate::OperatingSystemRandom;
use crate::{
    MaintenanceDispatchAssignment, MaintenanceMetadataAuthority, ShardRepairExecution,
    execute_shard_repair,
};
use meshspan_contracts::{ContractError, ContractVersion, RepairPlacementPlan, RequestContext};
use meshspan_domain::{DurationMicros, Revision, UnixMicros};
use meshspan_filesystem::{
    CommittedProtectedStripe, DurableContentCatalog, PublishedContentReference,
    ShardRepairCandidate,
};
use meshspan_metadata::{
    AuthoritativeCommand, ClaimMaintenanceWork, CommandContext, CompleteMaintenanceWork,
    MaintenanceWorkCompletion,
};
use meshspan_work::{WorkSubject, WorkUrgency};
use sha2::{Digest, Sha256};

impl StorageTargetRuntime {
    pub(super) fn execute_repair_assignment(
        &mut self,
        assignment: MaintenanceDispatchAssignment,
        now: UnixMicros,
    ) -> Result<(), ()> {
        let mut source = RepairSource::load(self, assignment, now)?;
        let attempt = RepairAttempt::claim(self, assignment, now)?;
        let targets = self.active.values().cloned().collect::<Vec<_>>();
        let configuration = self
            .native_filesystem
            .maintenance_protection_configuration(&targets, source.candidate.volume_id, now)
            .map_err(|_| ())?;
        let authorization_revision = self
            .maintenance_authority
            .reader()
            .current_revision()
            .map_err(|_| ())?;
        let current_targets = current_stripe_targets(&source.stripe)?;
        let placement = configuration.plan_repair(
            &meshspan_placement::FaultAwarePlacement::new(),
            RequestContext {
                contract_version: ContractVersion::V1_0,
                operation_id: random_operation_id(&mut OperatingSystemRandom)?,
                deadline: attempt.claim.lease_expires_at,
                expected_revision: Some(authorization_revision),
            },
            source.stripe.stripe.coding_layout(),
            source.candidate.source_receipt.shard.shard_index,
            &current_targets,
        );
        let placement = match placement {
            Ok(placement) => placement,
            // This planner has not called a provider. A durable Retry is safe only
            // here; a failed physical attempt may already have an unknown effect.
            Err(ContractError::ResourceExhausted) => {
                attempt.defer(self, RepairDeferralReason::NoEligibleDestination)?;
                return Err(());
            }
            Err(_) => return Err(()),
        };
        if placement.topology_revision != configuration.topology_revision()
            || placement.capacity_revision != configuration.capacity_revision()
        {
            return Err(());
        }
        let execution = attempt.execution(&source, &placement, authorization_revision)?;
        let mut repairer = self
            .native_filesystem
            .maintenance_repairer(&targets, now)
            .map_err(|_| ())?;
        // The worker replays the exact already committed claim; it cannot create a
        // different fence or second attempt between planning and provider admission.
        let receipt = execute_shard_repair(&self.maintenance_authority, &mut repairer, &execution)
            .map_err(|_| ())?;
        source
            .catalogue
            .install_shard_repair(source.content, &receipt.transition)
            .map_err(|_| ())
    }
}

struct RepairSource {
    catalogue: DurableContentCatalog,
    content: PublishedContentReference,
    stripe: CommittedProtectedStripe,
    candidate: ShardRepairCandidate,
}

impl RepairSource {
    fn load(
        runtime: &StorageTargetRuntime,
        assignment: MaintenanceDispatchAssignment,
        now: UnixMicros,
    ) -> Result<Self, ()> {
        let WorkSubject::Repair {
            volume_id,
            manifest_id,
            stripe_index,
            shard_index,
            source_generation,
        } = assignment.subject
        else {
            return Err(());
        };
        let catalogue = runtime
            .native_filesystem
            .maintenance_catalogue(now)
            .map_err(|_| ())?;
        let content = catalogue
            .committed_content_by_manifest(manifest_id)
            .map_err(|_| ())?
            .ok_or(())?;
        let stripe = catalogue
            .committed_protected_stripe(content, stripe_index)
            .map_err(|_| ())?;
        let receipt = stripe
            .receipts
            .as_slice()
            .iter()
            .copied()
            .find(|receipt| receipt.shard.shard_index == shard_index)
            .ok_or(())?;
        let candidate = catalogue
            .shard_repair_candidate(receipt.target_id, receipt.target_generation, receipt.shard)
            .map_err(|_| ())?
            .filter(|candidate| {
                candidate.volume_id == volume_id
                    && candidate.manifest_id == manifest_id
                    && candidate.source_layout_generation == source_generation
                    && candidate.source_receipt.shard.stripe_index == stripe_index
            })
            .ok_or(())?;
        Ok(Self {
            catalogue,
            content,
            stripe,
            candidate,
        })
    }
}

struct RepairAttempt {
    claim_context: CommandContext,
    completion_context: CommandContext,
    claim: ClaimMaintenanceWork,
    subject: WorkSubject,
}

impl RepairAttempt {
    fn claim(
        runtime: &StorageTargetRuntime,
        assignment: MaintenanceDispatchAssignment,
        now: UnixMicros,
    ) -> Result<Self, ()> {
        let work = runtime
            .maintenance_authority
            .reader()
            .maintenance_work(assignment.work_id)
            .map_err(|_| ())?
            .filter(|work| work.subject == assignment.subject)
            .ok_or(())?;
        let actor = runtime.maintenance_actor(now)?;
        let (worker_node_id, worker_incarnation) = runtime.worker_identity()?;
        let mut random = OperatingSystemRandom;
        let claim_context = random_maintenance_context(&mut random, actor, now)?;
        let completion_context = random_maintenance_context(&mut random, actor, now)?;
        let fence = super::random_maintenance_fence(&mut random)?;
        let claim = ClaimMaintenanceWork {
            work_id: assignment.work_id,
            claim_generation: assignment.claim_generation,
            worker_node_id,
            worker_incarnation,
            fence,
            lease_expires_at: now
                .checked_add(DurationMicros::new(MAINTENANCE_LEASE_MICROS))
                .ok_or(())?,
        };
        runtime
            .maintenance_authority
            .commit(
                claim_context,
                &AuthoritativeCommand::ClaimMaintenanceWork(claim),
            )
            .map_err(|_| ())?;
        Ok(Self {
            claim_context,
            completion_context,
            claim,
            subject: work.subject,
        })
    }

    fn defer(self, runtime: &StorageTargetRuntime, reason: RepairDeferralReason) -> Result<(), ()> {
        let completed_at = super::current_time().map_err(|_| ())?;
        self.prepare_deferral(runtime, reason, completed_at)?
            .commit(&runtime.maintenance_authority)
            .map(|_| ())
            .map_err(|_| ())
    }

    fn prepare_deferral(
        self,
        runtime: &StorageTargetRuntime,
        reason: RepairDeferralReason,
        completed_at: UnixMicros,
    ) -> Result<PreparedRepairDeferral, ()> {
        let reader = runtime.maintenance_authority.reader();
        // Read the partition revision before the work snapshot. Any intervening
        // mutation, including stronger coalesced urgency, rejects this completion.
        let revision = reader.current_revision().map_err(|_| ())?;
        let work = reader
            .maintenance_work(self.claim.work_id)
            .map_err(|_| ())?
            .ok_or(())?;
        let current = work.claim.ok_or(())?;
        if current.generation != self.claim.claim_generation
            || current.fence != self.claim.fence
            || current.worker_node_id != self.claim.worker_node_id
            || current.worker_incarnation != self.claim.worker_incarnation
            || work.subject != self.subject
        {
            return Err(());
        }
        // A caller may supply a forward tick instant. Clock sampling must neither
        // shorten that logical time nor spend the retry delay while planning waits.
        let completed_at = completed_at.max(self.claim_context.occurred_at);
        let retry_at = completed_at
            .checked_add(repair_retry_delay(
                work.signals.urgency(),
                self.claim.claim_generation,
            ))
            .ok_or(())?;
        let mut context = self.completion_context;
        context.occurred_at = completed_at;
        context.expected_revision = Some(revision);
        Ok(PreparedRepairDeferral {
            context,
            command: CompleteMaintenanceWork {
                work_id: self.claim.work_id,
                claim_generation: self.claim.claim_generation,
                worker_node_id: self.claim.worker_node_id,
                worker_incarnation: self.claim.worker_incarnation,
                fence: self.claim.fence,
                outcome: MaintenanceWorkCompletion::Retry {
                    failure_digest: reason.digest(),
                    retry_at,
                },
            },
        })
    }

    fn execution<'a>(
        &self,
        source: &'a RepairSource,
        placement: &RepairPlacementPlan,
        authorization_revision: Revision,
    ) -> Result<ShardRepairExecution<'a>, ()> {
        let mut random = OperatingSystemRandom;
        Ok(ShardRepairExecution {
            claim_context: self.claim_context,
            effect_context: random_maintenance_context(
                &mut random,
                self.claim_context.actor_principal_id,
                self.claim_context.occurred_at,
            )?,
            completion_context: self.completion_context,
            claim: self.claim,
            volume_id: source.candidate.volume_id,
            manifest_id: source.candidate.manifest_id,
            source_layout_generation: source.candidate.source_layout_generation,
            physical: meshspan_filesystem::ShardRepairRequest {
                replacement_operation_id: random_operation_id(&mut random)?,
                source_receipt: source.candidate.source_receipt,
                replacement_target_id: placement.replacement_target_id,
                replacement_target_generation: placement.replacement_target_generation,
                authorization_revision,
                deadline: self.claim.lease_expires_at,
                observed_at: self.claim_context.occurred_at,
            },
            stripe: &source.stripe,
        })
    }
}

/// A completion has one immutable context once prepared. Consuming it prevents
/// this owner from resubmitting the same operation with a different time/revision
/// after an uncertain result. The claimed job remains fenced until lease recovery.
struct PreparedRepairDeferral {
    context: CommandContext,
    command: CompleteMaintenanceWork,
}

impl PreparedRepairDeferral {
    fn commit(
        self,
        authority: &impl MaintenanceMetadataAuthority,
    ) -> Result<meshspan_metadata::CommandReceipt, meshspan_cluster::MetadataAuthorityRequestError>
    {
        authority.commit(
            self.context,
            &AuthoritativeCommand::CompleteMaintenanceWork(self.command),
        )
    }
}

/// These retry bounds concern a failed placement attempt, not absence detection
/// or permission to postpone initial urgent repair. Committed deferrals cap the
/// unavailable-work delay at five seconds and preventive-work delay at five minutes.
fn repair_retry_delay(urgency: WorkUrgency, generation: u64) -> DurationMicros {
    let (base, cap): (u64, u64) = match urgency {
        WorkUrgency::Unavailable | WorkUrgency::LastRecoveryMargin => (1, 5),
        WorkUrgency::UnderProtected => (5, 30),
        WorkUrgency::Required => (15, 60),
        WorkUrgency::Routine => (30, 300),
    };
    let exponent = u32::try_from(generation.saturating_sub(1).min(9)).unwrap_or(9);
    DurationMicros::new(base.saturating_mul(2_u64.pow(exponent)).min(cap) * 1_000_000)
}

#[derive(Clone, Copy)]
enum RepairDeferralReason {
    NoEligibleDestination,
}

impl RepairDeferralReason {
    fn digest(self) -> [u8; 32] {
        let variant = match self {
            Self::NoEligibleDestination => 1_u8,
        };
        let mut digest = Sha256::new();
        digest.update(b"meshspan.maintenance.repair-deferral.v1\0");
        digest.update([variant]);
        digest.finalize().into()
    }
}

#[cfg(test)]
pub(super) fn assert_deferral_time_and_revision(
    runtime: &StorageTargetRuntime,
    subject: WorkSubject,
    now: UnixMicros,
) -> Result<(), Box<dyn std::error::Error>> {
    let attempt = claim_deferral_fixture(runtime, subject, now, 124)?;
    let operation = attempt.completion_context.operation_id;
    let completed_at = now
        .checked_add(DurationMicros::new(10_000_000))
        .ok_or("completion time")?;
    let prepared = attempt
        .prepare_deferral(
            runtime,
            RepairDeferralReason::NoEligibleDestination,
            completed_at,
        )
        .map_err(|()| "elapsed deferral preparation")?;
    assert_eq!(prepared.context.operation_id, operation);
    assert_eq!(prepared.context.occurred_at, completed_at);
    let expected_retry = now
        .checked_add(DurationMicros::new(11_000_000))
        .ok_or("elapsed retry")?;
    assert!(
        matches!(prepared.command.outcome, MaintenanceWorkCompletion::Retry { retry_at, .. } if retry_at == expected_retry)
    );
    let work_id = prepared.command.work_id;
    let receipt = prepared.commit(&runtime.maintenance_authority)?;
    assert_eq!(receipt.operation_id, operation);
    let reopened = super::open_root_repository_at(&runtime.state_directory, completed_at)?;
    assert_eq!(
        reopened
            .maintenance_work(work_id)?
            .ok_or("elapsed work")?
            .next_attempt_at,
        expected_retry
    );
    assert_stale_deferral_rejected(runtime, subject, now)?;
    Ok(())
}

#[cfg(test)]
fn assert_stale_deferral_rejected(
    runtime: &StorageTargetRuntime,
    subject: WorkSubject,
    now: UnixMicros,
) -> Result<(), Box<dyn std::error::Error>> {
    let attempt = claim_deferral_fixture(runtime, subject, now, 125)?;
    let prepared = attempt
        .prepare_deferral(
            runtime,
            RepairDeferralReason::NoEligibleDestination,
            UnixMicros::new(now.get().checked_sub(1).ok_or("earlier clock")?),
        )
        .map_err(|()| "stale deferral preparation")?;
    assert_eq!(
        prepared.context.occurred_at, now,
        "forward tick time is retained"
    );
    let operation = prepared.context.operation_id;
    let work_id = prepared.command.work_id;
    let reader = runtime.maintenance_authority.reader();
    let before = reader.maintenance_work(work_id)?.ok_or("claimed work")?;
    let mut signals = before.signals;
    signals.data_unavailable = true;
    runtime.maintenance_authority.commit(
        random_maintenance_context(
            &mut OperatingSystemRandom,
            prepared.context.actor_principal_id,
            now,
        )
        .map_err(|()| "escalation context")?,
        &AuthoritativeCommand::QueueMaintenanceWork(meshspan_metadata::QueueMaintenanceWork {
            work_id,
            subject,
            deduplication_key: before.deduplication_key,
            signals,
            demand: before.demand,
            next_attempt_at: now,
        }),
    )?;
    let escalated = reader.maintenance_work(work_id)?.ok_or("escalated work")?;
    assert!(escalated.revision > before.revision);
    assert!(matches!(
        prepared.commit(&runtime.maintenance_authority),
        Err(meshspan_cluster::MetadataAuthorityRequestError::Rejected)
    ));
    let reopened = super::open_root_repository_at(&runtime.state_directory, now)?;
    assert_eq!(
        reopened.maintenance_work(work_id)?.ok_or("fenced work")?,
        escalated
    );
    assert!(reopened.resolve_operation(operation)?.is_none());
    Ok(())
}

#[cfg(test)]
fn claim_deferral_fixture(
    runtime: &StorageTargetRuntime,
    subject: WorkSubject,
    now: UnixMicros,
    identity: u8,
) -> Result<RepairAttempt, Box<dyn std::error::Error>> {
    let work_id = meshspan_domain::WorkId::from_bytes([identity; 16])?;
    let actor = runtime
        .maintenance_actor(now)
        .map_err(|()| "deferral actor")?;
    runtime.maintenance_authority.commit(
        random_maintenance_context(&mut OperatingSystemRandom, actor, now)
            .map_err(|()| "deferral queue context")?,
        &AuthoritativeCommand::QueueMaintenanceWork(meshspan_metadata::QueueMaintenanceWork {
            work_id,
            subject,
            deduplication_key: [identity; 32],
            signals: meshspan_work::WorkSignals {
                data_unavailable: false,
                remaining_recovery_margin: 0,
                protection_debt: 1,
                locality_debt: 0,
                instability: 0,
                access_heat: 0,
                created_at: now,
                due_at: Some(now),
            },
            demand: meshspan_work::WorkDemand {
                in_flight_bytes: super::SCRUB_PAGE_IN_FLIGHT_BYTES,
            },
            next_attempt_at: now,
        }),
    )?;
    let work = runtime
        .maintenance_authority
        .reader()
        .maintenance_work(work_id)?
        .ok_or("deferral work")?;
    RepairAttempt::claim(
        runtime,
        MaintenanceDispatchAssignment {
            work_id,
            subject,
            demand: work.demand,
            priority: work.priority,
            claim_generation: 1,
        },
        now,
    )
    .map_err(|()| "deferral claim".into())
}

#[cfg(test)]
mod tests {
    use super::repair_retry_delay;
    use meshspan_work::WorkUrgency;

    #[test]
    fn retry_delay_respects_urgency_and_caps_unbounded_attempt_counts() {
        for (urgency, first, second, cap) in [
            (WorkUrgency::Unavailable, 1, 2, 5),
            (WorkUrgency::LastRecoveryMargin, 1, 2, 5),
            (WorkUrgency::UnderProtected, 5, 10, 30),
            (WorkUrgency::Required, 15, 30, 60),
            (WorkUrgency::Routine, 30, 60, 300),
        ] {
            assert_eq!(repair_retry_delay(urgency, 1).get(), first * 1_000_000);
            assert_eq!(repair_retry_delay(urgency, 2).get(), second * 1_000_000);
            assert_eq!(repair_retry_delay(urgency, u64::MAX).get(), cap * 1_000_000);
        }
    }
}
