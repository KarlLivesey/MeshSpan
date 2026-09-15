// SPDX-License-Identifier: GPL-2.0-only

//! Losing a worker's in-memory state preserves its planned or already written replacement.

use super::*;
use meshspan_domain::{Clock, UnixMicros};
use meshspan_metadata::{MaintenanceWorkState, ShardRepairEffectRecord};
use meshspan_work::WorkSubject;
use std::{error::Error, sync::Arc};

pub(in super::super) fn assert_saved_attempt_takeover(
    runtime: &mut StorageTargetRuntime,
    previous: &ShardRepairEffectRecord,
    mut now: UnixMicros,
) -> Result<(), Box<dyn Error>> {
    for (identity, write_before_loss) in [(220, false), (221, true)] {
        let catalogue = runtime.native_filesystem.maintenance_catalogue(now)?;
        let content = catalogue
            .committed_content_by_manifest(previous.manifest_id)?
            .ok_or("takeover manifest")?;
        let stripe = catalogue.committed_protected_stripe(content, 0)?;
        let source = *stripe
            .receipts
            .as_slice()
            .first()
            .ok_or("takeover source")?;
        let candidate = catalogue
            .shard_repair_candidate(source.target_id, source.target_generation, source.shard)?
            .ok_or("takeover source route")?;
        let subject = WorkSubject::Repair {
            volume_id: previous.volume_id,
            manifest_id: previous.manifest_id,
            stripe_index: source.shard.stripe_index,
            shard_index: source.shard.shard_index,
            source_generation: candidate.source_layout_generation,
        };
        let attempt = claim_deferral_fixture(runtime, subject, now, identity)?;
        let targets = runtime.active.values().cloned().collect::<Vec<_>>();
        let original_assignment = assignment(runtime, attempt.claim.work_id, 1)?;
        let source = RepairSource::load(runtime, original_assignment, now)
            .map_err(|()| "takeover source")?;
        let plan = attempt
            .plan(runtime, &source, &targets, now)
            .map_err(|()| "retain original physical selection")?
            .ok_or("takeover destination")?;
        if write_before_loss {
            let revision = runtime.maintenance_authority.reader().current_revision()?;
            let execution = attempt.execution(&source, &plan, revision);
            let mut repairer = runtime
                .native_filesystem
                .maintenance_repairer(&targets, now)?;
            let receipt = repairer.resume_repair(
                plan.intent,
                execution.physical,
                &source.stripe,
                &At(now),
            )?;
            assert_eq!(receipt.operation_id, plan.intent.context.operation_id);
        }
        now = plan.claim.lease_expires_at;
        let reopened = super::super::open_root_repository_at(&runtime.state_directory, now)?;
        let retained = reopened
            .shard_repair_attempt(plan.claim.work_id)?
            .ok_or("saved plan")?;
        assert_eq!(retained.plan, plan);
        assert!(
            reopened
                .maintenance_effect_reference(plan.claim.work_id)?
                .is_none()
        );
        runtime.maintenance_clock = Arc::new(At(now));
        let next = assignment(runtime, plan.claim.work_id, 2)?;
        runtime
            .execute_repair_assignment(next, now)
            .map_err(|()| "resume original repair")?;
        let current = reopened
            .shard_repair_attempt(plan.claim.work_id)?
            .ok_or("adopted plan")?;
        assert_eq!(current.plan.intent, retained.plan.intent);
        assert_eq!(current.plan.claim.claim_generation, 2);
        assert_ne!(
            current.plan.effect_context.operation_id,
            retained.plan.effect_context.operation_id
        );
        let work = reopened
            .maintenance_work(plan.claim.work_id)?
            .ok_or("completed repair")?;
        assert_eq!(work.state, MaintenanceWorkState::Complete);
        let reference = reopened
            .maintenance_effect_reference(work.work_id)?
            .ok_or("repair effect")?;
        let effect = reopened
            .shard_repair_effect(reference.operation_id)?
            .ok_or("exact effect")?;
        assert_eq!(
            effect.replacement_receipt.operation_id,
            retained.plan.intent.context.operation_id
        );
        assert_eq!(
            effect.replacement_receipt.target_id,
            retained.plan.intent.target_id
        );
        assert_eq!(
            effect.replacement_receipt.digest,
            retained.plan.intent.expected_digest
        );
    }
    Ok(())
}

fn assignment(
    runtime: &StorageTargetRuntime,
    work: meshspan_domain::WorkId,
    generation: u64,
) -> Result<MaintenanceDispatchAssignment, Box<dyn Error>> {
    let work = runtime
        .maintenance_authority
        .reader()
        .maintenance_work(work)?
        .ok_or("takeover work")?;
    Ok(MaintenanceDispatchAssignment {
        work_id: work.work_id,
        subject: work.subject,
        demand: work.demand,
        priority: work.priority,
        claim_generation: generation,
    })
}

struct At(UnixMicros);
impl Clock for At {
    fn now(&self) -> UnixMicros {
        self.0
    }
}
