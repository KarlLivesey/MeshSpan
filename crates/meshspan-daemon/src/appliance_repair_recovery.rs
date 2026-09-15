// SPDX-License-Identifier: GPL-2.0-only

//! Finish a committed repair without consulting or reconstructing its obsolete source.

use super::{RepairAttempt, StorageTargetRuntime};
use crate::{MaintenanceDispatchAssignment, MaintenanceMetadataAuthority};
use meshspan_domain::UnixMicros;
use meshspan_filesystem::{RepairProjectionCursor, RepairProjectionManifest};
use meshspan_metadata::{
    AuthoritativeCommand, CompleteMaintenanceWork, MaintenanceEffectReference,
    MaintenanceWorkCompletion,
};
use meshspan_work::WorkSubject;

/// Returns whether an existing effect owns this step. Bounded projection may need
/// another tick before completion; no new claim or physical attempt is then started.
pub(super) fn recover_committed_effect(
    runtime: &StorageTargetRuntime,
    assignment: MaintenanceDispatchAssignment,
    now: UnixMicros,
) -> Result<bool, ()> {
    let reader = runtime.maintenance_authority.reader();
    let Some(reference) = reader
        .maintenance_effect_reference(assignment.work_id)
        .map_err(|_| ())?
    else {
        return Ok(false);
    };
    let effect = reader
        .shard_repair_effect(reference.operation_id)
        .map_err(|_| ())?
        .ok_or(())?;
    if effect.work_id != assignment.work_id
        || effect.revision != reference.revision
        || assignment.subject
            != (WorkSubject::Repair {
                volume_id: effect.volume_id,
                manifest_id: effect.manifest_id,
                stripe_index: effect.source_receipt.shard.stripe_index,
                shard_index: effect.source_receipt.shard.shard_index,
                source_generation: effect.source_layout_generation,
            })
    {
        return Err(());
    }
    let mut catalogue = runtime
        .native_filesystem
        .maintenance_catalogue(now)
        .map_err(|_| ())?;
    let content = catalogue
        .committed_content_by_manifest(effect.manifest_id)
        .map_err(|_| ())?
        .ok_or(())?;
    super::super::repair_projection::project_manifest(
        reader,
        &mut catalogue,
        RepairProjectionManifest {
            volume_id: effect.volume_id,
            content,
        },
    )
    .map_err(|_| ())?;
    let wanted = RepairProjectionCursor {
        revision: reference.revision,
        effect_operation_id: reference.operation_id,
    };
    if catalogue
        .repair_projection_cursor(reader.partition_id(), content)
        .map_err(|_| ())?
        .is_some_and(|cursor| cursor >= wanted)
    {
        let claim_at = super::super::current_time().map_err(|_| ())?.max(now);
        RepairAttempt::claim(runtime, assignment, claim_at)?
            .complete_existing_effect(runtime, reference)?;
    }
    Ok(true)
}

impl RepairAttempt {
    fn complete_existing_effect(
        self,
        runtime: &StorageTargetRuntime,
        effect: MaintenanceEffectReference,
    ) -> Result<(), ()> {
        let mut context = self.completion_context;
        context.occurred_at = super::super::current_time()
            .map_err(|_| ())?
            .max(self.claim_context.occurred_at);
        // The immutable effect reference and fresh fence are checked atomically by
        // metadata. Sample completion time after projection/claim IO so an expired
        // lease cannot be extended by retaining its initial timestamp.
        runtime
            .maintenance_authority
            .commit(
                context,
                &AuthoritativeCommand::CompleteMaintenanceWork(CompleteMaintenanceWork {
                    work_id: self.claim.work_id,
                    claim_generation: self.claim.claim_generation,
                    worker_node_id: self.claim.worker_node_id,
                    worker_incarnation: self.claim.worker_incarnation,
                    fence: self.claim.fence,
                    outcome: MaintenanceWorkCompletion::Succeeded {
                        effect_operation_id: effect.operation_id,
                        effect_revision: effect.revision,
                        effect_result_digest: effect.result_digest,
                    },
                }),
            )
            .map_err(|_| ())?;
        Ok(())
    }
}

#[cfg(test)]
pub(in super::super) fn assert_committed_effect_recovery(
    runtime: &mut super::StorageTargetRuntime,
    previous: &meshspan_metadata::ShardRepairEffectRecord,
    now: meshspan_domain::UnixMicros,
) -> Result<(), Box<dyn std::error::Error>> {
    use super::*;
    use meshspan_metadata::{MaintenanceWorkState, PageLimit};

    let source = previous.replacement_receipt;
    let (attempt, effect, replacement) =
        commit_replacement_without_completion(runtime, previous, now)?;
    let mut catalogue = runtime.native_filesystem.maintenance_catalogue(now)?;
    let content = catalogue
        .committed_content_by_manifest(previous.manifest_id)?
        .ok_or("recovery manifest")?;
    super::super::repair_projection::project_manifest(
        runtime.maintenance_authority.reader(),
        &mut catalogue,
        meshspan_filesystem::RepairProjectionManifest {
            volume_id: previous.volume_id,
            content,
        },
    )?;
    drop(catalogue);
    let resumed_at = attempt.claim.lease_expires_at;
    let reader = super::super::open_root_repository_at(&runtime.state_directory, resumed_at)?;
    let before = reader
        .maintenance_work(attempt.claim.work_id)?
        .ok_or("unfinished repair")?;
    assert_eq!(before.state, MaintenanceWorkState::Claimed);
    assert_eq!(before.attempt_count, 1);
    let assignment = MaintenanceDispatchAssignment {
        work_id: before.work_id,
        subject: before.subject,
        demand: before.demand,
        priority: before.priority,
        claim_generation: 2,
    };
    assert!(RepairSource::load(runtime, assignment, resumed_at).is_err());
    let substituted = MaintenanceDispatchAssignment {
        subject: WorkSubject::Repair {
            volume_id: previous.volume_id,
            manifest_id: previous.manifest_id,
            stripe_index: source.shard.stripe_index,
            shard_index: source.shard.shard_index,
            source_generation: 3,
        },
        ..assignment
    };
    assert!(
        runtime
            .execute_repair_assignment(substituted, resumed_at)
            .is_err()
    );
    assert_eq!(
        reader.maintenance_work(before.work_id)?,
        Some(before.clone())
    );
    runtime
        .execute_repair_assignment(assignment, resumed_at)
        .map_err(|()| "committed effect must complete after its source route was projected away")?;
    let after = reader
        .maintenance_work(before.work_id)?
        .ok_or("recovered work")?;
    assert_eq!(after.state, MaintenanceWorkState::Complete);
    assert_eq!(after.attempt_count, 2);
    assert_eq!(after.result_digest, Some(effect.result_digest));
    let reference = reader
        .maintenance_effect_reference(before.work_id)?
        .ok_or("original committed effect")?;
    assert_eq!(reference.operation_id, effect.operation_id);
    assert_eq!(reference.revision, effect.committed_revision);
    let effects = reader.shard_repair_effects(
        previous.volume_id,
        previous.manifest_id,
        None,
        PageLimit::new(3)?,
    )?;
    assert_eq!(
        effects.items.len(),
        2,
        "recovery creates no second replacement effect"
    );
    let reopened = runtime
        .native_filesystem
        .maintenance_catalogue(resumed_at)?;
    assert_eq!(
        reopened
            .committed_protected_stripe(content, source.shard.stripe_index)?
            .receipts
            .as_slice(),
        &[replacement],
    );
    Ok(())
}

#[cfg(test)]
fn commit_replacement_without_completion(
    runtime: &StorageTargetRuntime,
    previous: &meshspan_metadata::ShardRepairEffectRecord,
    now: UnixMicros,
) -> Result<
    (
        RepairAttempt,
        meshspan_metadata::CommandReceipt,
        meshspan_contracts::ShardReceipt,
    ),
    Box<dyn std::error::Error>,
> {
    use super::{OperatingSystemRandom, claim_deferral_fixture, random_maintenance_context};
    use meshspan_metadata::CommitShardRepair;

    let source = previous.replacement_receipt;
    let subject = WorkSubject::Repair {
        volume_id: previous.volume_id,
        manifest_id: previous.manifest_id,
        stripe_index: source.shard.stripe_index,
        shard_index: source.shard.shard_index,
        source_generation: 2,
    };
    let attempt = claim_deferral_fixture(runtime, subject, now, 126)?;
    // A later repair must never rewind a physical generation. Materialize the exact
    // replacement before committing its route and interrupting terminal completion.
    let catalogue = runtime.native_filesystem.maintenance_catalogue(now)?;
    let content = catalogue
        .committed_content_by_manifest(previous.manifest_id)?
        .ok_or("repair content")?;
    let stripe = catalogue.committed_protected_stripe(content, source.shard.stripe_index)?;
    let targets = runtime.active.values().cloned().collect::<Vec<_>>();
    let mut repairer = runtime
        .native_filesystem
        .maintenance_repairer(&targets, now)?;
    let replacement = repairer.repair(
        meshspan_filesystem::ShardRepairRequest {
            replacement_operation_id: super::super::random_operation_id(&mut OperatingSystemRandom)
                .map_err(|()| "repair operation")?,
            source_receipt: source,
            replacement_target_id: previous.source_receipt.target_id,
            replacement_target_generation: previous.source_receipt.target_generation,
            replacement_shard_generation: source
                .shard
                .generation
                .checked_add(1)
                .ok_or("generation exhausted")?,
            authorization_revision: runtime.maintenance_authority.reader().current_revision()?,
            deadline: attempt.claim.lease_expires_at,
            observed_at: now,
        },
        &stripe,
    )?;
    let effect = runtime.maintenance_authority.commit(
        random_maintenance_context(
            &mut OperatingSystemRandom,
            attempt.claim_context.actor_principal_id,
            now,
        )
        .map_err(|()| "recovery effect context")?,
        &AuthoritativeCommand::CommitShardRepair(CommitShardRepair {
            work_id: attempt.claim.work_id,
            claim_generation: attempt.claim.claim_generation,
            worker_node_id: attempt.claim.worker_node_id,
            worker_incarnation: attempt.claim.worker_incarnation,
            fence: attempt.claim.fence,
            volume_id: previous.volume_id,
            manifest_id: previous.manifest_id,
            source_layout_generation: 2,
            source_receipt: source,
            replacement_receipt: replacement,
        }),
    )?;
    Ok((attempt, effect, replacement))
}
