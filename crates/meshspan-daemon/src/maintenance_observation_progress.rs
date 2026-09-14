// SPDX-License-Identifier: GPL-2.0-only

//! Reuse authoritative effects and local verification checkpoints; never infer bytes from budgets.

use meshspan_contracts::MaintenanceProgressMetric as Metric;
use meshspan_metadata::{
    AuthoritativeRepository, LocalDatabase, MaintenanceWorkRecord, StorageDrainState,
};
use meshspan_work::WorkSubject;

pub(super) fn read(
    repository: &AuthoritativeRepository,
    local: &LocalDatabase,
    record: &MaintenanceWorkRecord,
) -> Result<Option<Vec<Metric>>, ()> {
    if record.state == meshspan_metadata::MaintenanceWorkState::Complete
        && repository
            .maintenance_effect_reference(record.work_id)
            .map_err(|_| ())?
            .is_none()
    {
        return Err(());
    }
    let mut values = Vec::new();
    match record.subject {
        WorkSubject::Repair { .. } => {
            if let Some(reference) = repository
                .maintenance_effect_reference(record.work_id)
                .map_err(|_| ())?
            {
                let effect = repository
                    .shard_repair_effect(reference.operation_id)
                    .map_err(|_| ())?
                    .ok_or(())?;
                if effect.work_id != record.work_id {
                    return Err(());
                }
                values.push(Metric::RepairedBytes(effect.replacement_receipt.length));
            }
        }
        WorkSubject::Scrub { .. } | WorkSubject::Reconcile { .. } => {
            return verification(repository, local, record);
        }
        WorkSubject::Rebalance {
            volume_id,
            topology_revision,
        } => {
            if let Some(progress) = repository
                .rebalance_scan_progress(record.work_id)
                .map_err(|_| ())?
            {
                if progress.volume_id != volume_id
                    || progress.topology_revision != topology_revision
                {
                    return Err(());
                }
                values.extend([
                    Metric::RebalanceScannedStripes(progress.scanned_stripes),
                    Metric::RebalanceQueuedRepairs(progress.queued_repairs),
                ]);
            }
        }
        WorkSubject::Drain(scope) => {
            let drain = repository
                .storage_drain(record.work_id)
                .map_err(|_| ())?
                .ok_or(())?;
            if drain.scope != scope {
                return Err(());
            }
            values.push(Metric::SafeDrains(u64::from(
                drain.state == StorageDrainState::SafeToDetach,
            )));
        }
    }
    Ok(Some(values))
}

fn verification(
    repository: &AuthoritativeRepository,
    local: &LocalDatabase,
    record: &MaintenanceWorkRecord,
) -> Result<Option<Vec<Metric>>, ()> {
    let (target, generation, scrub) = match record.subject {
        WorkSubject::Scrub {
            target_id,
            target_generation,
        } => (target_id, target_generation, true),
        WorkSubject::Reconcile {
            target_id,
            target_generation,
        } => (target_id, target_generation, false),
        _ => return Err(()),
    };
    let progress = repository
        .maintenance_verification_progress(record.work_id)
        .map_err(|_| ())?;
    let (observations, bytes) = if let Some(progress) = progress {
        (progress.observations, progress.verified_bytes)
    } else if let Some(progress) = local.scrub_progress(record.work_id).map_err(|_| ())? {
        if progress.target_id != target || progress.target_generation != generation {
            return Err(());
        }
        (progress.observation_count, progress.verified_bytes)
    } else if record.attempt_count == 0 {
        (0, 0)
    } else {
        // Work may be active on another node. No local checkpoint is not zero progress.
        return Ok(None);
    };
    Ok(Some(if scrub {
        vec![
            Metric::ScrubObservations(observations),
            Metric::ScrubVerifiedBytes(bytes),
        ]
    } else {
        vec![
            Metric::ReconciliationObservations(observations),
            Metric::ReconciliationVerifiedBytes(bytes),
        ]
    }))
}
