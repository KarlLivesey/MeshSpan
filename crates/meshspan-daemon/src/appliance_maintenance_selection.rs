// SPDX-License-Identifier: GPL-2.0-only

//! Bounded per-family scans and local execution eligibility before work reservation.

use meshspan_domain::{ContentManifestId, UnixMicros, VolumeId};
use meshspan_filesystem::DurableContentCatalog;
use meshspan_metadata::ReadyMaintenanceWork;
use meshspan_work::{DrainScope, WorkBudget, WorkKind, WorkSubject, WorkUsage};

use super::{SCRUB_PAGE_IN_FLIGHT_BYTES, StorageTargetRuntime};
use crate::{MaintenanceDispatchAssignment, MaintenanceDispatchError, MaintenanceDispatcher};

impl StorageTargetRuntime {
    pub(super) fn next_maintenance_assignment(
        &mut self,
        now: UnixMicros,
        kind: WorkKind,
    ) -> Result<Option<MaintenanceDispatchAssignment>, ()> {
        let budget = WorkBudget::new(1, SCRUB_PAGE_IN_FLIGHT_BYTES, None).map_err(|_| ())?;
        let mut dispatcher = MaintenanceDispatcher::resume(
            &self.maintenance_authority,
            self.maintenance_cursors.get(&kind).copied(),
        );
        // Open/validate the catalogue once per repair scan, not once per candidate.
        let catalogue = matches!(kind, WorkKind::Repair)
            .then(|| self.native_filesystem.maintenance_catalogue(now))
            .transpose()
            .map_err(|_| ())?;
        let batch = dispatcher.prepare_batch_where(
            now,
            budget,
            WorkUsage {
                active_jobs: 0,
                in_flight_bytes: 0,
            },
            1_000,
            |selected| {
                if selected.subject.kind() != kind {
                    return Ok(false);
                }
                self.locally_executable_maintenance(selected, catalogue.as_ref())
            },
        );
        // Preserve progress even when a candidate's local validation fails. Its error is
        // still reported, and the authoritative job remains for this or another executor.
        if let Some(cursor) = dispatcher.cursor() {
            self.maintenance_cursors.insert(kind, cursor);
        } else {
            self.maintenance_cursors.remove(&kind);
        }
        Ok(batch.map_err(|_| ())?.assignments.first().copied())
    }

    fn locally_executable_maintenance(
        &self,
        selected: &ReadyMaintenanceWork,
        catalogue: Option<&DurableContentCatalog>,
    ) -> Result<bool, MaintenanceDispatchError> {
        match selected.subject {
            WorkSubject::Scrub {
                target_id,
                target_generation,
            }
            | WorkSubject::Reconcile {
                target_id,
                target_generation,
            } => {
                if !self.active.values().any(|target| {
                    let context = target.context();
                    context.target_id == target_id && context.generation == target_generation
                }) {
                    return Ok(false);
                }
                let current = self
                    .maintenance_authority
                    .reader()
                    .readable_storage_target_provider_context(self.local_node_id, target_id)?;
                Ok(current.is_some_and(|context| context.generation == target_generation))
            }
            WorkSubject::Repair {
                volume_id,
                manifest_id,
                ..
            } => has_repair_manifest(
                catalogue.ok_or(MaintenanceDispatchError::EligibilityUnavailable)?,
                volume_id,
                manifest_id,
            ),
            WorkSubject::Drain(DrainScope::Target { .. }) => {
                let reader = self.maintenance_authority.reader();
                Ok(
                    reader
                        .target_drain_attestation_pending(selected.work_id, self.local_node_id)?
                        || reader
                            .maintenance_effect_reference(selected.work_id)?
                            .is_some(),
                )
            }
            // Node/fault-group drains have their own scope coordinator; they are not
            // target-drain assignments even though they share the durable work family.
            WorkSubject::Drain(DrainScope::Node { .. } | DrainScope::FaultGroup { .. }) => {
                Ok(false)
            }
            WorkSubject::Rebalance { .. } => Ok(true),
        }
    }
}

fn has_repair_manifest(
    catalogue: &DurableContentCatalog,
    volume: VolumeId,
    manifest: ContentManifestId,
) -> Result<bool, MaintenanceDispatchError> {
    let Some(content) = catalogue
        .committed_content_by_manifest(manifest)
        .map_err(|_| MaintenanceDispatchError::EligibilityUnavailable)?
    else {
        return Ok(false);
    };
    let transfer = catalogue
        .committed_layout_transfer(content)
        .map_err(|_| MaintenanceDispatchError::EligibilityUnavailable)?;
    if transfer.volume_id() != volume {
        return Err(MaintenanceDispatchError::InvalidProjection);
    }
    Ok(true)
}
