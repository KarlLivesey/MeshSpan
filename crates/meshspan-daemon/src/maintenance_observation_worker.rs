// SPDX-License-Identifier: GPL-2.0-only

//! Paged durable job observations on the storage IO worker, independent of job execution.

use crate::runtime_observations::{
    MaintenanceJobCounts, MaintenanceProgressCounts, RuntimeObservations,
};
#[path = "maintenance_observation_progress.rs"]
mod progress;
use meshspan_domain::WorkId;
use meshspan_metadata::{
    AuthoritativeRepository, MaintenanceWorkRecord, MaintenanceWorkState, PageLimit,
};
use meshspan_work::WorkKind;
use std::time::{Duration, Instant};

pub(crate) struct MaintenanceObservationWorker {
    inventory: crate::operational_observation_worker::OperationalObservationWorker,
    observations: RuntimeObservations,
    pass: Option<Pass>,
    next_pass: Option<Instant>,
}

struct Pass {
    progress: MaintenanceProgressCounts,
    started: Instant,
    after: Option<WorkId>,
    jobs: [MaintenanceJobCounts; 5],
}

impl MaintenanceObservationWorker {
    pub(crate) fn new(observations: RuntimeObservations) -> Self {
        Self {
            inventory: crate::operational_observation_worker::OperationalObservationWorker::new(
                observations.clone(),
            ),
            observations,
            pass: None,
            next_pass: None,
        }
    }

    pub(crate) fn tick(
        &mut self,
        repository: &AuthoritativeRepository,
        local: &meshspan_metadata::LocalDatabase,
    ) {
        use meshspan_domain::Clock as _;
        self.inventory
            .tick(repository, crate::OperatingSystemClock.now());
        if self.next_pass.is_some_and(|next| next > Instant::now()) {
            return;
        }
        let pass = self.pass.get_or_insert_with(|| Pass {
            progress: MaintenanceProgressCounts::default(),
            started: Instant::now(),
            after: None,
            jobs: [MaintenanceJobCounts::default(); 5],
        });
        match pass.advance(repository, local) {
            Ok(false) => return,
            Ok(true) => {
                self.observations
                    .record_maintenance_jobs(pass.started, pass.jobs, pass.progress);
            }
            // Preserve the previous completed sample and its increasing age. A partial
            // scan must not replace complete evidence with invented zero queue lengths.
            Err(()) => self.observations.record_maintenance_observation_failure(),
        }
        self.pass = None;
        self.next_pass = Some(Instant::now() + Duration::from_secs(60));
    }
}

impl Pass {
    fn advance(
        &mut self,
        repository: &AuthoritativeRepository,
        local: &meshspan_metadata::LocalDatabase,
    ) -> Result<bool, ()> {
        let page = repository
            .maintenance_observation_page(self.after, PageLimit::new(16).map_err(|_| ())?)
            .map_err(|_| ())?;
        for record in page.items {
            self.progress
                .observe(progress::read(repository, local, &record)?)?;
            let index = match record.subject.kind() {
                WorkKind::Repair => 0,
                WorkKind::Drain => 1,
                WorkKind::Rebalance => 2,
                WorkKind::Reconcile => 3,
                WorkKind::Scrub => 4,
            };
            observe(self.jobs.get_mut(index).ok_or(())?, &record)?;
        }
        self.after = page.next;
        Ok(self.after.is_none())
    }
}

fn observe(counts: &mut MaintenanceJobCounts, record: &MaintenanceWorkRecord) -> Result<(), ()> {
    let state_count = match record.state {
        MaintenanceWorkState::Queued => &mut counts.queued,
        MaintenanceWorkState::Claimed => &mut counts.claimed,
        MaintenanceWorkState::Complete => &mut counts.completed,
    };
    *state_count = state_count.checked_add(1).ok_or(())?;
    if record.state != MaintenanceWorkState::Complete {
        counts.protection_debt = counts
            .protection_debt
            .checked_add(u64::from(record.signals.protection_debt > 0))
            .ok_or(())?;
        counts.locality_debt = counts
            .locality_debt
            .checked_add(u64::from(record.signals.locality_debt > 0))
            .ok_or(())?;
        counts.pending_demand_bytes = counts
            .pending_demand_bytes
            .checked_add(record.demand.in_flight_bytes)
            .ok_or(())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshspan_domain::{NodeId, Revision, UnixMicros, VolumeId};
    use meshspan_metadata::MaintenanceWorkClaim;
    use meshspan_work::{WorkDemand, WorkSignals, WorkSubject};

    #[test]
    fn completed_jobs_do_not_contribute_pending_demand_or_debt()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut record = MaintenanceWorkRecord {
            work_id: WorkId::from_bytes([1; 16])?,
            deduplication_key: [1; 32],
            subject: WorkSubject::Rebalance {
                volume_id: VolumeId::from_bytes([2; 16])?,
                topology_revision: Revision::new(1),
            },
            signals: WorkSignals {
                data_unavailable: false,
                remaining_recovery_margin: 1,
                protection_debt: 3,
                locality_debt: 2,
                instability: 0,
                access_heat: 0,
                created_at: UnixMicros::new(1),
                due_at: None,
            },
            demand: WorkDemand {
                in_flight_bytes: 4_096,
            },
            priority: 1,
            state: MaintenanceWorkState::Queued,
            next_attempt_at: UnixMicros::new(1),
            attempt_count: 0,
            completed_at: None,
            result_digest: None,
            revision: Revision::new(1),
            claim: None,
        };
        let mut counts = MaintenanceJobCounts::default();
        observe(&mut counts, &record).map_err(|()| "queued observation failed")?;
        record.state = MaintenanceWorkState::Claimed;
        record.attempt_count = 1;
        record.claim = Some(MaintenanceWorkClaim {
            generation: 1,
            worker_node_id: NodeId::from_bytes([3; 16])?,
            worker_incarnation: 1,
            fence: 1,
            claimed_at: UnixMicros::new(2),
            lease_expires_at: UnixMicros::new(60),
            revision: Revision::new(2),
        });
        observe(&mut counts, &record).map_err(|()| "claimed observation failed")?;
        record.state = MaintenanceWorkState::Complete;
        record.claim = None;
        record.completed_at = Some(UnixMicros::new(3));
        record.result_digest = Some([3; 32]);
        observe(&mut counts, &record).map_err(|()| "completed observation failed")?;
        assert_eq!((counts.queued, counts.claimed, counts.completed), (1, 1, 1));
        assert_eq!((counts.protection_debt, counts.locality_debt), (2, 2));
        assert_eq!(counts.pending_demand_bytes, 8_192);
        Ok(())
    }
}
