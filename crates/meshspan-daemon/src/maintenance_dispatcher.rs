// SPDX-License-Identifier: GPL-2.0-only

//! Race-safe selection and local resource reservation for autonomous maintenance workers.

use meshspan_domain::{UnixMicros, WorkId};
use meshspan_metadata::{
    AuthoritativeRepository, MaintenanceWorkRecord, MaintenanceWorkState, ReadyMaintenanceWorkPage,
    RepositoryError,
};
use meshspan_work::{WorkBudget, WorkDemand, WorkSubject, WorkUsage};
use thiserror::Error;

use crate::ConsensusAuthenticationAuthority;

/// Immutable reads required to prepare a local dispatch batch.
pub trait MaintenanceWorkSource {
    /// Selects priority-ordered ready work fitting the caller's current coarse budget.
    ///
    /// # Errors
    ///
    /// Fails closed for invalid bounds, corrupt state or database failure.
    fn ready_work(
        &self,
        now: UnixMicros,
        budget: WorkBudget,
        usage: WorkUsage,
        limit: usize,
    ) -> Result<ReadyMaintenanceWorkPage, RepositoryError>;

    /// Reloads one exact job immediately before local resource reservation.
    ///
    /// # Errors
    ///
    /// Fails closed for corrupt state or database failure.
    fn work(&self, work_id: WorkId) -> Result<Option<MaintenanceWorkRecord>, RepositoryError>;
}

impl MaintenanceWorkSource for AuthoritativeRepository {
    fn ready_work(
        &self,
        now: UnixMicros,
        budget: WorkBudget,
        usage: WorkUsage,
        limit: usize,
    ) -> Result<ReadyMaintenanceWorkPage, RepositoryError> {
        self.ready_maintenance_work(now, budget, usage, None, limit)
    }

    fn work(&self, work_id: WorkId) -> Result<Option<MaintenanceWorkRecord>, RepositoryError> {
        self.maintenance_work(work_id)
    }
}

impl MaintenanceWorkSource for ConsensusAuthenticationAuthority {
    fn ready_work(
        &self,
        now: UnixMicros,
        budget: WorkBudget,
        usage: WorkUsage,
        limit: usize,
    ) -> Result<ReadyMaintenanceWorkPage, RepositoryError> {
        self.reader().ready_work(now, budget, usage, limit)
    }

    fn work(&self, work_id: WorkId) -> Result<Option<MaintenanceWorkRecord>, RepositoryError> {
        self.reader().work(work_id)
    }
}

/// Exact authoritative job snapshot reserved for one local execution attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceDispatchAssignment {
    /// Stable durable job identity.
    pub work_id: WorkId,
    /// Closed operation-specific subject.
    pub subject: WorkSubject,
    /// Maximum local memory/transfer footprint reserved for the attempt.
    pub demand: WorkDemand,
    /// Persisted priority used for deterministic selection.
    pub priority: u64,
    /// Next authoritative fenced-claim generation the executor must request.
    pub claim_generation: u64,
}

/// One locally reserved batch and its complete post-reservation usage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceDispatchBatch {
    /// Assignments safe to launch concurrently, in authoritative priority order.
    pub assignments: Vec<MaintenanceDispatchAssignment>,
    /// Starting usage plus every returned assignment's demand.
    pub reserved_usage: WorkUsage,
}

/// Failure to prepare a trustworthy bounded dispatch batch.
#[derive(Debug, Error)]
pub enum MaintenanceDispatchError {
    /// An authoritative queue read failed closed.
    #[error("maintenance work could not be read")]
    Repository(#[from] RepositoryError),
    /// The selected row and exact job snapshot contradicted one another.
    #[error("maintenance ready-work projection contradicted its authoritative job")]
    InvalidProjection,
    /// Attempt counters or local resource arithmetic exceeded their representation.
    #[error("maintenance dispatch capacity was exceeded")]
    Capacity,
}

/// Stateless dispatcher; fenced claims remain the executor's race-winning boundary.
pub struct MaintenanceDispatcher<'a, Source> {
    source: &'a Source,
}

impl<'a, Source> MaintenanceDispatcher<'a, Source> {
    /// Binds the dispatcher to one current authoritative read source.
    #[must_use]
    pub const fn new(source: &'a Source) -> Self {
        Self { source }
    }
}

impl<Source: MaintenanceWorkSource> MaintenanceDispatcher<'_, Source> {
    /// Selects and locally reserves a bounded priority-ordered batch.
    ///
    /// This method never claims work. Each launched executor commits its exact fenced claim as
    /// its first transition, so another node winning the race cannot leave an idle remote lease.
    /// Rows that changed benignly between selection and reload are ignored for this tick.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits, corrupt projections, database failure and arithmetic overflow.
    pub fn prepare_batch(
        &self,
        now: UnixMicros,
        budget: WorkBudget,
        usage: WorkUsage,
        limit: usize,
    ) -> Result<MaintenanceDispatchBatch, MaintenanceDispatchError> {
        let ready = self.source.ready_work(now, budget, usage, limit)?;
        let mut reserved_usage = usage;
        let mut assignments = Vec::with_capacity(ready.work.len());
        for selected in ready.work {
            let Some(record) = self.source.work(selected.work_id)? else {
                continue;
            };
            if record.revision != selected.revision {
                continue;
            }
            if record.subject != selected.subject
                || record.demand != selected.demand
                || record.priority != selected.priority
            {
                return Err(MaintenanceDispatchError::InvalidProjection);
            }
            if !ready_at(record.state, record.claim, record.next_attempt_at, now) {
                continue;
            }
            if !budget.admits(reserved_usage, record.demand) {
                continue;
            }
            let claim_generation = record
                .attempt_count
                .checked_add(1)
                .ok_or(MaintenanceDispatchError::Capacity)?;
            reserved_usage.active_jobs = reserved_usage
                .active_jobs
                .checked_add(1)
                .ok_or(MaintenanceDispatchError::Capacity)?;
            reserved_usage.in_flight_bytes = reserved_usage
                .in_flight_bytes
                .checked_add(record.demand.in_flight_bytes)
                .ok_or(MaintenanceDispatchError::Capacity)?;
            assignments.push(MaintenanceDispatchAssignment {
                work_id: record.work_id,
                subject: record.subject,
                demand: record.demand,
                priority: record.priority,
                claim_generation,
            });
        }
        Ok(MaintenanceDispatchBatch {
            assignments,
            reserved_usage,
        })
    }
}

fn ready_at(
    state: MaintenanceWorkState,
    claim: Option<meshspan_metadata::MaintenanceWorkClaim>,
    next_attempt_at: UnixMicros,
    now: UnixMicros,
) -> bool {
    if next_attempt_at > now {
        return false;
    }
    match (state, claim) {
        (MaintenanceWorkState::Queued, None) => true,
        (MaintenanceWorkState::Claimed, Some(claim)) => claim.lease_expires_at <= now,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use meshspan_domain::{ContentManifestId, NodeId, Revision, VolumeId};
    use meshspan_metadata::{MaintenanceWorkClaim, ReadyMaintenanceWork};
    use meshspan_work::WorkSignals;

    use super::*;

    #[test]
    fn dispatch_reserves_in_priority_order_and_derives_next_fence_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = record(1, 700, 9, MaintenanceWorkState::Queued, None)?;
        let second = record(
            2,
            400,
            8,
            MaintenanceWorkState::Claimed,
            Some(MaintenanceWorkClaim {
                generation: 2,
                worker_node_id: NodeId::from_bytes([8; 16])?,
                worker_incarnation: 1,
                fence: 3,
                claimed_at: UnixMicros::new(10),
                lease_expires_at: UnixMicros::new(20),
                revision: Revision::new(7),
            }),
        )?;
        let source = FixedSource::new([first.clone(), second.clone()]);
        let budget = WorkBudget::new(2, 1_000, None)?;
        let batch = MaintenanceDispatcher::new(&source).prepare_batch(
            UnixMicros::new(30),
            budget,
            WorkUsage {
                active_jobs: 0,
                in_flight_bytes: 0,
            },
            10,
        )?;
        assert_eq!(batch.assignments.len(), 1);
        assert_eq!(batch.assignments[0].work_id, first.work_id);
        assert_eq!(batch.assignments[0].claim_generation, 1);
        assert_eq!(batch.reserved_usage.active_jobs, 1);
        assert_eq!(batch.reserved_usage.in_flight_bytes, 700);

        let only_second = FixedSource::new([second]);
        let batch = MaintenanceDispatcher::new(&only_second).prepare_batch(
            UnixMicros::new(30),
            budget,
            WorkUsage {
                active_jobs: 0,
                in_flight_bytes: 0,
            },
            10,
        )?;
        assert_eq!(batch.assignments[0].claim_generation, 3);
        Ok(())
    }

    struct FixedSource {
        records: BTreeMap<WorkId, MaintenanceWorkRecord>,
    }

    impl FixedSource {
        fn new<const LENGTH: usize>(records: [MaintenanceWorkRecord; LENGTH]) -> Self {
            Self {
                records: records
                    .into_iter()
                    .map(|record| (record.work_id, record))
                    .collect(),
            }
        }
    }

    impl MaintenanceWorkSource for FixedSource {
        fn ready_work(
            &self,
            _now: UnixMicros,
            _budget: WorkBudget,
            _usage: WorkUsage,
            _limit: usize,
        ) -> Result<ReadyMaintenanceWorkPage, RepositoryError> {
            let mut work = self
                .records
                .values()
                .map(|record| ReadyMaintenanceWork {
                    work_id: record.work_id,
                    subject: record.subject,
                    demand: record.demand,
                    priority: record.priority,
                    revision: record.revision,
                })
                .collect::<Vec<_>>();
            work.sort_by_key(|item| std::cmp::Reverse(item.priority));
            Ok(ReadyMaintenanceWorkPage { work, next: None })
        }

        fn work(&self, work_id: WorkId) -> Result<Option<MaintenanceWorkRecord>, RepositoryError> {
            Ok(self.records.get(&work_id).cloned())
        }
    }

    fn record(
        seed: u8,
        bytes: u64,
        priority: u64,
        state: MaintenanceWorkState,
        claim: Option<MaintenanceWorkClaim>,
    ) -> Result<MaintenanceWorkRecord, meshspan_domain::IdentifierError> {
        Ok(MaintenanceWorkRecord {
            work_id: WorkId::from_bytes([seed; 16])?,
            deduplication_key: [seed; 32],
            subject: WorkSubject::Repair {
                volume_id: VolumeId::from_bytes([3; 16])?,
                manifest_id: ContentManifestId::from_bytes([4; 16])?,
                stripe_index: u64::from(seed),
                shard_index: u16::from(seed),
                source_generation: 1,
            },
            signals: WorkSignals {
                data_unavailable: false,
                remaining_recovery_margin: 1,
                protection_debt: 1,
                locality_debt: 0,
                instability: 0,
                access_heat: 0,
                created_at: UnixMicros::new(1),
                due_at: None,
            },
            demand: WorkDemand {
                in_flight_bytes: bytes,
            },
            priority,
            state,
            next_attempt_at: UnixMicros::new(1),
            attempt_count: claim.map_or(0, |value| value.generation),
            completed_at: None,
            result_digest: None,
            revision: Revision::new(10),
            claim,
        })
    }
}
