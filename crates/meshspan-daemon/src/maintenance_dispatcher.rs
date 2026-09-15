// SPDX-License-Identifier: GPL-2.0-only

//! Race-safe selection and local resource reservation for autonomous maintenance workers.

use meshspan_domain::{UnixMicros, WorkId};
use meshspan_metadata::{
    AuthoritativeRepository, MaintenanceWorkCursor, MaintenanceWorkRecord, MaintenanceWorkState,
    ReadyMaintenanceWork, ReadyMaintenanceWorkPage, RepositoryError,
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
        after: Option<MaintenanceWorkCursor>,
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
        after: Option<MaintenanceWorkCursor>,
    ) -> Result<ReadyMaintenanceWorkPage, RepositoryError> {
        self.ready_maintenance_work(now, budget, usage, after, limit)
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
        after: Option<MaintenanceWorkCursor>,
    ) -> Result<ReadyMaintenanceWorkPage, RepositoryError> {
        self.reader().ready_work(now, budget, usage, limit, after)
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
    /// Local immutable state required for execution could not be validated.
    #[error("maintenance local execution state could not be read")]
    EligibilityUnavailable,
}

/// Bounded queue scan; fenced claims remain the executor's race-winning boundary.
///
/// The cursor is scheduling progress, not authority or evidence that skipped work completed.
pub struct MaintenanceDispatcher<'a, Source> {
    source: &'a Source,
    after: Option<MaintenanceWorkCursor>,
}

impl<'a, Source> MaintenanceDispatcher<'a, Source> {
    /// Binds the dispatcher to one current authoritative read source.
    #[must_use]
    pub const fn new(source: &'a Source) -> Self {
        Self {
            source,
            after: None,
        }
    }

    /// Resumes a prior bounded scan against the current authoritative queue.
    #[must_use]
    pub const fn resume(source: &'a Source, after: Option<MaintenanceWorkCursor>) -> Self {
        Self { source, after }
    }

    /// Returns the last examined position, or the beginning after a completed scan.
    #[must_use]
    pub const fn cursor(&self) -> Option<MaintenanceWorkCursor> {
        self.after
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
        &mut self,
        now: UnixMicros,
        budget: WorkBudget,
        usage: WorkUsage,
        limit: usize,
    ) -> Result<MaintenanceDispatchBatch, MaintenanceDispatchError> {
        self.prepare_batch_where(now, budget, usage, limit, |_| Ok(true))
    }

    /// Selects only subjects executable by this local runtime before reserving resources.
    ///
    /// # Errors
    ///
    /// Has the same closed failure modes as [`Self::prepare_batch`].
    pub fn prepare_batch_where(
        &mut self,
        now: UnixMicros,
        budget: WorkBudget,
        usage: WorkUsage,
        limit: usize,
        executable: impl Fn(&ReadyMaintenanceWork) -> Result<bool, MaintenanceDispatchError>,
    ) -> Result<MaintenanceDispatchBatch, MaintenanceDispatchError> {
        let ready = self
            .source
            .ready_work(now, budget, usage, limit, self.after)?;
        let next_page = ready.next;
        let mut candidates = ready.work.into_iter();
        let mut reserved_usage = usage;
        let mut assignments = Vec::new();
        while reserved_usage.active_jobs < budget.maximum_concurrent_jobs() {
            let Some(selected) = candidates.next() else {
                break;
            };
            self.after = Some(selected.cursor());
            if !executable(&selected)? {
                continue;
            }
            let Some(assignment) = self.current_assignment(selected, now)? else {
                continue;
            };
            if !budget.admits(reserved_usage, assignment.demand) {
                continue;
            }
            reserved_usage.active_jobs = reserved_usage
                .active_jobs
                .checked_add(1)
                .ok_or(MaintenanceDispatchError::Capacity)?;
            reserved_usage.in_flight_bytes = reserved_usage
                .in_flight_bytes
                .checked_add(assignment.demand.in_flight_bytes)
                .ok_or(MaintenanceDispatchError::Capacity)?;
            assignments.push(assignment);
        }
        // A full local budget can stop in the middle of a fetched page. Resume after the
        // last examined row, not the page end, so unexamined executable jobs remain next.
        if candidates.len() == 0 {
            self.after = next_page;
        }
        Ok(MaintenanceDispatchBatch {
            assignments,
            reserved_usage,
        })
    }

    fn current_assignment(
        &self,
        selected: ReadyMaintenanceWork,
        now: UnixMicros,
    ) -> Result<Option<MaintenanceDispatchAssignment>, MaintenanceDispatchError> {
        let Some(record) = self.source.work(selected.work_id)? else {
            return Ok(None);
        };
        if record.revision != selected.revision {
            return Ok(None);
        }
        if record.subject != selected.subject
            || record.demand != selected.demand
            || record.priority != selected.priority
        {
            return Err(MaintenanceDispatchError::InvalidProjection);
        }
        if !ready_at(record.state, record.claim, record.next_attempt_at, now) {
            return Ok(None);
        }
        let claim_generation = record
            .attempt_count
            .checked_add(1)
            .ok_or(MaintenanceDispatchError::Capacity)?;
        Ok(Some(MaintenanceDispatchAssignment {
            work_id: record.work_id,
            subject: record.subject,
            demand: record.demand,
            priority: record.priority,
            claim_generation,
        }))
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

    #[test]
    fn executable_work_remains_reachable_beyond_the_first_thousand_candidates()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut records = BTreeMap::new();
        for index in 1_u128..=1_001 {
            let mut work = record(1, 1, 9, MaintenanceWorkState::Queued, None)?;
            work.work_id = WorkId::from_bytes(index.to_be_bytes())?;
            work.deduplication_key[..16].copy_from_slice(&work.work_id.as_bytes());
            if let WorkSubject::Repair { stripe_index, .. } = &mut work.subject {
                *stripe_index = u64::try_from(index)?;
            }
            records.insert(work.work_id, work);
        }
        let mut expected = record(2, 1, 8, MaintenanceWorkState::Queued, None)?;
        expected.subject = WorkSubject::Scrub {
            target_id: meshspan_domain::TargetId::from_bytes([5; 16])?,
            target_generation: 1,
        };
        let expected_id = expected.work_id;
        records.insert(expected_id, expected);
        let source = FixedSource { records };
        let mut dispatcher = MaintenanceDispatcher::new(&source);
        let mut found = Vec::new();
        for _round in 0..2 {
            let batch = dispatcher.prepare_batch_where(
                UnixMicros::new(30),
                WorkBudget::new(1, 1_000, None)?,
                WorkUsage {
                    active_jobs: 0,
                    in_flight_bytes: 0,
                },
                1_000,
                |work| Ok(matches!(work.subject, WorkSubject::Scrub { .. })),
            )?;
            found.extend(batch.assignments.into_iter().map(|work| work.work_id));
        }
        assert_eq!(
            found,
            vec![expected_id],
            "a bounded scan must move past unrelated jobs"
        );
        assert!(source.records.values().all(|work| work.attempt_count == 0));
        Ok(())
    }

    #[test]
    fn resumed_scan_keeps_unexamined_candidates_and_wraps_after_the_last_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = FixedSource::new([
            record(1, 100, 9, MaintenanceWorkState::Queued, None)?,
            record(2, 100, 8, MaintenanceWorkState::Queued, None)?,
            record(3, 100, 7, MaintenanceWorkState::Queued, None)?,
        ]);
        let mut cursor = None;
        let mut selected = Vec::new();
        let mut positions = Vec::new();
        for _round in 0..3 {
            let mut dispatcher = MaintenanceDispatcher::resume(&source, cursor);
            let batch = dispatcher.prepare_batch(
                UnixMicros::new(30),
                WorkBudget::new(1, 1_000, None)?,
                WorkUsage {
                    active_jobs: 0,
                    in_flight_bytes: 0,
                },
                3,
            )?;
            assert_eq!(batch.assignments.len(), 1);
            selected.push(batch.assignments[0].work_id);
            cursor = dispatcher.cursor();
            positions.push(cursor);
        }
        let first = WorkId::from_bytes([1; 16])?;
        let second = WorkId::from_bytes([2; 16])?;
        assert_eq!(selected, [first, second, WorkId::from_bytes([3; 16])?]);
        assert_eq!(
            positions,
            [
                Some(MaintenanceWorkCursor {
                    priority: 9,
                    created_at: UnixMicros::new(1),
                    work_id: first
                }),
                Some(MaintenanceWorkCursor {
                    priority: 8,
                    created_at: UnixMicros::new(1),
                    work_id: second
                }),
                None,
            ]
        );
        Ok(())
    }

    #[test]
    fn local_validation_failure_is_reported_without_restarting_the_scan()
    -> Result<(), Box<dyn std::error::Error>> {
        let unavailable = record(1, 100, 9, MaintenanceWorkState::Queued, None)?;
        let eligible = record(2, 100, 8, MaintenanceWorkState::Queued, None)?;
        let unavailable_id = unavailable.work_id;
        let eligible_id = eligible.work_id;
        let source = FixedSource::new([unavailable, eligible]);
        let mut dispatcher = MaintenanceDispatcher::new(&source);
        let budget = WorkBudget::new(1, 1_000, None)?;
        let usage = WorkUsage {
            active_jobs: 0,
            in_flight_bytes: 0,
        };
        let result = dispatcher.prepare_batch_where(UnixMicros::new(30), budget, usage, 2, |_| {
            Err(MaintenanceDispatchError::EligibilityUnavailable)
        });
        assert!(matches!(
            result,
            Err(MaintenanceDispatchError::EligibilityUnavailable)
        ));
        assert_eq!(
            dispatcher.cursor().map(|cursor| cursor.work_id),
            Some(unavailable_id)
        );
        let mut resumed = MaintenanceDispatcher::resume(&source, dispatcher.cursor());
        let batch = resumed.prepare_batch(UnixMicros::new(30), budget, usage, 2)?;
        assert_eq!(batch.assignments.len(), 1);
        assert_eq!(batch.assignments[0].work_id, eligible_id);
        assert_eq!(batch.reserved_usage.in_flight_bytes, 100);
        assert!(resumed.cursor().is_none());
        assert!(source.records.values().all(|work| work.attempt_count == 0));
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
            limit: usize,
            after: Option<MaintenanceWorkCursor>,
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
                    created_at: record.signals.created_at,
                })
                .collect::<Vec<_>>();
            work.sort_by_key(|item| {
                (
                    std::cmp::Reverse(item.priority),
                    item.created_at,
                    item.work_id,
                )
            });
            if let Some(after) = after {
                let boundary = (
                    std::cmp::Reverse(after.priority),
                    after.created_at,
                    after.work_id,
                );
                work.retain(|item| {
                    (
                        std::cmp::Reverse(item.priority),
                        item.created_at,
                        item.work_id,
                    ) > boundary
                });
            }
            let next = if work.len() > limit {
                work.truncate(limit);
                work.last().map(ReadyMaintenanceWork::cursor)
            } else {
                None
            };
            Ok(ReadyMaintenanceWorkPage { work, next })
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
