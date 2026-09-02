// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative durable maintenance jobs and short-lived fenced execution claims.

use meshspan_domain::{NodeId, OperationId, Revision, UnixMicros, WorkId};
use meshspan_work::{WorkBudget, WorkDemand, WorkKind, WorkSignals, WorkSubject, WorkUsage};
use rusqlite::{OptionalExtension, Row, Transaction, params};

use super::apply::to_i64;
use super::{AuthoritativeRepository, EntityKind, EntityReference, RepositoryError};
use crate::{
    ClaimMaintenanceWork, CommandContext, CommitScrubPass, CommitShardRepair,
    CompleteMaintenanceWork, MaintenanceWorkCompletion, QueueMaintenanceWork, RenewMaintenanceWork,
};

mod drain;
mod repair;
mod scrub;
mod scrub_schedule;

pub use repair::ShardRepairEffectRecord;
pub use scrub::ScrubPassEffectRecord;
pub use scrub_schedule::{DueStorageScrub, DueStorageScrubCursor, DueStorageScrubPage};

pub(super) use drain::begin_target;

const JOB_QUEUED: i64 = 1;
const JOB_CLAIMED: i64 = 2;
const JOB_COMPLETE: i64 = 3;
const CLAIM_ACTIVE: i64 = 1;
const CLAIM_SUPERSEDED: i64 = 2;
const CLAIM_COMPLETE: i64 = 3;
const ACTIVE_NODE: i64 = 2;
const MAXIMUM_LEASE_MICROS: i64 = 15 * 60 * 1_000_000;
const MAXIMUM_READY_PAGE_ITEMS: usize = 1_000;

// Reserved operation-kind values for the Stage 9 domain effects which are allowed to make each
// job terminal. Until those transitions exist, a worker can safely retry but cannot manufacture
// successful work from an unrelated operation receipt.
const REPAIR_EFFECT_KIND: i64 = 105;
const SCRUB_EFFECT_KIND: i64 = 106;
const DRAIN_EFFECT_KIND: i64 = 108;
const REBALANCE_EFFECT_KIND: i64 = 109;
const RECONCILE_EFFECT_KIND: i64 = 110;

/// Durable lifecycle of one deduplicated maintenance job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceWorkState {
    /// Eligible for a claim once `next_attempt_at` is reached.
    Queued,
    /// Owned by one current unexpired fenced claim.
    Claimed,
    /// Terminal effect was linked to an exact authoritative operation.
    Complete,
}

/// Current fenced execution claim, if the job has one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceWorkClaim {
    /// Monotonic claim generation.
    pub generation: u64,
    /// Worker node owning the lease.
    pub worker_node_id: NodeId,
    /// Exact worker incarnation.
    pub worker_incarnation: u64,
    /// Unpredictable positive fence.
    pub fence: u64,
    /// Original authoritative claim instant.
    pub claimed_at: UnixMicros,
    /// Current authoritative lease end.
    pub lease_expires_at: UnixMicros,
    /// Revision of the latest claim transition.
    pub revision: Revision,
}

/// Exact authoritative state of one maintenance job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceWorkRecord {
    /// Stable job identity.
    pub work_id: WorkId,
    /// Semantic deduplication key.
    pub deduplication_key: [u8; 32],
    /// Closed generation-bound subject.
    pub subject: WorkSubject,
    /// Latest coalesced safety signals.
    pub signals: WorkSignals,
    /// Maximum bytes retained by one attempt.
    pub demand: WorkDemand,
    /// Persisted deterministic priority score.
    pub priority: u64,
    /// Current durable lifecycle state.
    pub state: MaintenanceWorkState,
    /// Earliest next claim instant.
    pub next_attempt_at: UnixMicros,
    /// Number of fenced attempts created so far.
    pub attempt_count: u64,
    /// Terminal completion instant, if complete.
    pub completed_at: Option<UnixMicros>,
    /// Exact authoritative effect-result digest, if complete.
    pub result_digest: Option<[u8; 32]>,
    /// Latest job transition revision.
    pub revision: Revision,
    /// Current active claim, including an expired claim awaiting fenced replacement.
    pub claim: Option<MaintenanceWorkClaim>,
}

/// Minimal immutable effect reference needed to recover after a lost completion response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceEffectReference {
    /// Exact committed domain-effect operation.
    pub operation_id: OperationId,
    /// Authoritative revision committed by the effect.
    pub revision: Revision,
    /// Exact operation-result digest accepted by work completion.
    pub result_digest: [u8; 32],
}

impl AuthoritativeRepository {
    /// Returns one exact durable maintenance job and its current claim.
    ///
    /// # Errors
    ///
    /// Fails closed when persisted identities, subject bytes, signals, state or claim contradict
    /// the schema and lifecycle invariants.
    pub fn maintenance_work(
        &self,
        work_id: WorkId,
    ) -> Result<Option<MaintenanceWorkRecord>, RepositoryError> {
        load_record(self.database.connection(), work_id)
    }

    /// Returns the highest-priority ready work that fits the caller's remaining local budget.
    ///
    /// Expired claims are eligible for a newly fenced attempt. This read never mutates or
    /// transfers ownership by itself; the following claim is the authoritative race boundary.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive bounds, impossible usage, corrupt rows and SQLite failures.
    pub fn ready_maintenance_work(
        &self,
        now: UnixMicros,
        budget: WorkBudget,
        usage: WorkUsage,
        after: Option<MaintenanceWorkCursor>,
        limit: usize,
    ) -> Result<ReadyMaintenanceWorkPage, RepositoryError> {
        ready_page(self.database.connection(), now, budget, usage, after, limit)
    }

    /// Returns one committed shard-repair transition with both exact provider receipts.
    ///
    /// # Errors
    ///
    /// Fails closed when any persisted identity, digest, length or generation is malformed.
    pub fn shard_repair_effect(
        &self,
        effect_operation_id: OperationId,
    ) -> Result<Option<ShardRepairEffectRecord>, RepositoryError> {
        repair::load(self.database.connection(), effect_operation_id)
    }

    /// Returns one committed complete scrub-pass summary.
    ///
    /// # Errors
    ///
    /// Fails closed when any persisted identity, count, digest or generation is malformed.
    pub fn scrub_pass_effect(
        &self,
        effect_operation_id: OperationId,
    ) -> Result<Option<ScrubPassEffectRecord>, RepositoryError> {
        scrub::load(self.database.connection(), effect_operation_id)
    }

    /// Returns an already committed effect for one maintenance job, if present.
    ///
    /// This is the recovery boundary after the effect commits but its worker crashes before
    /// completing the fenced job. A later claim links this exact immutable effect instead of
    /// repeating physical work or inventing another effect.
    ///
    /// # Errors
    ///
    /// Fails closed when job/effect/operation state is malformed or contradictory.
    pub fn maintenance_effect_reference(
        &self,
        work_id: WorkId,
    ) -> Result<Option<MaintenanceEffectReference>, RepositoryError> {
        effect_reference(self.database.connection(), work_id)
    }

    /// Returns local active target generations whose last complete scrub is overdue.
    ///
    /// A never-scrubbed generation becomes due relative to its authoritative admission time.
    /// The returned due instant is stable, allowing repeated planners to deduplicate the same
    /// cycle until a complete scrub effect advances it.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive bounds, impossible time arithmetic, corrupt rows and SQLite
    /// failures.
    pub fn due_storage_scrubs(
        &self,
        node_id: NodeId,
        now: UnixMicros,
        maximum_verification_age: meshspan_domain::DurationMicros,
        after: Option<DueStorageScrubCursor>,
        limit: usize,
    ) -> Result<DueStorageScrubPage, RepositoryError> {
        scrub_schedule::due_page(
            self.database.connection(),
            node_id,
            now,
            maximum_verification_age,
            after,
            limit,
        )
    }
}

fn effect_reference(
    connection: &rusqlite::Connection,
    work_id: WorkId,
) -> Result<Option<MaintenanceEffectReference>, RepositoryError> {
    let Some(job) = load_record(connection, work_id)? else {
        return Ok(None);
    };
    let (table, expected_kind) = match job.subject.kind() {
        WorkKind::Repair => ("maintenance_repair_effects", REPAIR_EFFECT_KIND),
        WorkKind::Scrub => ("maintenance_scrub_effects", SCRUB_EFFECT_KIND),
        WorkKind::Drain | WorkKind::Rebalance | WorkKind::Reconcile => return Ok(None),
    };
    let sql = format!(
        "SELECT effect.effect_operation_id, operation.revision, operation.result_digest,
                operation.operation_kind
         FROM {table} effect
         JOIN operations operation ON operation.operation_id = effect.effect_operation_id
         WHERE effect.work_id = ?1"
    );
    connection
        .query_row(&sql, [work_id.as_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .optional()?
        .map(|(operation, revision_value, digest, kind)| {
            let result_digest = exact(digest)?;
            if kind != expected_kind || result_digest == [0; 32] {
                return Err(RepositoryError::CorruptState);
            }
            Ok(MaintenanceEffectReference {
                operation_id: OperationId::from_bytes(exact(operation)?)
                    .map_err(|_| RepositoryError::CorruptState)?,
                revision: revision(revision_value)?,
                result_digest,
            })
        })
        .transpose()
}

/// Stable keyset position in the deterministic maintenance priority order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceWorkCursor {
    /// Persisted priority score, ordered descending.
    pub priority: u64,
    /// Original creation instant, ordered ascending within equal priority.
    pub created_at: UnixMicros,
    /// Stable final tie-breaker.
    pub work_id: WorkId,
}

/// One ready, budget-admitted maintenance assignment awaiting an authoritative claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyMaintenanceWork {
    /// Stable job identity.
    pub work_id: WorkId,
    /// Exact generation-bound subject.
    pub subject: WorkSubject,
    /// Maximum attempt memory/transfer footprint.
    pub demand: WorkDemand,
    /// Persisted deterministic priority.
    pub priority: u64,
    /// Revision a claimant observed.
    pub revision: Revision,
}

/// One bounded keyset page of ready work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyMaintenanceWorkPage {
    /// Assignments ordered by safety priority.
    pub work: Vec<ReadyMaintenanceWork>,
    /// Cursor for the next page, when more fitting work exists.
    pub next: Option<MaintenanceWorkCursor>,
}

fn ready_page(
    connection: &rusqlite::Connection,
    now: UnixMicros,
    budget: WorkBudget,
    usage: WorkUsage,
    after: Option<MaintenanceWorkCursor>,
    limit: usize,
) -> Result<ReadyMaintenanceWorkPage, RepositoryError> {
    if limit == 0
        || limit > MAXIMUM_READY_PAGE_ITEMS
        || usage.in_flight_bytes > budget.maximum_in_flight_bytes()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    if usage.active_jobs >= budget.maximum_concurrent_jobs() {
        return Ok(ReadyMaintenanceWorkPage {
            work: Vec::new(),
            next: None,
        });
    }
    let remaining_bytes = budget
        .maximum_in_flight_bytes()
        .checked_sub(usage.in_flight_bytes)
        .ok_or(RepositoryError::InvalidCommand)?;
    let (has_cursor, cursor_priority, cursor_created_at, cursor_work_id) = match after {
        Some(cursor) => (
            1_i64,
            to_i64(cursor.priority)?,
            cursor.created_at.get(),
            cursor.work_id.as_bytes(),
        ),
        None => (0_i64, 0_i64, 0_i64, [0_u8; 16]),
    };
    let mut statement = connection.prepare(
        "SELECT j.work_id, j.work_kind, j.subject_payload, j.in_flight_bytes,
                j.priority, j.revision, j.created_at
         FROM maintenance_work_jobs j
         LEFT JOIN maintenance_work_claims c ON c.work_id = j.work_id AND c.state = ?1
         WHERE j.next_attempt_at <= ?2
           AND (j.state = ?3 OR (j.state = ?4 AND c.lease_expires_at <= ?2))
           AND j.in_flight_bytes <= ?5
           AND (?6 = 0 OR j.priority < ?7
                OR (j.priority = ?7 AND j.created_at > ?8)
                OR (j.priority = ?7 AND j.created_at = ?8 AND j.work_id > ?9))
         ORDER BY j.priority DESC, j.created_at, j.work_id
         LIMIT ?10",
    )?;
    let rows = statement.query_map(
        params![
            CLAIM_ACTIVE,
            now.get(),
            JOB_QUEUED,
            JOB_CLAIMED,
            to_i64(remaining_bytes)?,
            has_cursor,
            cursor_priority,
            cursor_created_at,
            cursor_work_id.as_slice(),
            i64::try_from(limit.saturating_add(1))
                .map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        decode_ready_work,
    )?;
    let mut work = rows.collect::<Result<Vec<_>, _>>()?;
    let next = if work.len() > limit {
        work.pop();
        work.last().map(|item| MaintenanceWorkCursor {
            priority: item.work.priority,
            created_at: item.created_at,
            work_id: item.work.work_id,
        })
    } else {
        None
    };
    Ok(ReadyMaintenanceWorkPage {
        work: work.into_iter().map(|item| item.work).collect(),
        next,
    })
}

struct ReadyWorkRow {
    work: ReadyMaintenanceWork,
    created_at: UnixMicros,
}

fn decode_ready_work(row: &Row<'_>) -> rusqlite::Result<ReadyWorkRow> {
    decode_ready_work_inner(row).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_ready_work_inner(row: &Row<'_>) -> Result<ReadyWorkRow, RepositoryError> {
    let stored_kind = row.get::<_, i64>(1)?;
    let subject = WorkSubject::decode(&row.get::<_, Vec<u8>>(2)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    if stored_kind != kind_code(subject.kind()) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(ReadyWorkRow {
        work: ReadyMaintenanceWork {
            work_id: WorkId::from_bytes(exact(row.get(0)?)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            subject,
            demand: WorkDemand {
                in_flight_bytes: positive(row.get(3)?)?,
            },
            priority: positive(row.get(4)?)?,
            revision: revision(row.get(5)?)?,
        },
        created_at: UnixMicros::new(row.get(6)?),
    })
}

pub(super) fn queue(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: QueueMaintenanceWork,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_queue(transaction, context, value)?;
    let payload = value.subject.encode();
    if let Some(existing) = existing_deduplicated(transaction, value.deduplication_key)? {
        if existing.kind != kind_code(value.subject.kind())
            || existing.subject_payload != payload
            || (existing.work_id != value.work_id && work_id_exists(transaction, value.work_id)?)
        {
            return Err(RepositoryError::InvalidCommand);
        }
        if existing.state != JOB_COMPLETE {
            merge_signals(transaction, existing.work_id, context, value, revision)?;
        }
        return Ok(entity(existing.work_id));
    }
    if work_id_exists(transaction, value.work_id)? {
        return Err(RepositoryError::InvalidCommand);
    }
    let priority = value.signals.priority(context.occurred_at).get();
    transaction.execute(
        "INSERT INTO maintenance_work_jobs(
            work_id, deduplication_key, work_kind, subject_payload, data_unavailable,
            remaining_recovery_margin, protection_debt, locality_debt, instability, access_heat,
            in_flight_bytes, due_at, priority, state, next_attempt_at, attempt_count, created_at,
            completed_at, result_digest, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 0,
                   ?16, NULL, NULL, ?17)",
        params![
            value.work_id.as_bytes().as_slice(),
            value.deduplication_key.as_slice(),
            kind_code(value.subject.kind()),
            payload,
            i64::from(value.signals.data_unavailable),
            i64::from(value.signals.remaining_recovery_margin),
            i64::from(value.signals.protection_debt),
            i64::from(value.signals.locality_debt),
            i64::from(value.signals.instability),
            i64::from(value.signals.access_heat),
            to_i64(value.demand.in_flight_bytes)?,
            value.signals.due_at.map(UnixMicros::get),
            to_i64(priority)?,
            JOB_QUEUED,
            value.next_attempt_at.get(),
            value.signals.created_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(entity(value.work_id))
}

pub(super) fn claim(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: ClaimMaintenanceWork,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_lease(context.occurred_at, value.lease_expires_at)?;
    validate_worker(transaction, value.worker_node_id, value.worker_incarnation)?;
    let job = load_job_for_transition(transaction, value.work_id)?;
    if job.state == JOB_COMPLETE || job.next_attempt_at > context.occurred_at.get() {
        return Err(RepositoryError::InvalidCommand);
    }
    let active = active_claim(transaction, value.work_id)?;
    match (job.state, active) {
        (JOB_QUEUED, None) => {}
        (JOB_CLAIMED, Some(claim)) if claim.lease_expires_at <= context.occurred_at.get() => {
            transaction.execute(
                "UPDATE maintenance_work_claims SET state = ?1, revision = ?2
                 WHERE work_id = ?3 AND claim_generation = ?4 AND state = ?5",
                params![
                    CLAIM_SUPERSEDED,
                    to_i64(revision.get())?,
                    value.work_id.as_bytes().as_slice(),
                    to_i64(claim.generation)?,
                    CLAIM_ACTIVE,
                ],
            )?;
        }
        (JOB_QUEUED | JOB_CLAIMED, _) => return Err(RepositoryError::InvalidCommand),
        _ => return Err(RepositoryError::CorruptState),
    }
    let expected_generation = latest_claim_generation(transaction, value.work_id)?
        .checked_add(1)
        .ok_or(RepositoryError::CapacityExceeded)?;
    if value.claim_generation != expected_generation
        || value.worker_incarnation == 0
        || value.fence == 0
    {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO maintenance_work_claims(
            work_id, claim_generation, worker_node_id, worker_incarnation, fence, claimed_at,
            lease_expires_at, state, completed_at, result_digest, retry_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, NULL, ?9)",
        params![
            value.work_id.as_bytes().as_slice(),
            to_i64(value.claim_generation)?,
            value.worker_node_id.as_bytes().as_slice(),
            to_i64(value.worker_incarnation)?,
            to_i64(value.fence)?,
            context.occurred_at.get(),
            value.lease_expires_at.get(),
            CLAIM_ACTIVE,
            to_i64(revision.get())?,
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE maintenance_work_jobs
         SET state = ?1, attempt_count = attempt_count + 1, revision = ?2
         WHERE work_id = ?3 AND state IN (?4, ?5)",
        params![
            JOB_CLAIMED,
            to_i64(revision.get())?,
            value.work_id.as_bytes().as_slice(),
            JOB_QUEUED,
            JOB_CLAIMED,
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(entity(value.work_id))
}

pub(super) fn renew(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: RenewMaintenanceWork,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_lease(context.occurred_at, value.lease_expires_at)?;
    validate_worker(transaction, value.worker_node_id, value.worker_incarnation)?;
    let claim = require_live_claim(
        transaction,
        context,
        value.work_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    if value.lease_expires_at.get() <= claim.lease_expires_at {
        return Err(RepositoryError::InvalidCommand);
    }
    let changed = transaction.execute(
        "UPDATE maintenance_work_claims SET lease_expires_at = ?1, revision = ?2
         WHERE work_id = ?3 AND claim_generation = ?4 AND state = ?5",
        params![
            value.lease_expires_at.get(),
            to_i64(revision.get())?,
            value.work_id.as_bytes().as_slice(),
            to_i64(value.claim_generation)?,
            CLAIM_ACTIVE,
        ],
    )?;
    update_job_revision(transaction, value.work_id, revision, changed)?;
    Ok(entity(value.work_id))
}

pub(super) fn complete(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: CompleteMaintenanceWork,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_worker(transaction, value.worker_node_id, value.worker_incarnation)?;
    require_live_claim(
        transaction,
        context,
        value.work_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    let subject = load_job_for_transition(transaction, value.work_id)?.subject;
    let (job_state, next_attempt_at, completed_at, job_result, claim_result, retry_at) =
        completion_values(transaction, context, value.work_id, subject, value.outcome)?;
    let changed = transaction.execute(
        "UPDATE maintenance_work_claims
         SET state = ?1, completed_at = ?2, result_digest = ?3, retry_at = ?4, revision = ?5
         WHERE work_id = ?6 AND claim_generation = ?7 AND state = ?8",
        params![
            CLAIM_COMPLETE,
            context.occurred_at.get(),
            claim_result.as_slice(),
            retry_at,
            to_i64(revision.get())?,
            value.work_id.as_bytes().as_slice(),
            to_i64(value.claim_generation)?,
            CLAIM_ACTIVE,
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::CorruptState);
    }
    let changed = transaction.execute(
        "UPDATE maintenance_work_jobs
         SET state = ?1, next_attempt_at = ?2, completed_at = ?3, result_digest = ?4,
             revision = ?5
         WHERE work_id = ?6 AND state = ?7",
        params![
            job_state,
            next_attempt_at,
            completed_at,
            job_result.as_ref().map(<[u8; 32]>::as_slice),
            to_i64(revision.get())?,
            value.work_id.as_bytes().as_slice(),
            JOB_CLAIMED,
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(entity(value.work_id))
}

pub(super) fn commit_repair(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &CommitShardRepair,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    repair::commit(transaction, context, value, revision)
}

pub(super) fn commit_scrub(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: CommitScrubPass,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    scrub::commit(transaction, context, value, revision)
}

type CompletionValues = (
    i64,
    i64,
    Option<i64>,
    Option<[u8; 32]>,
    [u8; 32],
    Option<i64>,
);

fn completion_values(
    transaction: &Transaction<'_>,
    context: CommandContext,
    work_id: WorkId,
    subject: WorkSubject,
    outcome: MaintenanceWorkCompletion,
) -> Result<CompletionValues, RepositoryError> {
    match outcome {
        MaintenanceWorkCompletion::Succeeded {
            effect_operation_id,
            effect_revision,
            effect_result_digest,
        } => {
            if effect_result_digest == [0; 32] {
                return Err(RepositoryError::InvalidCommand);
            }
            validate_effect(
                transaction,
                work_id,
                subject.kind(),
                effect_operation_id,
                effect_revision,
                effect_result_digest,
            )?;
            Ok((
                JOB_COMPLETE,
                context.occurred_at.get(),
                Some(context.occurred_at.get()),
                Some(effect_result_digest),
                effect_result_digest,
                None,
            ))
        }
        MaintenanceWorkCompletion::Retry {
            failure_digest: attempt_digest,
            retry_at,
        }
        | MaintenanceWorkCompletion::Continue {
            progress_digest: attempt_digest,
            retry_at,
        } => {
            if attempt_digest == [0; 32] || retry_at <= context.occurred_at {
                return Err(RepositoryError::InvalidCommand);
            }
            Ok((
                JOB_QUEUED,
                retry_at.get(),
                None,
                None,
                attempt_digest,
                Some(retry_at.get()),
            ))
        }
    }
}

fn validate_effect(
    transaction: &Transaction<'_>,
    work_id: WorkId,
    kind: WorkKind,
    operation_id: meshspan_domain::OperationId,
    revision: Revision,
    result_digest: [u8; 32],
) -> Result<(), RepositoryError> {
    let expected_kind = match kind {
        WorkKind::Repair => REPAIR_EFFECT_KIND,
        WorkKind::Scrub => SCRUB_EFFECT_KIND,
        WorkKind::Drain => DRAIN_EFFECT_KIND,
        WorkKind::Rebalance => REBALANCE_EFFECT_KIND,
        WorkKind::Reconcile => RECONCILE_EFFECT_KIND,
    };
    let stored = transaction
        .query_row(
            "SELECT operation_kind, revision, result_digest FROM operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?;
    let operation_matches = match stored {
        Some((stored_kind, stored_revision, stored_digest))
            if stored_kind == expected_kind
                && stored_revision == to_i64(revision.get())?
                && stored_digest.as_slice() == result_digest =>
        {
            true
        }
        Some(_) | None => false,
    };
    let effect_matches = match kind {
        WorkKind::Repair => {
            transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM maintenance_repair_effects
             WHERE effect_operation_id = ?1 AND work_id = ?2)",
                params![
                    operation_id.as_bytes().as_slice(),
                    work_id.as_bytes().as_slice(),
                ],
                |row| row.get::<_, i64>(0),
            )? == 1
        }
        WorkKind::Scrub => {
            transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM maintenance_scrub_effects
                 WHERE effect_operation_id = ?1 AND work_id = ?2)",
                params![
                    operation_id.as_bytes().as_slice(),
                    work_id.as_bytes().as_slice(),
                ],
                |row| row.get::<_, i64>(0),
            )? == 1
        }
        WorkKind::Drain | WorkKind::Rebalance | WorkKind::Reconcile => false,
    };
    if operation_matches && effect_matches {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_queue(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: QueueMaintenanceWork,
) -> Result<(), RepositoryError> {
    let encoded = value.subject.encode();
    if value.deduplication_key == [0; 32]
        || WorkSubject::decode(&encoded).ok() != Some(value.subject)
        || value.signals.created_at > context.occurred_at
        || value.demand.in_flight_bytes == 0
        || value.next_attempt_at < value.signals.created_at
        || value
            .signals
            .due_at
            .is_some_and(|due_at| due_at < value.signals.created_at)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_subject_reference(transaction, value.subject)
}

fn validate_subject_reference(
    transaction: &Transaction<'_>,
    subject: WorkSubject,
) -> Result<(), RepositoryError> {
    let valid = match subject {
        WorkSubject::Repair { volume_id, .. } | WorkSubject::Rebalance { volume_id, .. } => {
            entity_exists(
                transaction,
                "volumes",
                "volume_id",
                volume_id.as_bytes(),
                None,
            )?
        }
        WorkSubject::Scrub {
            target_id,
            target_generation,
        }
        | WorkSubject::Reconcile {
            target_id,
            target_generation,
        }
        | WorkSubject::Drain(meshspan_work::DrainScope::Target {
            target_id,
            target_generation,
        }) => current_generation(
            transaction,
            "storage_targets",
            "target_id",
            "current_generation",
            target_id.as_bytes(),
            target_generation,
        )?,
        WorkSubject::Drain(meshspan_work::DrainScope::Node {
            node_id,
            node_incarnation,
        }) => current_generation(
            transaction,
            "nodes",
            "node_id",
            "current_incarnation",
            node_id.as_bytes(),
            node_incarnation,
        )?,
        WorkSubject::Drain(meshspan_work::DrainScope::FaultGroup { fault_group_id }) => {
            entity_exists(
                transaction,
                "fault_groups",
                "group_id",
                fault_group_id.as_bytes(),
                Some("state = 1"),
            )?
        }
    };
    if valid {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn entity_exists(
    transaction: &Transaction<'_>,
    table: &str,
    identity_column: &str,
    identity: [u8; 16],
    condition: Option<&str>,
) -> Result<bool, RepositoryError> {
    let condition = condition.map_or_else(String::new, |value| format!(" AND {value}"));
    let query =
        format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {identity_column} = ?1{condition})");
    Ok(transaction.query_row(&query, [identity.as_slice()], |row| row.get::<_, i64>(0))? == 1)
}

fn current_generation(
    transaction: &Transaction<'_>,
    table: &str,
    identity_column: &str,
    generation_column: &str,
    identity: [u8; 16],
    generation: u64,
) -> Result<bool, RepositoryError> {
    if generation == 0 {
        return Ok(false);
    }
    let query = format!(
        "SELECT EXISTS(SELECT 1 FROM {table}
         WHERE {identity_column} = ?1 AND {generation_column} = ?2)"
    );
    Ok(transaction.query_row(
        &query,
        params![identity.as_slice(), to_i64(generation)?],
        |row| row.get::<_, i64>(0),
    )? == 1)
}

struct ExistingWork {
    work_id: WorkId,
    kind: i64,
    subject_payload: Vec<u8>,
    state: i64,
}

fn existing_deduplicated(
    transaction: &Transaction<'_>,
    deduplication_key: [u8; 32],
) -> Result<Option<ExistingWork>, RepositoryError> {
    transaction
        .query_row(
            "SELECT work_id, work_kind, subject_payload, state
             FROM maintenance_work_jobs WHERE deduplication_key = ?1",
            [deduplication_key.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .map(|(work_id, kind, subject_payload, state)| {
            Ok(ExistingWork {
                work_id: WorkId::from_bytes(exact(work_id)?)
                    .map_err(|_| RepositoryError::CorruptState)?,
                kind,
                subject_payload,
                state,
            })
        })
        .transpose()
}

fn merge_signals(
    transaction: &Transaction<'_>,
    work_id: WorkId,
    context: CommandContext,
    value: QueueMaintenanceWork,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let priority = value.signals.priority(context.occurred_at).get();
    let changed = transaction.execute(
        "UPDATE maintenance_work_jobs SET
            data_unavailable = MAX(data_unavailable, ?1),
            remaining_recovery_margin = MIN(remaining_recovery_margin, ?2),
            protection_debt = MAX(protection_debt, ?3),
            locality_debt = MAX(locality_debt, ?4),
            instability = MAX(instability, ?5), access_heat = MAX(access_heat, ?6),
            in_flight_bytes = COALESCE(MAX(in_flight_bytes, ?7), ?7),
            due_at = CASE
                WHEN due_at IS NULL THEN ?8
                WHEN ?8 IS NULL THEN due_at
                ELSE MIN(due_at, ?8)
            END,
            priority = MAX(priority, ?9), next_attempt_at = MIN(next_attempt_at, ?10),
            revision = ?11
         WHERE work_id = ?12 AND state <> ?13",
        params![
            i64::from(value.signals.data_unavailable),
            i64::from(value.signals.remaining_recovery_margin),
            i64::from(value.signals.protection_debt),
            i64::from(value.signals.locality_debt),
            i64::from(value.signals.instability),
            i64::from(value.signals.access_heat),
            to_i64(value.demand.in_flight_bytes)?,
            value.signals.due_at.map(UnixMicros::get),
            to_i64(priority)?,
            value.next_attempt_at.get(),
            to_i64(revision.get())?,
            work_id.as_bytes().as_slice(),
            JOB_COMPLETE,
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn validate_worker(
    transaction: &Transaction<'_>,
    node_id: NodeId,
    incarnation: u64,
) -> Result<(), RepositoryError> {
    if incarnation == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    let current: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM nodes
         WHERE node_id = ?1 AND current_incarnation = ?2 AND state = ?3 AND retired_at IS NULL)",
        params![
            node_id.as_bytes().as_slice(),
            to_i64(incarnation)?,
            ACTIVE_NODE,
        ],
        |row| row.get(0),
    )?;
    if current == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_lease(now: UnixMicros, expires_at: UnixMicros) -> Result<(), RepositoryError> {
    let duration = expires_at
        .get()
        .checked_sub(now.get())
        .ok_or(RepositoryError::InvalidCommand)?;
    if duration > 0 && duration <= MAXIMUM_LEASE_MICROS {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

struct TransitionJob {
    state: i64,
    next_attempt_at: i64,
    subject: WorkSubject,
}

fn load_job_for_transition(
    transaction: &Transaction<'_>,
    work_id: WorkId,
) -> Result<TransitionJob, RepositoryError> {
    let stored = transaction
        .query_row(
            "SELECT state, next_attempt_at, subject_payload
             FROM maintenance_work_jobs WHERE work_id = ?1",
            [work_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    Ok(TransitionJob {
        state: stored.0,
        next_attempt_at: stored.1,
        subject: WorkSubject::decode(&stored.2).map_err(|_| RepositoryError::CorruptState)?,
    })
}

#[derive(Clone, Copy)]
struct ActiveClaim {
    generation: u64,
    worker_node_id: NodeId,
    worker_incarnation: u64,
    fence: u64,
    lease_expires_at: i64,
}

fn active_claim(
    transaction: &Transaction<'_>,
    work_id: WorkId,
) -> Result<Option<ActiveClaim>, RepositoryError> {
    transaction
        .query_row(
            "SELECT claim_generation, worker_node_id, worker_incarnation, fence, lease_expires_at
             FROM maintenance_work_claims WHERE work_id = ?1 AND state = ?2",
            params![work_id.as_bytes().as_slice(), CLAIM_ACTIVE],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .map(decode_active_claim)
        .transpose()
}

fn decode_active_claim(
    value: (i64, Vec<u8>, i64, i64, i64),
) -> Result<ActiveClaim, RepositoryError> {
    Ok(ActiveClaim {
        generation: positive(value.0)?,
        worker_node_id: NodeId::from_bytes(exact(value.1)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        worker_incarnation: positive(value.2)?,
        fence: positive(value.3)?,
        lease_expires_at: value.4,
    })
}

fn require_live_claim(
    transaction: &Transaction<'_>,
    context: CommandContext,
    work_id: WorkId,
    generation: u64,
    worker_node_id: NodeId,
    worker_incarnation: u64,
    fence: u64,
) -> Result<ActiveClaim, RepositoryError> {
    let job = load_job_for_transition(transaction, work_id)?;
    let claim = active_claim(transaction, work_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if job.state != JOB_CLAIMED
        || claim.generation != generation
        || claim.worker_node_id != worker_node_id
        || claim.worker_incarnation != worker_incarnation
        || claim.fence != fence
        || claim.lease_expires_at <= context.occurred_at.get()
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(claim)
    }
}

fn latest_claim_generation(
    transaction: &Transaction<'_>,
    work_id: WorkId,
) -> Result<u64, RepositoryError> {
    let value = transaction.query_row(
        "SELECT COALESCE(MAX(claim_generation), 0)
         FROM maintenance_work_claims WHERE work_id = ?1",
        [work_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )?;
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn update_job_revision(
    transaction: &Transaction<'_>,
    work_id: WorkId,
    revision: Revision,
    preceding_change_count: usize,
) -> Result<(), RepositoryError> {
    if preceding_change_count != 1 {
        return Err(RepositoryError::CorruptState);
    }
    let changed = transaction.execute(
        "UPDATE maintenance_work_jobs SET revision = ?1 WHERE work_id = ?2 AND state = ?3",
        params![
            to_i64(revision.get())?,
            work_id.as_bytes().as_slice(),
            JOB_CLAIMED,
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn work_id_exists(transaction: &Transaction<'_>, work_id: WorkId) -> Result<bool, RepositoryError> {
    Ok(transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM maintenance_work_jobs WHERE work_id = ?1)",
        [work_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )? == 1)
}

fn load_record(
    connection: &rusqlite::Connection,
    work_id: WorkId,
) -> Result<Option<MaintenanceWorkRecord>, RepositoryError> {
    connection
        .query_row(
            "SELECT j.work_id, j.deduplication_key, j.work_kind, j.subject_payload,
                    j.data_unavailable, j.remaining_recovery_margin, j.protection_debt,
                    j.locality_debt, j.instability, j.access_heat, j.in_flight_bytes,
                    j.created_at, j.due_at, j.priority, j.state, j.next_attempt_at,
                    j.attempt_count, j.completed_at, j.result_digest, j.revision,
                    c.claim_generation, c.worker_node_id, c.worker_incarnation, c.fence,
                    c.claimed_at, c.lease_expires_at, c.revision
             FROM maintenance_work_jobs j
             LEFT JOIN maintenance_work_claims c ON c.work_id = j.work_id AND c.state = ?2
             WHERE j.work_id = ?1",
            params![work_id.as_bytes().as_slice(), CLAIM_ACTIVE],
            decode_record,
        )
        .optional()
        .map_err(RepositoryError::from)
}

fn decode_record(row: &Row<'_>) -> rusqlite::Result<MaintenanceWorkRecord> {
    decode_record_inner(row).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_record_inner(row: &Row<'_>) -> Result<MaintenanceWorkRecord, RepositoryError> {
    let work_id =
        WorkId::from_bytes(exact(row.get(0)?)?).map_err(|_| RepositoryError::CorruptState)?;
    let deduplication_key = exact(row.get(1)?)?;
    if deduplication_key == [0; 32] {
        return Err(RepositoryError::CorruptState);
    }
    let stored_kind = row.get::<_, i64>(2)?;
    let subject = WorkSubject::decode(&row.get::<_, Vec<u8>>(3)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    if stored_kind != kind_code(subject.kind()) {
        return Err(RepositoryError::CorruptState);
    }
    let signals = WorkSignals {
        data_unavailable: bool_value(row.get(4)?)?,
        remaining_recovery_margin: bounded_u16(row.get(5)?)?,
        protection_debt: bounded_u16(row.get(6)?)?,
        locality_debt: bounded_u16(row.get(7)?)?,
        instability: bounded_u16(row.get(8)?)?,
        access_heat: bounded_u16(row.get(9)?)?,
        created_at: UnixMicros::new(row.get(11)?),
        due_at: row.get::<_, Option<i64>>(12)?.map(UnixMicros::new),
    };
    let demand = WorkDemand {
        in_flight_bytes: positive(row.get(10)?)?,
    };
    let state = job_state(row.get(14)?)?;
    let completed_at = row.get::<_, Option<i64>>(17)?.map(UnixMicros::new);
    let result_digest = row.get::<_, Option<Vec<u8>>>(18)?.map(exact).transpose()?;
    if (state == MaintenanceWorkState::Complete)
        != (completed_at.is_some() && result_digest.is_some())
    {
        return Err(RepositoryError::CorruptState);
    }
    let claim = row
        .get::<_, Option<i64>>(20)?
        .map(|generation| {
            Ok::<_, RepositoryError>(MaintenanceWorkClaim {
                generation: positive(generation)?,
                worker_node_id: NodeId::from_bytes(exact(row.get(21)?)?)
                    .map_err(|_| RepositoryError::CorruptState)?,
                worker_incarnation: positive(row.get(22)?)?,
                fence: positive(row.get(23)?)?,
                claimed_at: UnixMicros::new(row.get(24)?),
                lease_expires_at: UnixMicros::new(row.get(25)?),
                revision: revision(row.get(26)?)?,
            })
        })
        .transpose()?;
    if (state == MaintenanceWorkState::Claimed) != claim.is_some() {
        return Err(RepositoryError::CorruptState);
    }
    Ok(MaintenanceWorkRecord {
        work_id,
        deduplication_key,
        subject,
        signals,
        demand,
        priority: positive(row.get(13)?)?,
        state,
        next_attempt_at: UnixMicros::new(row.get(15)?),
        attempt_count: nonnegative(row.get(16)?)?,
        completed_at,
        result_digest,
        revision: revision(row.get(19)?)?,
        claim,
    })
}

fn kind_code(kind: WorkKind) -> i64 {
    match kind {
        WorkKind::Repair => 1,
        WorkKind::Scrub => 2,
        WorkKind::Drain => 3,
        WorkKind::Rebalance => 4,
        WorkKind::Reconcile => 5,
    }
}

fn job_state(value: i64) -> Result<MaintenanceWorkState, RepositoryError> {
    match value {
        JOB_QUEUED => Ok(MaintenanceWorkState::Queued),
        JOB_CLAIMED => Ok(MaintenanceWorkState::Claimed),
        JOB_COMPLETE => Ok(MaintenanceWorkState::Complete),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn bool_value(value: i64) -> Result<bool, RepositoryError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn bounded_u16(value: i64) -> Result<u16, RepositoryError> {
    u16::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::CorruptState)
}

fn nonnegative(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn revision(value: i64) -> Result<Revision, RepositoryError> {
    positive(value).map(Revision::new)
}

fn exact<const LENGTH: usize>(value: Vec<u8>) -> Result<[u8; LENGTH], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn entity(work_id: WorkId) -> EntityReference {
    EntityReference {
        kind: EntityKind::MaintenanceWork,
        id: work_id.as_bytes(),
    }
}
