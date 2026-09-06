// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative manual DNS task transitions under an exact live certificate-order fence.

use meshspan_domain::{CertificateOrderId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Row, Transaction, params};

use super::{
    AuthoritativeRepository, EntityKind, EntityReference, Page, PageLimit, RepositoryError,
};
use crate::{AdvanceManualDnsTask, CommandContext, ManualDnsTaskPhase, PartitionDatabase};

mod handoff;

const ORDER_CLAIMED: i64 = 2;
const CLAIM_ACTIVE: i64 = 1;
const DNS_01: i64 = 2;
const TASK_SUPERSEDED: i64 = 5;

/// Durable lifecycle visible to authorised administrators.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualDnsTaskState {
    /// The exact TXT value must be published.
    AwaitingPublication,
    /// Authoritative DNS returned the exact value.
    PublicationObserved,
    /// The exact TXT value should be removed.
    AwaitingRemoval,
    /// Authoritative DNS proved the exact value absent.
    Complete,
    /// A newer fenced worker replaced this task.
    Superseded,
}

/// Exact authoritative projection of one manual DNS task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManualDnsTaskRecord {
    /// Deterministic task identity.
    pub task_digest: [u8; 32],
    /// Owning certificate order.
    pub order_id: CertificateOrderId,
    /// Exact worker fence which created the task.
    pub fence: u64,
    /// Canonical TXT owner name.
    pub record_name: String,
    /// Exact unquoted TXT value.
    pub record_value: Vec<u8>,
    /// Authoritative challenge deadline.
    pub expires_at: UnixMicros,
    /// Current durable state.
    pub state: ManualDnsTaskState,
    /// Original creation instant.
    pub created_at: UnixMicros,
    /// Most recent transition instant.
    pub transitioned_at: UnixMicros,
    /// Most recent authoritative revision.
    pub revision: Revision,
}

/// Stable seek cursor for the operator-action queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManualDnsTaskCursor {
    expires_at: UnixMicros,
    created_at: UnixMicros,
    task_digest: [u8; 32],
}

impl ManualDnsTaskCursor {
    /// Reconstructs a cursor after a public boundary validates its fields.
    #[must_use]
    pub const fn new(
        expires_at: UnixMicros,
        created_at: UnixMicros,
        task_digest: [u8; 32],
    ) -> Self {
        Self {
            expires_at,
            created_at,
            task_digest,
        }
    }

    /// Returns the expiry portion of the stable seek key.
    #[must_use]
    pub const fn expires_at(self) -> UnixMicros {
        self.expires_at
    }

    /// Returns the creation-time portion of the stable seek key.
    #[must_use]
    pub const fn created_at(self) -> UnixMicros {
        self.created_at
    }

    /// Returns the task identity portion of the stable seek key.
    #[must_use]
    pub const fn task_digest(self) -> [u8; 32] {
        self.task_digest
    }
}

pub(super) fn advance(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &AdvanceManualDnsTask,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_live_manual_claim(transaction, context.occurred_at, value)?;
    let retained = handoff::retained_publication_epoch(transaction, value)?;
    let existing = load_existing(transaction, value, retained.is_some())?;
    match existing {
        None => create(transaction, context, value, revision)?,
        Some(phase) => advance_existing(transaction, context, value, phase, revision)?,
    }
    transaction.execute(
        "UPDATE certificate_orders SET revision = ?1 WHERE order_id = ?2",
        params![
            to_i64(revision.get())?,
            value.order_id.as_bytes().as_slice()
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::CertificateOrder,
        id: value.order_id.as_bytes(),
    })
}

fn validate_live_manual_claim(
    transaction: &Transaction<'_>,
    now: UnixMicros,
    value: &AdvanceManualDnsTask,
) -> Result<(), RepositoryError> {
    validate_task_shape(now, value)?;
    let valid: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM certificate_orders o
            JOIN certificate_order_claims c ON c.order_id = o.order_id
            JOIN acme_configurations a ON a.config_id = o.config_id
            WHERE o.order_id = ?1 AND o.state = ?2
              AND c.claim_generation = ?3 AND c.worker_node_id = ?4
              AND c.worker_incarnation = ?5 AND c.fence = ?6 AND c.state = ?7
              AND c.lease_expires_at > ?8 AND a.challenge_kind = ?9
              AND a.challenge_settings_secret_id IS NULL
        )",
        params![
            value.order_id.as_bytes().as_slice(),
            ORDER_CLAIMED,
            to_i64(value.claim_generation)?,
            value.worker_node_id.as_bytes().as_slice(),
            to_i64(value.worker_incarnation)?,
            to_i64(value.fence)?,
            CLAIM_ACTIVE,
            now.get(),
            DNS_01,
        ],
        |row| row.get(0),
    )?;
    if valid != 1
        || matches!(
            value.phase,
            ManualDnsTaskPhase::AwaitingPublication | ManualDnsTaskPhase::PublicationObserved
        ) && value.expires_at <= now
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn validate_task_shape(
    now: UnixMicros,
    value: &AdvanceManualDnsTask,
) -> Result<(), RepositoryError> {
    if now.get() < 0
        || value.task_digest == [0; 32]
        || value.fence == 0
        || value.claim_generation == 0
        || value.worker_incarnation == 0
        || value.expires_at.get() <= 0
        || value.record_value.len() > crate::MAXIMUM_MANUAL_DNS_VALUE_BYTES
        || meshspan_acme::Dns01Payload::new(&value.record_name, &value.record_value).is_err()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn load_existing(
    transaction: &Transaction<'_>,
    value: &AdvanceManualDnsTask,
    retained_publication: bool,
) -> Result<Option<i64>, RepositoryError> {
    transaction
        .query_row(
            "SELECT t.phase, t.revision, t.created_at, t.transitioned_at FROM manual_dns_tasks t
             JOIN certificate_order_claims c ON c.order_id = t.order_id
               AND c.claim_generation = t.claim_generation AND c.worker_node_id = t.worker_node_id
               AND c.worker_incarnation = t.worker_incarnation AND c.fence = t.fence
             WHERE t.task_digest = ?1 AND t.order_id = ?2
               AND ((t.claim_generation = ?3 AND t.worker_node_id = ?4
                     AND t.worker_incarnation = ?5 AND t.fence = ?6) OR ?10)
               AND t.record_name = ?7 AND t.record_value = ?8 AND t.expires_at = ?9",
            params![
                value.task_digest.as_slice(),
                value.order_id.as_bytes().as_slice(),
                to_i64(value.claim_generation)?,
                value.worker_node_id.as_bytes().as_slice(),
                to_i64(value.worker_incarnation)?,
                to_i64(value.fence)?,
                value.record_name,
                value.record_value,
                value.expires_at.get(),
                retained_publication,
            ],
            |row| {
                let phase: i64 = row.get(0)?;
                let revision: i64 = row.get(1)?;
                let created_at: i64 = row.get(2)?;
                let transitioned_at: i64 = row.get(3)?;
                parse_state(phase)?;
                if revision <= 0 || created_at < 0 || transitioned_at < created_at {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok(phase)
            },
        )
        .optional()
        .map_err(RepositoryError::from)
}

fn create(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &AdvanceManualDnsTask,
    revision: Revision,
) -> Result<(), RepositoryError> {
    if value.phase != ManualDnsTaskPhase::AwaitingPublication {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "UPDATE manual_dns_tasks SET phase = ?1, transitioned_at = ?2, revision = ?3
         WHERE order_id = ?4 AND phase IN (1, 2, 3) AND fence <> ?5",
        params![
            TASK_SUPERSEDED,
            context.occurred_at.get(),
            to_i64(revision.get())?,
            value.order_id.as_bytes().as_slice(),
            to_i64(value.fence)?,
        ],
    )?;
    transaction.execute(
        "INSERT INTO manual_dns_tasks(
            task_digest, order_id, claim_generation, worker_node_id, worker_incarnation, fence,
            record_name, record_value, expires_at, phase, created_at, transitioned_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10, ?10, ?11)",
        params![
            value.task_digest.as_slice(),
            value.order_id.as_bytes().as_slice(),
            to_i64(value.claim_generation)?,
            value.worker_node_id.as_bytes().as_slice(),
            to_i64(value.worker_incarnation)?,
            to_i64(value.fence)?,
            value.record_name,
            value.record_value,
            value.expires_at.get(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn advance_existing(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &AdvanceManualDnsTask,
    current: i64,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let requested = phase_code(value.phase);
    if current == TASK_SUPERSEDED || !(1..=4).contains(&current) {
        return Err(RepositoryError::InvalidCommand);
    }
    if requested <= current {
        return Ok(());
    }
    if !matches!((current, requested), (1, 2) | (2, 3 | 4) | (3, 4)) {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "UPDATE manual_dns_tasks SET phase = ?1, transitioned_at = ?2, revision = ?3
         WHERE task_digest = ?4 AND phase = ?5",
        params![
            requested,
            context.occurred_at.get(),
            to_i64(revision.get())?,
            value.task_digest.as_slice(),
            current,
        ],
    )?;
    Ok(())
}

const fn phase_code(value: ManualDnsTaskPhase) -> i64 {
    match value {
        ManualDnsTaskPhase::AwaitingPublication => 1,
        ManualDnsTaskPhase::PublicationObserved => 2,
        ManualDnsTaskPhase::AwaitingRemoval => 3,
        ManualDnsTaskPhase::Complete => 4,
    }
}

fn to_i64(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::CapacityExceeded)
}

impl AuthoritativeRepository {
    /// Reports whether an exact, still-live manual task already reached a phase.
    ///
    /// The publication epoch identifies the original challenge, independently of `value.fence`.
    /// Claim, checkpoint and task reads share one SQLite read snapshot. This performs no mutation,
    /// advances no revision and cannot renew a claim. A later write still needs its
    /// normal authoritative checks; this observation does not reserve authority.
    ///
    /// # Errors
    ///
    /// Rejects malformed requests, expired/replaced claims, substituted task identity,
    /// superseded tasks and corrupt retained state.
    pub fn manual_dns_task_transition_satisfied(
        &self,
        now: UnixMicros,
        value: &AdvanceManualDnsTask,
        publication_epoch: u64,
    ) -> Result<bool, RepositoryError> {
        let read_view = self.database.connection().unchecked_transaction()?;
        validate_live_manual_claim(&read_view, now, value)?;
        let retained = handoff::retained_publication_epoch(&read_view, value)?;
        if publication_epoch != retained.unwrap_or(value.fence) {
            return Err(RepositoryError::InvalidCommand);
        }
        let satisfied = match load_existing(&read_view, value, retained.is_some())? {
            Some(TASK_SUPERSEDED) => return Err(RepositoryError::InvalidCommand),
            Some(phase) => phase >= phase_code(value.phase),
            None => {
                if self.manual_dns_task(value.task_digest)?.is_some() {
                    return Err(RepositoryError::InvalidCommand);
                }
                false
            }
        };
        read_view.commit()?;
        Ok(satisfied)
    }

    /// Returns one exact manual DNS task.
    ///
    /// # Errors
    ///
    /// Fails closed when any persisted identity, phase, time or revision is malformed.
    pub fn manual_dns_task(
        &self,
        task_digest: [u8; 32],
    ) -> Result<Option<ManualDnsTaskRecord>, RepositoryError> {
        self.database
            .connection()
            .query_row(
                "SELECT task_digest, order_id, fence, record_name, record_value, expires_at,
                        phase, created_at, transitioned_at, revision
                 FROM manual_dns_tasks WHERE task_digest = ?1",
                [task_digest.as_slice()],
                decode_record,
            )
            .optional()
            .map_err(RepositoryError::from)
    }

    /// Returns the earliest-deadline page requiring operator publication or removal.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits and fails closed for malformed durable tasks.
    pub fn actionable_manual_dns_tasks(
        &self,
        after: Option<ManualDnsTaskCursor>,
        limit: PageLimit,
    ) -> Result<Page<ManualDnsTaskRecord, ManualDnsTaskCursor>, RepositoryError> {
        actionable_tasks(&self.database, after, limit)
    }
}

fn actionable_tasks(
    database: &PartitionDatabase,
    after: Option<ManualDnsTaskCursor>,
    limit: PageLimit,
) -> Result<Page<ManualDnsTaskRecord, ManualDnsTaskCursor>, RepositoryError> {
    let lower_expiry = after.map_or(i64::MIN, |cursor| cursor.expires_at.get());
    let lower_created = after.map_or(i64::MIN, |cursor| cursor.created_at.get());
    let lower_digest = after.map_or([0; 32], |cursor| cursor.task_digest);
    let sql_limit = i64::try_from(limit.get().saturating_add(1))
        .map_err(|_| RepositoryError::InvalidPageLimit)?;
    let mut statement = database.connection().prepare(
        "SELECT task_digest, order_id, fence, record_name, record_value, expires_at,
                phase, created_at, transitioned_at, revision
         FROM manual_dns_tasks
         WHERE phase IN (1, 3)
           AND (expires_at, created_at, task_digest) > (?1, ?2, ?3)
         ORDER BY expires_at, created_at, task_digest LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            lower_expiry,
            lower_created,
            lower_digest.as_slice(),
            sql_limit
        ],
        decode_record,
    )?;
    let mut records = rows.collect::<Result<Vec<_>, _>>()?;
    let next = if records.len() > limit.get() {
        records.truncate(limit.get());
        records.last().map(|record| {
            ManualDnsTaskCursor::new(record.expires_at, record.created_at, record.task_digest)
        })
    } else {
        None
    };
    Ok(Page {
        items: records,
        next,
    })
}

fn decode_record(row: &Row<'_>) -> rusqlite::Result<ManualDnsTaskRecord> {
    let task_digest = row.get::<_, Vec<u8>>(0)?;
    let order_id = row.get::<_, Vec<u8>>(1)?;
    let fence = row.get::<_, i64>(2)?;
    let record_name = row.get::<_, String>(3)?;
    let record_value = row.get::<_, Vec<u8>>(4)?;
    let expires_at = row.get::<_, i64>(5)?;
    let phase = row.get::<_, i64>(6)?;
    let created_at = row.get::<_, i64>(7)?;
    let transitioned_at = row.get::<_, i64>(8)?;
    let revision = row.get::<_, i64>(9)?;
    if fence <= 0
        || expires_at <= 0
        || transitioned_at < created_at
        || revision <= 0
        || meshspan_acme::Dns01Payload::new(&record_name, &record_value).is_err()
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(ManualDnsTaskRecord {
        task_digest: exact(task_digest)?,
        order_id: CertificateOrderId::from_bytes(exact(order_id)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        fence: u64::try_from(fence).map_err(|_| rusqlite::Error::InvalidQuery)?,
        record_name,
        record_value,
        expires_at: UnixMicros::new(expires_at),
        state: parse_state(phase)?,
        created_at: UnixMicros::new(created_at),
        transitioned_at: UnixMicros::new(transitioned_at),
        revision: Revision::new(
            u64::try_from(revision).map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
    })
}

fn parse_state(value: i64) -> rusqlite::Result<ManualDnsTaskState> {
    match value {
        1 => Ok(ManualDnsTaskState::AwaitingPublication),
        2 => Ok(ManualDnsTaskState::PublicationObserved),
        3 => Ok(ManualDnsTaskState::AwaitingRemoval),
        4 => Ok(ManualDnsTaskState::Complete),
        5 => Ok(ManualDnsTaskState::Superseded),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn exact<const LENGTH: usize>(bytes: Vec<u8>) -> rusqlite::Result<[u8; LENGTH]> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
