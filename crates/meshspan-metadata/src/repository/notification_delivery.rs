// SPDX-License-Identifier: GPL-2.0-only

//! Finite delivery claims and restart-safe retry scheduling, independent of storage maintenance.

use meshspan_domain::{AuditEventId, ComponentInstanceId, NodeId, Revision, UnixMicros, WorkId};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{AuthoritativeRepository, EntityKind, EntityReference, RepositoryError, apply::to_i64};
use crate::{
    ClaimNotification, CommandContext, CompleteNotification, NotificationDeliveryOutcome,
    NotificationEventKind,
};

/// Durable notification lifecycle. Terminal rows retain deduplication evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NotificationDeliveryState {
    /// Waiting for its next eligible attempt.
    Queued = 1,
    /// One worker owns a finite attempt.
    Claimed = 2,
    /// External endpoint accepted the notification.
    Accepted = 3,
    /// Permanent rejection needs an administrator to correct the channel.
    Rejected = 4,
    /// Configuration changed or was disabled before completion.
    Cancelled = 5,
}

/// Redacted outbox projection; no remote destination, credentials or source payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationDeliveryRecord {
    /// Stable external idempotency identity.
    pub delivery_id: WorkId,
    /// Owning channel.
    pub channel_id: ComponentInstanceId,
    /// Configuration under which this event was queued.
    pub channel_sequence: u64,
    /// Source committed event identity.
    pub event_id: AuditEventId,
    /// Closed event code; clients inspect authoritative state for details.
    pub event_kind: NotificationEventKind,
    /// Source event instant.
    pub occurred_at: UnixMicros,
    /// Number of claimed attempts, never reset across restarts.
    pub attempt: u64,
    /// Current durable lifecycle state.
    pub state: NotificationDeliveryState,
    /// Earliest retry; for claimed rows this is the lease expiry.
    pub next_attempt_at: UnixMicros,
    /// Node, incarnation and expiration present only while claimed.
    pub claim: Option<(NodeId, u64, UnixMicros)>,
    /// Revision of the latest transition.
    pub revision: Revision,
}

impl AuthoritativeRepository {
    /// Reads one durable delivery without external IO or secret access.
    ///
    /// # Errors
    /// Rejects corrupt lifecycle fields and database errors.
    pub fn notification_delivery(
        &self,
        id: WorkId,
    ) -> Result<Option<NotificationDeliveryRecord>, RepositoryError> {
        load(self.database.connection(), id)
    }
}

pub(super) fn claim(
    tx: &Transaction<'_>,
    context: CommandContext,
    value: ClaimNotification,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let current = load(tx, value.delivery_id)?.ok_or(RepositoryError::InvalidCommand)?;
    check_current_channel(tx, &current)?;
    check_worker(tx, value.worker_node_id, value.worker_incarnation)?;
    if current.attempt != value.expected_attempt
        || current.next_attempt_at > context.occurred_at
        || !matches!(
            current.state,
            NotificationDeliveryState::Queued | NotificationDeliveryState::Claimed
        )
        || context.occurred_at.get() < 0
    {
        return Err(RepositoryError::StaleRevision);
    }
    let attempt = to_i64(
        current
            .attempt
            .checked_add(1)
            .ok_or(RepositoryError::CapacityExceeded)?,
    )?;
    let expires = context
        .occurred_at
        .get()
        .checked_add(60_000_000)
        .ok_or(RepositoryError::CapacityExceeded)?;
    let id = value.delivery_id.as_bytes();
    tx.execute(
        "UPDATE notification_deliveries SET state = 2, attempt = ?2,
        worker_node_id = ?3, worker_incarnation = ?4, claim_expires_at = ?5,
        next_attempt_at = ?5, revision = ?6 WHERE delivery_id = ?1",
        params![
            id.as_slice(),
            attempt,
            value.worker_node_id.as_bytes().as_slice(),
            to_i64(value.worker_incarnation)?,
            expires,
            to_i64(revision.get())?
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::NotificationDelivery,
        id,
    })
}

pub(super) fn complete(
    tx: &Transaction<'_>,
    context: CommandContext,
    value: CompleteNotification,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let current = load(tx, value.delivery_id)?.ok_or(RepositoryError::InvalidCommand)?;
    check_current_channel(tx, &current)?;
    check_worker(tx, value.worker_node_id, value.worker_incarnation)?;
    let Some((node, incarnation, expires)) = current.claim else {
        return Err(RepositoryError::StaleRevision);
    };
    if node != value.worker_node_id
        || incarnation != value.worker_incarnation
        || current.attempt != value.attempt
        || context.occurred_at >= expires
        || context.occurred_at.get() < expires.get() - 60_000_000
    {
        return Err(RepositoryError::StaleRevision);
    }
    let (state, next, delivered) = match value.outcome {
        NotificationDeliveryOutcome::Accepted => (
            3,
            context.occurred_at.get(),
            Some(context.occurred_at.get()),
        ),
        NotificationDeliveryOutcome::Rejected => (4, context.occurred_at.get(), None),
        NotificationDeliveryOutcome::Retry => {
            // 5, 10, 20, ... seconds, capped at one hour. Stable identity jitter prevents every
            // channel from retrying at the same instant; no wall-clock-derived random state.
            let exponent = u32::try_from(value.attempt.saturating_sub(1).min(10))
                .map_err(|_| RepositoryError::CapacityExceeded)?;
            let delay = (5_i64 << exponent).min(3600) * 1_000_000;
            let jitter = i64::from(value.delivery_id.as_bytes()[0]) * 1000;
            let next = context
                .occurred_at
                .get()
                .checked_add(delay + jitter)
                .ok_or(RepositoryError::CapacityExceeded)?;
            (1, next, None)
        }
    };
    let id = value.delivery_id.as_bytes();
    tx.execute(
        "UPDATE notification_deliveries SET state = ?2, next_attempt_at = ?3,
        delivered_at = ?4, worker_node_id = NULL, worker_incarnation = NULL,
        claim_expires_at = NULL, revision = ?5 WHERE delivery_id = ?1",
        params![
            id.as_slice(),
            state,
            next,
            delivered,
            to_i64(revision.get())?
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::NotificationDelivery,
        id,
    })
}

fn check_current_channel(
    tx: &Transaction<'_>,
    current: &NotificationDeliveryRecord,
) -> Result<(), RepositoryError> {
    let channel =
        super::notification::load(tx, current.channel_id)?.ok_or(RepositoryError::CorruptState)?;
    if !channel.enabled || channel.sequence != current.channel_sequence {
        return Err(RepositoryError::StaleRevision);
    }
    Ok(())
}

fn check_worker(
    tx: &Transaction<'_>,
    node: NodeId,
    incarnation: u64,
) -> Result<(), RepositoryError> {
    let valid: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM nodes WHERE node_id = ?1
        AND current_incarnation = ?2 AND state = 2 AND retired_at IS NULL)",
        params![node.as_bytes().as_slice(), to_i64(incarnation)?],
        |row| row.get(0),
    )?;
    if !valid {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

pub(super) fn load(
    connection: &Connection,
    id: WorkId,
) -> Result<Option<NotificationDeliveryRecord>, RepositoryError> {
    let raw = connection
        .query_row(
            "SELECT channel_id, channel_sequence, event_id, event_kind,
        occurred_at, attempt, state, next_attempt_at, worker_node_id, worker_incarnation,
        claim_expires_at, revision FROM notification_deliveries WHERE delivery_id = ?1",
            [id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, [u8; 16]>(0)?,
                    super::notification::unsigned(row, 1)?,
                    row.get::<_, [u8; 16]>(2)?,
                    row.get::<_, u8>(3)?,
                    row.get::<_, i64>(4)?,
                    super::notification::unsigned(row, 5)?,
                    row.get::<_, u8>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<[u8; 16]>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    super::notification::unsigned(row, 11)?,
                ))
            },
        )
        .optional()?;
    let Some((
        channel,
        sequence,
        event,
        kind,
        occurred,
        attempt,
        state,
        next,
        node,
        incarnation,
        expires,
        revision,
    )) = raw
    else {
        return Ok(None);
    };
    let corrupt = || RepositoryError::CorruptState;
    let state = match state {
        1 => NotificationDeliveryState::Queued,
        2 => NotificationDeliveryState::Claimed,
        3 => NotificationDeliveryState::Accepted,
        4 => NotificationDeliveryState::Rejected,
        5 => NotificationDeliveryState::Cancelled,
        _ => return Err(corrupt()),
    };
    let event_kind = match kind {
        1 => NotificationEventKind::CertificateOrderQueued,
        2 => NotificationEventKind::CertificateOrderCompleted,
        3 => NotificationEventKind::ManualDnsTaskChanged,
        4 => NotificationEventKind::BackupRunCompleted,
        _ => return Err(corrupt()),
    };
    let claim = match (node, incarnation, expires) {
        (Some(node), Some(incarnation), Some(expires))
            if state == NotificationDeliveryState::Claimed
                && incarnation > 0
                && attempt > 0
                && expires == next =>
        {
            Some((
                NodeId::from_bytes(node).map_err(|_| corrupt())?,
                u64::try_from(incarnation).map_err(|_| corrupt())?,
                UnixMicros::new(expires),
            ))
        }
        (None, None, None) if state != NotificationDeliveryState::Claimed => None,
        _ => return Err(corrupt()),
    };
    if sequence == 0 || revision == 0 || occurred < 0 || next < 0 {
        return Err(corrupt());
    }
    Ok(Some(NotificationDeliveryRecord {
        delivery_id: id,
        channel_id: ComponentInstanceId::from_bytes(channel).map_err(|_| corrupt())?,
        channel_sequence: sequence,
        event_id: AuditEventId::from_bytes(event).map_err(|_| corrupt())?,
        event_kind,
        occurred_at: UnixMicros::new(occurred),
        attempt,
        state,
        next_attempt_at: UnixMicros::new(next),
        claim,
        revision: Revision::new(revision),
    }))
}
