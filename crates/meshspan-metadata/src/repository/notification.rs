// SPDX-License-Identifier: GPL-2.0-only

//! Immutable channel configuration and projection from committed, allow-listed event kinds.

use meshspan_domain::{AuditEventId, ComponentInstanceId, PrincipalId, Revision, WorkId, uuid_v8};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::{AuthoritativeRepository, EntityKind, EntityReference, RepositoryError, apply::to_i64};
use crate::{
    CommandContext, ConfigureNotificationChannel, NotificationChannelKind, NotificationEventKind,
    QueueNotification, RecordName, SecretGenerationReference,
};

/// Current validated channel configuration; it never contains plaintext destination credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotificationChannelRecord {
    /// Exact channel identity.
    pub channel_id: ComponentInstanceId,
    /// Immutable configuration sequence.
    pub sequence: u64,
    /// Non-secret administrative label.
    pub display_name: RecordName,
    /// Selected userspace transport.
    pub kind: NotificationChannelKind,
    /// Encrypted kind-10 settings generation.
    pub settings: SecretGenerationReference,
    /// Explicit administrator opt-in.
    pub enabled: bool,
    /// Allowed closed event kinds.
    pub event_filter: u8,
    /// Principal responsible for this configuration.
    pub configured_by: PrincipalId,
    /// Creation boundary; new channels do not replay historic audit entries.
    pub created_revision: Revision,
    /// Revision of the current configuration.
    pub revision: Revision,
}

impl AuthoritativeRepository {
    /// Reads one current notification channel, without decrypting its settings.
    ///
    /// # Errors
    /// Rejects malformed stored configuration or unavailable persistence.
    pub fn notification_channel(
        &self,
        id: ComponentInstanceId,
    ) -> Result<Option<NotificationChannelRecord>, RepositoryError> {
        load(self.database.connection(), id)
    }
}

/// Stable delivery identity shared by every retry and worker for one channel/event pair.
///
/// # Errors
/// Rejects an invalid derived identity.
pub fn notification_delivery_id(
    channel: ComponentInstanceId,
    event: AuditEventId,
) -> Result<WorkId, meshspan_domain::IdentifierError> {
    let mut hash = Sha256::new();
    hash.update(b"meshspan.notification.delivery.v1\0");
    hash.update(channel.as_bytes());
    hash.update(event.as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash.finalize()[..16]);
    WorkId::from_bytes(uuid_v8(bytes))
}

pub(super) fn configure(
    tx: &Transaction<'_>,
    context: CommandContext,
    value: &ConfigureNotificationChannel,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if !(1..=15).contains(&value.event_filter)
        || value.settings.generation == 0
        || value.settings.secret_id == [0; 16]
        || context.occurred_at.get() < 0
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let current = load(tx, value.channel_id)?;
    if current.as_ref().map_or(0, |record| record.sequence) != value.expected_sequence {
        return Err(RepositoryError::StaleRevision);
    }
    let sequence = to_i64(
        value
            .expected_sequence
            .checked_add(1)
            .ok_or(RepositoryError::CapacityExceeded)?,
    )?;
    let channel = value.channel_id.as_bytes();
    let revision = to_i64(revision.get())?;
    if current.is_none() {
        let channels: i64 =
            tx.query_row("SELECT count(*) FROM notification_channels", [], |row| {
                row.get(0)
            })?;
        if channels >= 64 {
            return Err(RepositoryError::CapacityExceeded);
        }
        tx.execute(
            "INSERT INTO notification_channels VALUES (?1, 1, ?2, ?2)",
            params![channel.as_slice(), revision],
        )?;
    }
    tx.execute(
        "INSERT INTO notification_channel_configurations(
        channel_id, sequence, display_name, channel_kind, settings_id, settings_generation,
        enabled, event_filter, configured_by, revision)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            channel.as_slice(),
            sequence,
            value.display_name.display(),
            value.kind as u8,
            value.settings.secret_id.as_slice(),
            to_i64(value.settings.generation)?,
            value.enabled,
            value.event_filter,
            context.actor_principal_id.as_bytes().as_slice(),
            revision
        ],
    )?;
    tx.execute(
        "UPDATE notification_channels SET active_sequence = ?2, revision = ?3
        WHERE channel_id = ?1",
        params![channel.as_slice(), sequence, revision],
    )?;
    // Existing in-flight network IO cannot be undone. Fence its receipt and do not silently send
    // old events to new destinations or with newly broadened credentials.
    tx.execute(
        "UPDATE notification_deliveries SET state = 5, worker_node_id = NULL,
        worker_incarnation = NULL, claim_expires_at = NULL, revision = ?2
        WHERE channel_id = ?1 AND state IN (1, 2)",
        params![channel.as_slice(), revision],
    )?;
    Ok(EntityReference {
        kind: EntityKind::NotificationChannel,
        id: channel,
    })
}

pub(super) fn queue(
    tx: &Transaction<'_>,
    context: CommandContext,
    value: QueueNotification,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let channel = load(tx, value.channel_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if !channel.enabled
        || channel.sequence != value.channel_sequence
        || context.occurred_at.get() < 0
    {
        return Err(RepositoryError::StaleRevision);
    }
    let (kind, occurred_at, source_revision): (i64, i64, i64) = tx
        .query_row(
            "SELECT a.event_kind, a.occurred_at, o.revision FROM audit_events a
        JOIN operations o USING(operation_id) WHERE a.event_id = ?1
        AND o.committed_log_index IS NOT NULL AND o.completed_at IS NOT NULL",
            [value.event_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    let kind =
        NotificationEventKind::from_audit_kind(kind).ok_or(RepositoryError::InvalidCommand)?;
    if channel.event_filter & kind.filter_bit() == 0
        || occurred_at < 0
        || source_revision < to_i64(channel.created_revision.get())?
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let id = notification_delivery_id(value.channel_id, value.event_id)
        .map_err(|_| RepositoryError::InvalidCommand)?
        .as_bytes();
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM notification_deliveries
        WHERE delivery_id = ?1)",
        [id.as_slice()],
        |row| row.get(0),
    )?;
    if !exists {
        let pending: i64 = tx.query_row(
            "SELECT count(*) FROM (SELECT 1 FROM notification_deliveries
            WHERE channel_id = ?1 AND state IN (1, 2) LIMIT 10000)",
            [value.channel_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if pending >= 10_000 {
            return Err(RepositoryError::CapacityExceeded);
        }
        tx.execute(
            "INSERT INTO notification_deliveries(delivery_id, channel_id, channel_sequence,
            event_id, event_kind, occurred_at, state, next_attempt_at, revision)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8)",
            params![
                id.as_slice(),
                value.channel_id.as_bytes().as_slice(),
                to_i64(channel.sequence)?,
                value.event_id.as_bytes().as_slice(),
                kind as u8,
                occurred_at,
                context.occurred_at.get(),
                to_i64(revision.get())?
            ],
        )?;
    }
    Ok(EntityReference {
        kind: EntityKind::NotificationDelivery,
        id,
    })
}

pub(super) fn load(
    connection: &Connection,
    id: ComponentInstanceId,
) -> Result<Option<NotificationChannelRecord>, RepositoryError> {
    let stored = connection
        .query_row(
            "SELECT c.sequence, substr(c.display_name, 1, 257),
        c.channel_kind, c.settings_id, c.settings_generation, c.enabled, c.event_filter,
        c.configured_by, h.created_revision, c.revision FROM notification_channels h
        JOIN notification_channel_configurations c ON c.channel_id = h.channel_id
        AND c.sequence = h.active_sequence WHERE h.channel_id = ?1",
            [id.as_bytes().as_slice()],
            |row| {
                Ok(NotificationChannelRecord {
                    channel_id: id,
                    sequence: unsigned(row, 0)?,
                    display_name: RecordName::new(&row.get::<_, String>(1)?)
                        .map_err(corrupt_row)?,
                    kind: match row.get::<_, u8>(2)? {
                        1 => NotificationChannelKind::Webhook,
                        2 => NotificationChannelKind::Email,
                        _ => return Err(corrupt_row("unknown notification adapter")),
                    },
                    settings: SecretGenerationReference {
                        secret_id: row.get(3)?,
                        generation: unsigned(row, 4)?,
                    },
                    enabled: row.get(5)?,
                    event_filter: row.get(6)?,
                    configured_by: PrincipalId::from_bytes(row.get(7)?).map_err(corrupt_row)?,
                    created_revision: Revision::new(unsigned(row, 8)?),
                    revision: Revision::new(unsigned(row, 9)?),
                })
            },
        )
        .optional()?;
    if stored.as_ref().is_some_and(|record| {
        record.sequence == 0
            || record.settings.generation == 0
            || !(1..=15).contains(&record.event_filter)
            || record.created_revision == Revision::ZERO
            || record.revision < record.created_revision
    }) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(stored)
}

fn corrupt_row(error: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(error.to_string())))
}

pub(super) fn unsigned(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(row.get::<_, i64>(column)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}
