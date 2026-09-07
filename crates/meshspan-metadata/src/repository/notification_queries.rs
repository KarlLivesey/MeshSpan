// SPDX-License-Identifier: GPL-2.0-only

//! Bounded scheduling projections over the authoritative outbox, never network delivery.

use meshspan_domain::{AuditEventId, ComponentInstanceId, UnixMicros, WorkId};
use rusqlite::params;

use super::{
    AuthoritativeRepository, NotificationChannelRecord, NotificationDeliveryRecord, PageLimit,
    RepositoryError, notification, notification_delivery,
};

impl AuthoritativeRepository {
    /// Lists the explicitly bounded channel inventory in stable identity order.
    ///
    /// # Errors
    /// Rejects excess channels, malformed heads or unavailable persistence.
    pub fn notification_channels(&self) -> Result<Vec<NotificationChannelRecord>, RepositoryError> {
        let connection = self.database.connection();
        let mut statement = connection.prepare(
            "SELECT channel_id FROM notification_channels
            ORDER BY channel_id LIMIT 65",
        )?;
        let ids = statement
            .query_map([], |row| row.get::<_, [u8; 16]>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if ids.len() > 64 {
            return Err(RepositoryError::CorruptState);
        }
        ids.into_iter()
            .map(|id| {
                let id = ComponentInstanceId::from_bytes(id)
                    .map_err(|_| RepositoryError::CorruptState)?;
                notification::load(connection, id)?.ok_or(RepositoryError::CorruptState)
            })
            .collect()
    }

    /// Finds committed, selected events which have not yet entered this channel's outbox.
    ///
    /// Returns at most the requested page. Repeated calls after enqueue advance naturally;
    /// a failed enqueue leaves its source discoverable rather than losing a cursor update.
    ///
    /// # Errors
    /// Rejects absent/disabled channels, corrupt source identities and database errors.
    pub fn pending_notification_events(
        &self,
        channel_id: ComponentInstanceId,
        limit: PageLimit,
    ) -> Result<Vec<AuditEventId>, RepositoryError> {
        let connection = self.database.connection();
        let channel =
            notification::load(connection, channel_id)?.ok_or(RepositoryError::InvalidCommand)?;
        if !channel.enabled {
            return Err(RepositoryError::InvalidCommand);
        }
        let mut statement = connection.prepare(
            "SELECT a.event_id FROM audit_events a
            JOIN operations o USING(operation_id) WHERE a.event_kind IN (115, 118, 121, 136)
            AND o.committed_log_index IS NOT NULL AND o.completed_at IS NOT NULL
            AND o.revision >= ?2 AND ((CASE a.event_kind WHEN 115 THEN 1 WHEN 118 THEN 2
                WHEN 121 THEN 4 WHEN 136 THEN 8 END) & ?3) != 0
            AND NOT EXISTS (SELECT 1 FROM notification_deliveries d
                WHERE d.channel_id = ?1 AND d.event_id = a.event_id)
            ORDER BY o.committed_log_index, a.sequence, a.event_id LIMIT ?4",
        )?;
        statement
            .query_map(
                params![
                    channel_id.as_bytes().as_slice(),
                    super::apply::to_i64(channel.created_revision.get())?,
                    channel.event_filter,
                    i64::try_from(limit.get()).map_err(|_| RepositoryError::InvalidPageLimit)?
                ],
                |row| row.get::<_, [u8; 16]>(0),
            )?
            .map(|value| {
                AuditEventId::from_bytes(value?).map_err(|_| RepositoryError::CorruptState)
            })
            .collect()
    }

    /// Returns queued or expired-claim work in stable due-time/identity order.
    ///
    /// Claiming still requires the current channel and exact observed attempt. These reads do
    /// not reserve work or grant authority, so concurrent workers may observe the same page.
    ///
    /// # Errors
    /// Rejects negative time, corrupt records or unavailable persistence.
    pub fn ready_notification_deliveries(
        &self,
        now: UnixMicros,
        limit: PageLimit,
    ) -> Result<Vec<NotificationDeliveryRecord>, RepositoryError> {
        if now.get() < 0 {
            return Err(RepositoryError::InvalidCommand);
        }
        let connection = self.database.connection();
        let mut statement = connection.prepare(
            "SELECT delivery_id FROM notification_deliveries
            WHERE state IN (1, 2) AND next_attempt_at <= ?1
            ORDER BY next_attempt_at, delivery_id LIMIT ?2",
        )?;
        let ids = statement
            .query_map(
                params![
                    now.get(),
                    i64::try_from(limit.get()).map_err(|_| RepositoryError::InvalidPageLimit)?
                ],
                |row| row.get::<_, [u8; 16]>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| {
                let id = WorkId::from_bytes(id).map_err(|_| RepositoryError::CorruptState)?;
                notification_delivery::load(connection, id)?.ok_or(RepositoryError::CorruptState)
            })
            .collect()
    }
}
