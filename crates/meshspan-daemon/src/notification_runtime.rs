// SPDX-License-Identifier: GPL-2.0-only

//! Owned outbox scheduling and delivery. Receiver failures never stop file service or healing.

use crate::{
    ConsensusAuthenticationAuthority, LocalWrappingKey, NotificationTransport,
    OperatingSystemClock, OperatingSystemRandom,
};
use meshspan_domain::{
    AuditEventId, Clock, NodeId, OperationId, PrincipalId, RandomSource, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, ClaimNotification, CommandContext, CompleteNotification, EntityKind,
    NotificationDeliveryOutcome, NotificationDeliveryRecord, PageLimit, QueueNotification,
};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

/// Redacted local health: idle/healthy, retrying unavailable authority/settings, or worker stopped.
#[derive(Clone, Default)]
pub(crate) struct NotificationHealth(Arc<AtomicU8>);

impl NotificationHealth {
    pub(crate) fn code(&self) -> u8 {
        self.0.load(Ordering::Relaxed)
    }
}

pub(crate) struct NotificationRuntime {
    authority: ConsensusAuthenticationAuthority,
    key: LocalWrappingKey,
    transport: NotificationTransport,
    node: NodeId,
    incarnation: u64,
    health: NotificationHealth,
}

impl NotificationRuntime {
    pub(crate) fn new(
        authority: ConsensusAuthenticationAuthority,
        key: LocalWrappingKey,
        transport: NotificationTransport,
        node: NodeId,
        incarnation: u64,
    ) -> Self {
        Self {
            authority,
            key,
            transport,
            node,
            incarnation,
            health: NotificationHealth::default(),
        }
    }

    pub(crate) fn health(&self) -> NotificationHealth {
        self.health.clone()
    }

    pub(crate) async fn run_until(mut self, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => return,
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
            let handle = tokio::runtime::Handle::current();
            let health = self.health.clone();
            let mut worker = tokio::task::spawn_blocking(move || {
                let outcome = handle.block_on(self.run_once());
                (self, outcome)
            });
            // Even on shutdown observe the owned job; network attempts have a 35-second limit.
            // An accepted-but-unrecorded result remains an expiring claim, not a false receipt.
            tokio::select! {
                () = &mut shutdown => {
                    if worker.await.is_err() { health.0.store(2, Ordering::Relaxed); }
                    return;
                },
                result = &mut worker => {
                    if let Ok((returned, outcome)) = result {
                        self = returned;
                        health.0.store(u8::from(outcome.is_err()), Ordering::Relaxed);
                    } else {
                        health.0.store(2, Ordering::Relaxed);
                        shutdown.await;
                        return;
                    }
                }
            }
        }
    }

    async fn run_once(&self) -> Result<(), NotificationRuntimeError> {
        self.project_events()?;
        let due = self
            .authority
            .reader()
            .ready_notification_deliveries(
                OperatingSystemClock.now(),
                PageLimit::new(1).map_err(|_| NotificationRuntimeError)?,
            )
            .map_err(|_| NotificationRuntimeError)?;
        for delivery in due {
            self.deliver(delivery).await?;
        }
        Ok(())
    }

    fn project_events(&self) -> Result<(), NotificationRuntimeError> {
        // One event per channel per tick gives every destination a turn without an unbounded scan.
        for channel in self
            .authority
            .reader()
            .notification_channels()
            .map_err(|_| NotificationRuntimeError)?
        {
            if !channel.enabled {
                continue;
            }
            for event in self
                .authority
                .reader()
                .pending_notification_events(
                    channel.channel_id,
                    PageLimit::new(1).map_err(|_| NotificationRuntimeError)?,
                )
                .map_err(|_| NotificationRuntimeError)?
            {
                self.commit(
                    channel.configured_by,
                    &AuthoritativeCommand::QueueNotification(QueueNotification {
                        channel_id: channel.channel_id,
                        event_id: event,
                        channel_sequence: channel.sequence,
                    }),
                    EntityKind::NotificationDelivery,
                )?;
            }
        }
        Ok(())
    }

    async fn deliver(
        &self,
        delivery: NotificationDeliveryRecord,
    ) -> Result<(), NotificationRuntimeError> {
        let channel = self
            .authority
            .reader()
            .notification_channel(delivery.channel_id)
            .map_err(|_| NotificationRuntimeError)?
            .ok_or(NotificationRuntimeError)?;
        let destination = crate::notification_settings::load(&self.authority, &self.key, &channel)
            .map_err(|_| NotificationRuntimeError)?;
        self.commit(
            channel.configured_by,
            &AuthoritativeCommand::ClaimNotification(ClaimNotification {
                delivery_id: delivery.delivery_id,
                expected_attempt: delivery.attempt,
                worker_node_id: self.node,
                worker_incarnation: self.incarnation,
            }),
            EntityKind::NotificationDelivery,
        )?;
        let claimed = self
            .authority
            .reader()
            .notification_delivery(delivery.delivery_id)
            .map_err(|_| NotificationRuntimeError)?
            .ok_or(NotificationRuntimeError)?;
        if claimed.channel_sequence != channel.sequence
            || claimed.claim.is_none_or(|(node, incarnation, _)| {
                node != self.node || incarnation != self.incarnation
            })
        {
            return Err(NotificationRuntimeError);
        }
        let outcome: NotificationDeliveryOutcome =
            self.transport.deliver(&destination, &claimed).await;
        self.commit(
            channel.configured_by,
            &AuthoritativeCommand::CompleteNotification(CompleteNotification {
                delivery_id: claimed.delivery_id,
                attempt: claimed.attempt,
                worker_node_id: self.node,
                worker_incarnation: self.incarnation,
                outcome,
            }),
            EntityKind::NotificationDelivery,
        )
    }

    fn commit(
        &self,
        actor: PrincipalId,
        command: &AuthoritativeCommand,
        kind: EntityKind,
    ) -> Result<(), NotificationRuntimeError> {
        let mut random = [0; 32];
        OperatingSystemRandom
            .fill_bytes(&mut random)
            .map_err(|_| NotificationRuntimeError)?;
        let operation = uuid_v8(
            random[..16]
                .try_into()
                .map_err(|_| NotificationRuntimeError)?,
        );
        let audit = uuid_v8(
            random[16..]
                .try_into()
                .map_err(|_| NotificationRuntimeError)?,
        );
        let context = CommandContext {
            operation_id: OperationId::from_bytes(operation)
                .map_err(|_| NotificationRuntimeError)?,
            audit_event_id: AuditEventId::from_bytes(audit)
                .map_err(|_| NotificationRuntimeError)?,
            actor_principal_id: actor,
            occurred_at: OperatingSystemClock.now(),
            expected_revision: None,
        };
        let receipt = self
            .authority
            .commit_authoritative(context, command)
            .map_err(|_| NotificationRuntimeError)?;
        if receipt.operation_id != context.operation_id
            || receipt.request_digest != command.request_digest(context)
            || receipt.entity.kind != kind
            || receipt.result_digest == [0; 32]
        {
            return Err(NotificationRuntimeError);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct NotificationRuntimeError;
