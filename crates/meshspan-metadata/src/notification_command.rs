// SPDX-License-Identifier: GPL-2.0-only

//! Typed notification configuration and durable, fenced delivery transitions.

use meshspan_domain::{AuditEventId, ComponentInstanceId, NodeId, WorkId};

use crate::{RecordName, SecretGenerationReference};

/// Envelope-encrypted notification destination, allow-list and credentials.
pub const NOTIFICATION_SETTINGS_SECRET_KIND: u16 = 10;

/// Explicit delivery adapter selected by a channel; neither is enabled by default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NotificationChannelKind {
    /// Authenticated HTTPS POST, without redirects.
    Webhook = 1,
    /// Authenticated SMTP through a TLS-protected relay.
    Email = 2,
}

/// Closed, redacted facts derived from already committed audit events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NotificationEventKind {
    /// A new certificate order, including an automatically scheduled renewal.
    CertificateOrderQueued = 1,
    /// A certificate order reached a committed completion outcome.
    CertificateOrderCompleted = 2,
    /// A manual DNS task changed; inspect the authenticated administration API.
    ManualDnsTaskChanged = 3,
    /// A metadata backup run reached a committed completion outcome.
    BackupRunCompleted = 4,
}

impl NotificationEventKind {
    pub(crate) const fn from_audit_kind(kind: i64) -> Option<Self> {
        match kind {
            115 => Some(Self::CertificateOrderQueued),
            118 => Some(Self::CertificateOrderCompleted),
            121 => Some(Self::ManualDnsTaskChanged),
            136 => Some(Self::BackupRunCompleted),
            _ => None,
        }
    }

    /// Bit used in the channel's explicit event allow-list.
    #[must_use]
    pub const fn filter_bit(self) -> u8 {
        1 << (self as u8 - 1)
    }
}

/// Full immutable replacement of one notification channel configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigureNotificationChannel {
    /// Stable identity of this notification channel.
    pub channel_id: ComponentInstanceId,
    /// Zero creates the channel; otherwise must match its exact current sequence.
    pub expected_sequence: u64,
    /// Non-secret administrative label, never sent to a receiver.
    pub display_name: RecordName,
    /// Delivery protocol; its settings are validated before encryption by that adapter.
    pub kind: NotificationChannelKind,
    /// Existing envelope-encrypted, immutable settings generation of kind 10.
    pub settings: SecretGenerationReference,
    /// Explicit opt-in; disabling cancels outstanding deliveries.
    pub enabled: bool,
    /// Non-zero combination of `NotificationEventKind::filter_bit()` values.
    pub event_filter: u8,
}

/// Request to project one committed event into one channel's deduplicated outbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueNotification {
    /// Exact currently enabled channel.
    pub channel_id: ComponentInstanceId,
    /// Committed source; raw audit payload is never copied into the notification.
    pub event_id: AuditEventId,
    /// Exact configuration admitted by the scheduler.
    pub channel_sequence: u64,
}

/// Claims one delivery for at most 60 seconds; an expired claim may be replaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimNotification {
    /// Deterministically derived channel/event delivery identity.
    pub delivery_id: WorkId,
    /// Last observed attempt, initially zero; incremented atomically when claiming.
    pub expected_attempt: u64,
    /// Active worker node.
    pub worker_node_id: NodeId,
    /// Exact current worker incarnation.
    pub worker_incarnation: u64,
}

/// Redacted outcome: acceptance is by the external endpoint, not its final consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NotificationDeliveryOutcome {
    /// HTTPS success or SMTP acceptance after DATA.
    Accepted = 1,
    /// Ambiguous connection loss, timeout, or temporary receiver failure; retry later.
    Retry = 2,
    /// Invalid destination/credentials or permanent receiver rejection; attention required.
    Rejected = 3,
}

/// Resolves only the exact still-current delivery attempt and worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteNotification {
    /// Claimed delivery.
    pub delivery_id: WorkId,
    /// Exact claim attempt, not its predecessor.
    pub attempt: u64,
    /// Node which made the claimed attempt.
    pub worker_node_id: NodeId,
    /// Incarnation which made the claimed attempt.
    pub worker_incarnation: u64,
    /// Closed classification; no remote response bodies or secrets are retained.
    pub outcome: NotificationDeliveryOutcome,
}
