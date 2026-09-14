// SPDX-License-Identifier: GPL-2.0-only

//! Finite worker-pass outcomes, distinct from inventory or unique operation counts.

use crate::LatencyHistogram;
use std::time::Duration;

/// Owned operational worker being observed. No resource identity becomes a metric label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleKind {
    /// ACME admission, renewal and order execution.
    CertificateAutomation,
    /// Installation and acknowledgement of the selected public certificate.
    CertificateInstallation,
    /// Metadata backup capture, copy publication and protection completion.
    Backup,
    /// Local update candidate verification/distribution; not whole-rollout completion.
    UpdatePreparation,
    /// Native federation trust refresh and session handshake outcomes.
    FederationSessions,
}

impl LifecycleKind {
    /// Fixed observation slots, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::CertificateAutomation,
        Self::CertificateInstallation,
        Self::Backup,
        Self::UpdatePreparation,
        Self::FederationSessions,
    ];
}

/// Result actually returned by one finite owned worker pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleOutcome {
    /// No new work was selected, or an installed selection was already current.
    Idle,
    /// Work awaits external state, destinations or a subsequent authoritative transition.
    Pending,
    /// The worker recorded non-terminal progress.
    Progress,
    /// The worker committed its named unit, not necessarily an entire mesh-wide workflow.
    Completed,
    /// A failed or expired attempt was explicitly returned for retry.
    Retried,
    /// The pass returned an error before a normal outcome.
    Failed,
}

/// Process-local worker evidence. Replayed passes may count again; restart resets counts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleMetric {
    /// Passes with no new work.
    Idle(u64),
    /// Passes waiting for more evidence or external progress.
    Pending(u64),
    /// Passes recording non-terminal progress.
    Progress(u64),
    /// Passes returning completion of their named unit.
    Completed(u64),
    /// Explicit retry outcomes.
    Retried(u64),
    /// Returned errors.
    Failed(u64),
    /// Duration of observed passes, including failed ones.
    Duration(LatencyHistogram),
    /// Monotonic age of the last observed pass; absent until the first observation.
    ObservationAge(Duration),
}
