// SPDX-License-Identifier: GPL-2.0-only

//! Closed operational inventory measurements, never live service or protection authority.

use std::time::Duration;

/// Finite, identity-free certificate, backup and update observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryMetric {
    /// A public certificate has been selected in observed metadata.
    CertificateSelected(bool),
    /// Remaining selected-certificate validity at sample time, using the host wall clock.
    CertificateRemainingValidity(Duration),
    /// The selected certificate's validity has not begun at sample time.
    CertificateNotYetValid(bool),
    /// The selected certificate has expired at sample time.
    CertificateExpired(bool),
    /// Gateways represented in the selected encrypted delivery generation.
    CertificateRequiredGateways(u64),
    /// Exact-generation durable installation acknowledgements, not live gateway probes.
    CertificateInstalledGateways(u64),
    /// Monotonic age of the certificate observation.
    CertificateObservationAge(Duration),
    /// Failed certificate observation attempts in this process.
    CertificateObservationFailures(u64),
    /// Retained backup occurrences awaiting a worker.
    BackupsQueued(u64),
    /// Retained backup occurrences with a claimed worker.
    BackupsClaimed(u64),
    /// Retained backup occurrences with admitted bytes but unfinished protection.
    BackupsRecorded(u64),
    /// Retained backup occurrences historically meeting their protection thresholds.
    BackupsProtected(u64),
    /// Retained backup occurrences that ended without their protection thresholds.
    BackupsIncomplete(u64),
    /// Monotonic age of the start of a completed paged backup inventory.
    BackupObservationAge(Duration),
    /// Failed backup inventory passes in this process.
    BackupObservationFailures(u64),
    /// Retained running rollouts.
    UpdatesRunning(u64),
    /// Retained paused rollouts.
    UpdatesPaused(u64),
    /// Retained completed rollouts.
    UpdatesCompleted(u64),
    /// Retained cancelled rollouts.
    UpdatesCancelled(u64),
    /// Whether a running/paused rollout is currently selected in the observation.
    UpdateSelected(bool),
    /// Selected rollout nodes awaiting staging.
    UpdatePendingNodes(u64),
    /// Selected rollout nodes with staged bytes, including preparation in progress.
    UpdateStagedNodes(u64),
    /// Selected rollout nodes in the restart phase.
    UpdateRestartingNodes(u64),
    /// Selected rollout nodes with verified replacement processes.
    UpdateVerifiedNodes(u64),
    /// Selected rollout nodes with failed checkpoints.
    UpdateFailedNodes(u64),
    /// Selected rollout restart outcomes still requiring reconciliation.
    UpdateUnresolvedRestarts(u64),
    /// Monotonic age of the start of a completed paged update inventory.
    UpdateObservationAge(Duration),
    /// Failed update inventory passes in this process.
    UpdateObservationFailures(u64),
}
