// SPDX-License-Identifier: GPL-2.0-only

//! Cluster composition for bounded branch exchange and deterministic namespace reconciliation.

use meshspan_domain::{NamespaceCommitId, VolumeId};
use meshspan_filesystem::{
    NamespaceHistoryBundle, NamespaceHistoryImport, NamespaceHistoryLimits,
    NamespaceReconciliationApplication, NamespaceReconciliationReceipt,
    PreparedNamespaceReconciliation, PublicationError, ReconciliationFrontier,
    ReconciliationLimits, ReconciliationStoreError, VersionPublicationStore,
};
use thiserror::Error;

/// Production service boundary used after authenticated peers compare branch heads.
pub struct FilesystemConvergenceService<'a> {
    publications: &'a mut VersionPublicationStore,
    history_limits: NamespaceHistoryLimits,
    reconciliation_limits: ReconciliationLimits,
}

impl<'a> FilesystemConvergenceService<'a> {
    /// Binds one daemon-local branch store to explicit exchange and planning bounds.
    #[must_use]
    pub const fn new(
        publications: &'a mut VersionPublicationStore,
        history_limits: NamespaceHistoryLimits,
        reconciliation_limits: ReconciliationLimits,
    ) -> Self {
        Self {
            publications,
            history_limits,
            reconciliation_limits,
        }
    }

    /// Produces the immutable causal suffix requested by an authenticated peer.
    ///
    /// # Errors
    ///
    /// Rejects unknown heads, mixed scopes, non-mutation history, corruption and exceeded bounds.
    pub fn export_history(
        &self,
        volume_id: VolumeId,
        heads: &[NamespaceCommitId],
        known_commits: &[NamespaceCommitId],
    ) -> Result<NamespaceHistoryBundle, FilesystemConvergenceError> {
        self.publications
            .export_namespace_history(volume_id, heads, known_commits, self.history_limits)
            .map_err(Into::into)
    }

    /// Imports peer history and prepares its deterministic merge against the supplied frontier.
    ///
    /// The immutable import commits before planning. A crash at that boundary is safe: the same
    /// bundle is idempotent and planning can resume without moving a local branch head.
    ///
    /// # Errors
    ///
    /// Rejects malformed/colliding history or an incomplete, corrupt reconciliation frontier.
    pub fn import_and_prepare(
        &mut self,
        bundle: &NamespaceHistoryBundle,
        frontier: &ReconciliationFrontier,
    ) -> Result<PreparedHistoryReconciliation, FilesystemConvergenceError> {
        let imported = self
            .publications
            .import_namespace_history(bundle, self.history_limits)?;
        let prepared = self
            .publications
            .prepare_namespace_reconciliation(frontier, self.reconciliation_limits)?;
        Ok(PreparedHistoryReconciliation { imported, prepared })
    }

    /// Atomically applies one previously prepared deterministic merge.
    ///
    /// # Errors
    ///
    /// Rejects a substituted/stale plan, missing immutable records, corruption or persistence
    /// failure.
    pub fn apply(
        &mut self,
        application: NamespaceReconciliationApplication,
        prepared: &PreparedNamespaceReconciliation,
    ) -> Result<NamespaceReconciliationReceipt, FilesystemConvergenceError> {
        self.publications
            .apply_namespace_reconciliation(application, prepared)
            .map_err(Into::into)
    }
}

/// Durable import evidence paired with the exact deterministic plan it enabled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedHistoryReconciliation {
    /// Result of the all-or-nothing immutable import.
    pub imported: NamespaceHistoryImport,
    /// Exact causal and namespace replay plans ready for atomic application.
    pub prepared: PreparedNamespaceReconciliation,
}

/// Stable cluster-level convergence service failures.
#[derive(Debug, Error)]
pub enum FilesystemConvergenceError {
    /// Immutable publication or import failed.
    #[error("filesystem convergence publication failed")]
    Publication(#[from] PublicationError),
    /// Causal or namespace replay planning failed.
    #[error("filesystem convergence planning failed")]
    Planning(#[from] ReconciliationStoreError),
}
