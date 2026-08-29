// SPDX-License-Identifier: GPL-2.0-only

//! Permanent local manifest-root retirement from replicated cleanup completion authority.

use meshspan_domain::{
    ContentManifestId, FileVersionId, OperationId, Revision, UnixMicros, VolumeId,
};
use thiserror::Error;

/// Exact replicated completion authority applied by one gateway.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupRetirementAuthority {
    /// Idempotency identity of this gateway-local application.
    pub retirement_operation_id: OperationId,
    /// Replicated cleanup proposal identity.
    pub cleanup_operation_id: OperationId,
    /// This gateway's durable unreachable scan selected by the proposal.
    pub source_scan_operation_id: OperationId,
    /// Exact operation-independent cleanup subject shared by all participants.
    pub reachability_subject_digest: [u8; 32],
    /// Exact number of completed items in the sealed inventory.
    pub completed_item_count: u64,
    /// Ordered digest of all committed provider tombstone completions.
    pub completion_digest: [u8; 32],
    /// Replicated operation that completed the final item.
    pub completion_operation_id: OperationId,
    /// Replicated terminal completion revision.
    pub completion_revision: Revision,
    /// Replicated terminal completion instant.
    pub completed_at: UnixMicros,
    /// Gateway-known time at which this authority was durably applied.
    pub retired_at: UnixMicros,
}

/// Immutable local proof that one manifest root can never be republished.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupRetirementReceipt {
    /// Idempotency identity of this gateway-local application.
    pub retirement_operation_id: OperationId,
    /// Replicated cleanup proposal identity.
    pub cleanup_operation_id: OperationId,
    /// Local scan whose active fence became permanent.
    pub source_scan_operation_id: OperationId,
    /// Volume containing the unreachable historical version.
    pub volume_id: VolumeId,
    /// Historical version selected by the scan.
    pub version_id: FileVersionId,
    /// Immutable content-manifest identity.
    pub manifest_id: ContentManifestId,
    /// Immutable manifest root permanently excluded from publication.
    pub manifest_root_digest: [u8; 32],
    /// Replicated terminal completion revision.
    pub completion_revision: Revision,
    /// Digest binding the exact durable local retirement and replicated authority.
    pub retirement_digest: [u8; 32],
}

/// Stable failures while applying replicated cleanup completion locally.
#[derive(Debug, Error)]
pub enum VersionCleanupRetirementError {
    /// Required identity, count, revision, digest or time ordering is invalid.
    #[error("cleanup retirement input is invalid")]
    InvalidInput,
    /// An idempotency or globally retired identity belongs to different authority.
    #[error("cleanup retirement authority conflicts with durable state")]
    Conflict,
    /// The local scan fence is absent, released or describes another cleanup subject.
    #[error("cleanup retirement authority is stale")]
    Stale,
    /// Persisted retirement or fence state violates its exact digest/identity contract.
    #[error("cleanup retirement state is corrupt")]
    Corrupt,
    /// Deterministic test-only interruption before the retirement transaction commits.
    #[error("cleanup retirement transaction fault injected")]
    InjectedFault,
    /// SQLite persistence failed.
    #[error("cleanup retirement database operation failed")]
    Sqlite(#[from] rusqlite::Error),
}
