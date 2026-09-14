// SPDX-License-Identifier: GPL-2.0-only

//! Durable identity selected before an encrypted backup upload can have side effects.

use meshspan_contracts::BackupObjectIdentity;
use meshspan_domain::{OperationId, Revision};

/// Records intended bytes, not a successful provider write or a recoverable backup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindBackupPublicationIntent {
    /// Exact immutable encrypted object selected for this destination.
    pub object: BackupObjectIdentity,
    /// Stable provider store operation, retained even if its response is lost.
    pub store_operation_id: OperationId,
    /// Current live schedule-run claim authorising publication.
    pub claim: crate::MetadataBackupRunClaim,
    /// Exact active destination configuration checked before IO.
    pub expected_destination_revision: Revision,
}

/// Original publication identity remains available after local journal or worker loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupPublicationIntentRecord {
    /// Immutable first-admitted intent; later claims may only reuse its exact object/operation.
    pub binding: BindBackupPublicationIntent,
    /// First committed intent revision, not a provider completion revision.
    pub revision: Revision,
}

/// Exact intended upload whose run was authoritatively abandoned before admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbandonedBackupPublication {
    /// Durable pre-IO identity; not evidence that the provider received bytes.
    pub intent: BackupPublicationIntentRecord,
    /// Current terminal run revision required when admitting retirement evidence.
    pub run_revision: Revision,
}
