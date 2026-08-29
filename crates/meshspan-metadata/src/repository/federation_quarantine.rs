// SPDX-License-Identifier: GPL-2.0-only

//! Federated mutation quarantine facade and independently verified read model.

use meshspan_domain::{
    FederatedMutationEvidence, OperationId, QuarantineId, QuarantineReason, Revision,
};

use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    AuthoritativeCommand, CommandContext, FederationQuarantineResolution, PartitionDatabase,
};

/// Current independently verified quarantine lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationQuarantineState {
    /// Immutable payload remains invisible and has not yet been presented for recovery.
    Retained,
    /// Authorised administration has been shown the recovery item.
    Surfaced,
    /// Restore or restore-as-copy authority was recorded.
    Restored,
    /// Payload reclamation was authorised after surfacing.
    Discarded,
}

/// One signed quarantined mutation and its current recovery state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationQuarantineRecord {
    /// Stable quarantine identity.
    pub quarantine_id: QuarantineId,
    /// Remote source operation.
    pub source_operation_id: OperationId,
    /// Exact historical grant-use evidence.
    pub evidence: FederatedMutationEvidence,
    /// Authoritatively derived inadmissibility reason.
    pub reason: QuarantineReason,
    /// Retained immutable payload digest.
    pub payload_digest: [u8; 32],
    /// Current recovery lifecycle.
    pub state: FederationQuarantineState,
    /// Terminal resolution, if one has been authorised.
    pub resolution: Option<FederationQuarantineResolution>,
    /// Last authoritative revision.
    pub revision: Revision,
}

pub(super) fn is_command(command: &AuthoritativeCommand) -> bool {
    matches!(
        command,
        AuthoritativeCommand::RetainFederatedMutationQuarantine(_)
            | AuthoritativeCommand::SurfaceFederatedMutationQuarantine(_)
            | AuthoritativeCommand::ResolveFederatedMutationQuarantine(_)
    )
}

pub(super) fn execute(
    transaction: &rusqlite::Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let quarantine_id =
        super::federation_quarantine_transition::execute(transaction, context, command, revision)?;
    Ok(EntityReference {
        kind: EntityKind::FederationQuarantine,
        id: quarantine_id.as_bytes(),
    })
}

pub(super) fn quarantine(
    database: &PartitionDatabase,
    quarantine_id: QuarantineId,
) -> Result<Option<FederationQuarantineRecord>, RepositoryError> {
    super::federation_quarantine_evidence::load_verified(database.connection(), quarantine_id)
        .map(|stored| stored.map(|value| value.record))
}
