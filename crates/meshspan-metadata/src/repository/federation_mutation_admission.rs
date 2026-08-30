// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative verification and historical classification of remote mutation acknowledgements.

use meshspan_domain::{
    FederatedMutationAcknowledgement, FederatedMutationAdmission, OperationId, QuarantineId,
    QuarantineReason, Revision,
};

use super::federation_succession_trust::verify_side_signature;
use super::{
    CommandReceipt, EntityKind, EntityReference, RepositoryError, federation_actor_attestation,
    federation_grant,
};
use crate::{AdmitFederatedMutation, CommandContext, FederatedActorState, PartitionDatabase};

/// Exact durable owner decision for one deterministic federated mutation operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederatedMutationAdmissionReceipt {
    /// Consensus-applied operation receipt.
    pub receipt: CommandReceipt,
    /// Immutable admitted or quarantined outcome, including the authoritative reason.
    pub admission: FederatedMutationAdmission,
}

pub(super) fn admit(
    transaction: &rusqlite::Transaction<'_>,
    context: CommandContext,
    command: &AdmitFederatedMutation,
    _revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.acknowledgement.source_operation_id == context.operation_id
        || command.acknowledgement.evidence.accepted_at() > context.occurred_at
        || classify(transaction, &command.acknowledgement)? != FederatedMutationAdmission::Admitted
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(EntityReference {
        kind: EntityKind::FederationMutationAdmission,
        id: command.namespace_commit_id.as_bytes(),
    })
}

pub(super) fn classify(
    connection: &rusqlite::Connection,
    acknowledgement: &FederatedMutationAcknowledgement,
) -> Result<FederatedMutationAdmission, RepositoryError> {
    if acknowledgement.signer_generation == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    let evidence = acknowledgement.evidence;
    verify_side_signature(
        connection,
        evidence.relationship_id(),
        evidence.accepting_mesh_id(),
        acknowledgement.signer_generation,
        &acknowledgement.signing_payload(),
        acknowledgement.signature,
        false,
    )?;
    if !matches!(
        evidence.resource(),
        meshspan_domain::FederationResourceScope::StorageCapacity { .. }
    ) {
        let relationship = super::federation_succession_trust::relationship(
            connection,
            evidence.relationship_id(),
        )?;
        if relationship.remote_mesh_id != evidence.accepting_mesh_id() {
            return Err(RepositoryError::InvalidCommand);
        }
        if evidence.actor().home_mesh_id() == evidence.accepting_mesh_id() {
            let attestation = federation_actor_attestation::attestation_connection(
                connection,
                evidence.relationship_id(),
                evidence.actor(),
            )?
            .ok_or(RepositoryError::InvalidCommand)?;
            if attestation.state != FederatedActorState::Active {
                return Ok(FederatedMutationAdmission::Quarantined(
                    QuarantineReason::PrincipalInactive,
                ));
            }
        }
    }
    federation_grant::classify_persisted_mutation(connection, evidence)
}

pub(super) fn resolve(
    database: &PartitionDatabase,
    operation_id: OperationId,
) -> Result<Option<FederatedMutationAdmissionReceipt>, RepositoryError> {
    let Some(receipt) = super::receipt::resolve_operation(database, operation_id)? else {
        return Ok(None);
    };
    let admission = match receipt.entity.kind {
        EntityKind::FederationMutationAdmission => FederatedMutationAdmission::Admitted,
        EntityKind::FederationQuarantine => {
            let quarantine_id = QuarantineId::from_bytes(receipt.entity.id)
                .map_err(|_| RepositoryError::CorruptState)?;
            let quarantine = super::federation_quarantine::quarantine(database, quarantine_id)?
                .ok_or(RepositoryError::CorruptState)?;
            FederatedMutationAdmission::Quarantined(quarantine.reason)
        }
        _ => return Err(RepositoryError::InvalidCommand),
    };
    Ok(Some(FederatedMutationAdmissionReceipt {
        receipt,
        admission,
    }))
}
