// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative verification and historical classification of remote mutation acknowledgements.

use meshspan_domain::{
    FederatedMutationAcknowledgement, FederatedMutationAdmission, QuarantineReason,
};

use super::federation_succession_trust::verify_side_signature;
use super::{RepositoryError, federation_grant, federation_principal};
use crate::FederatedPrincipalState;

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
        evidence.subject().home_mesh_id(),
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
        if relationship.local_mesh_id != evidence.resource().authority_mesh_id()
            || relationship.remote_mesh_id != evidence.subject().home_mesh_id()
        {
            return Err(RepositoryError::InvalidCommand);
        }
        let projection = federation_principal::projection_connection(
            connection,
            evidence.relationship_id(),
            evidence.subject(),
        )?
        .ok_or(RepositoryError::InvalidCommand)?;
        if projection.state != FederatedPrincipalState::Active {
            return Ok(FederatedMutationAdmission::Quarantined(
                QuarantineReason::PrincipalInactive,
            ));
        }
    }
    federation_grant::classify_persisted_mutation(connection, evidence)
}
