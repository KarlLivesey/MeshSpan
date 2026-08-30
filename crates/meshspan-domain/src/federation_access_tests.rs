// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{
    DurationMicros, FederationAccess, FederationPreset, MeshId, NamespaceFederationPolicy,
    ObjectId, StorageFederationPolicy, StorageParticipation, VolumeId,
};

#[test]
fn valid_disconnected_edit_is_admitted() -> Result<(), Box<dyn std::error::Error>> {
    let grant = edit_grant(10, Some(40))?;
    let evidence = edit_evidence(&grant, 20, Rights::WRITE_DATA)?;
    assert_eq!(
        classify_federated_mutation(&grant, evidence, None)?,
        FederatedMutationAdmission::Admitted
    );
    Ok(())
}

#[test]
fn retroactive_revocation_quarantines_without_erasing() -> Result<(), Box<dyn std::error::Error>> {
    let grant = edit_grant(10, Some(40))?;
    let evidence = edit_evidence(&grant, 30, Rights::WRITE_DATA)?;
    assert_eq!(
        classify_federated_mutation(&grant, evidence, Some(UnixMicros::new(25)))?,
        FederatedMutationAdmission::Quarantined(QuarantineReason::Revoked)
    );
    assert_eq!(
        classify_federated_mutation(&grant, evidence, Some(UnixMicros::new(35)))?,
        FederatedMutationAdmission::Admitted
    );
    Ok(())
}

#[test]
fn expired_and_overbroad_use_is_quarantined() -> Result<(), Box<dyn std::error::Error>> {
    let grant = edit_grant(10, Some(40))?;
    assert_eq!(
        classify_federated_mutation(&grant, edit_evidence(&grant, 40, Rights::WRITE_DATA)?, None,)?,
        FederatedMutationAdmission::Quarantined(QuarantineReason::Expired)
    );
    assert_eq!(
        classify_federated_mutation(
            &grant,
            edit_evidence(&grant, 20, Rights::CHANGE_OWNER)?,
            None,
        )?,
        FederatedMutationAdmission::Quarantined(QuarantineReason::OutsideRights)
    );
    Ok(())
}

#[test]
fn substituted_principal_is_rejected_as_an_attack() -> Result<(), Box<dyn std::error::Error>> {
    let grant = edit_grant(10, Some(40))?;
    let mut evidence = edit_evidence(&grant, 20, Rights::WRITE_DATA)?;
    evidence.actor = FederatedPrincipal::new(mesh(9)?, crate::PrincipalId::from_bytes([9; 16])?);
    assert_eq!(
        classify_federated_mutation(&grant, evidence, None),
        Err(FederationGrantError::EvidenceMismatch)
    );
    Ok(())
}

#[test]
fn remote_storage_enforces_effective_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let policy = FederationPolicy::Storage(StorageFederationPolicy::new(
        50,
        StorageParticipation::new(true, false),
        false,
        None,
    )?);
    let resource = FederationResourceScope::StorageCapacity {
        provider_mesh_id: mesh(3)?,
    };
    let grant = FederationGrant::new(
        FederationGrantId::from_bytes([4; 16])?,
        FederationRelationshipId::from_bytes([5; 16])?,
        FederationGrantRoute::direct(mesh(3)?, mesh(6)?)?,
        None,
        resource,
        policy,
        2,
        UnixMicros::new(10),
        None,
    )?;
    let evidence = FederatedMutationEvidence::new(
        grant.grant_id(),
        grant.relationship_id(),
        FederatedPrincipal::new(
            grant.recipient_mesh_id(),
            crate::PrincipalId::from_bytes([7; 16])?,
        ),
        resource,
        grant.authority_epoch(),
        UnixMicros::new(20),
        Rights::default(),
        51,
    );
    assert_eq!(
        classify_federated_mutation(&grant, evidence, None)?,
        FederatedMutationAdmission::Quarantined(QuarantineReason::OutsideStorageLimit)
    );
    Ok(())
}

fn edit_grant(
    valid_from: i64,
    valid_until: Option<i64>,
) -> Result<FederationGrant, Box<dyn std::error::Error>> {
    let offline_duration = valid_until
        .and_then(|until| u64::try_from(until - valid_from).ok())
        .map(DurationMicros::new);
    let policy = FederationPolicy::Namespace(NamespaceFederationPolicy::new(
        FederationAccess::from_preset(FederationPreset::Edit),
        offline_duration,
    ));
    Ok(FederationGrant::new(
        FederationGrantId::from_bytes([1; 16])?,
        FederationRelationshipId::from_bytes([2; 16])?,
        FederationGrantRoute::direct(mesh(5)?, mesh(3)?)?,
        None,
        FederationResourceScope::File {
            owner_mesh_id: mesh(5)?,
            volume_id: VolumeId::from_bytes([6; 16])?,
            object_id: ObjectId::from_bytes([7; 16])?,
        },
        policy,
        8,
        UnixMicros::new(valid_from),
        valid_until.map(UnixMicros::new),
    )?)
}

fn edit_evidence(
    grant: &FederationGrant,
    accepted_at: i64,
    required_rights: Rights,
) -> Result<FederatedMutationEvidence, crate::IdentifierError> {
    Ok(FederatedMutationEvidence::new(
        grant.grant_id(),
        grant.relationship_id(),
        FederatedPrincipal::new(
            grant.recipient_mesh_id(),
            crate::PrincipalId::from_bytes([4; 16])?,
        ),
        grant.resource(),
        grant.authority_epoch(),
        UnixMicros::new(accepted_at),
        required_rights,
        0,
    ))
}

fn mesh(value: u8) -> Result<MeshId, crate::IdentifierError> {
    MeshId::from_bytes([value; 16])
}
