// SPDX-License-Identifier: GPL-2.0-only

use ed25519_dalek::SigningKey;
use meshspan_domain::{
    DurationMicros, FederatedPrincipal, FederationGrant, FederationGrantId, FederationPolicy,
    FederationRelationshipId, FederationRelationshipKind, FederationResourceScope, MeshId,
    PrincipalId, Revision, StorageFederationPolicy, StorageParticipation, UnixMicros,
};
use meshspan_metadata::{
    CachedFederationGrantAuthority, FederationGovernanceDirection, FederationGrantRecord,
    FederationGrantRestriction, FederationGrantState, FederationIdentityOwner,
    FederationRelationshipRecord, FederationRelationshipState, FederationTransportAuthority,
    FederationTrustIdentity, FederationTrustIdentityRecord,
};
use meshspan_transport::{FederationLocalIdentityBinding, FederationPeerBinding};

use super::{EffectiveFederationGrantAuthorityError, evaluate_authority};
use crate::FederationConnectionAuthority;

#[test]
fn exact_bilateral_authority_is_admitted_with_both_revision_receipts()
-> Result<(), Box<dyn std::error::Error>> {
    let local = local_authority()?;
    let local_grant = grant_record(50, 4)?;
    let remote = remote_authority(grant_record(50, 6)?)?;

    let effective = evaluate_authority(&local, &local_grant, &remote, UnixMicros::new(15))?
        .ok_or("matching authority was withheld")?;
    assert_eq!(effective.grant, local_grant.grant);
    assert_eq!(effective.local_authority_revision, Revision::new(9));
    assert_eq!(effective.local_grant_revision, Revision::new(4));
    assert_eq!(effective.remote_authority_revision, Revision::new(7));
    assert_eq!(effective.remote_grant_revision, Revision::new(6));
    assert_eq!(effective.remote_observed_at, UnixMicros::new(14));
    Ok(())
}

#[test]
fn stale_epoch_rotation_revocation_and_expiry_withhold_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let local = local_authority()?;
    let local_grant = grant_record(50, 4)?;

    let mut stale_epoch = remote_authority(grant_record(50, 6)?)?;
    stale_epoch.relationship.relationship.authority_epoch = 2;
    assert!(evaluate_authority(&local, &local_grant, &stale_epoch, UnixMicros::new(15))?.is_none());

    let mut stale_identity = remote_authority(grant_record(50, 6)?)?;
    stale_identity
        .relationship
        .local_identity
        .identity
        .generation = 3;
    assert!(
        evaluate_authority(&local, &local_grant, &stale_identity, UnixMicros::new(15))?.is_none()
    );

    let mut revoked = remote_authority(grant_record(50, 6)?)?;
    revoked.grant.state = FederationGrantState::Revoked;
    assert!(evaluate_authority(&local, &local_grant, &revoked, UnixMicros::new(15))?.is_none());

    let remote = remote_authority(grant_record(50, 6)?)?;
    assert!(evaluate_authority(&local, &local_grant, &remote, UnixMicros::new(20))?.is_none());
    Ok(())
}

#[test]
fn same_fence_identity_or_grant_substitution_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let local = local_authority()?;
    let local_grant = grant_record(50, 4)?;

    let mut identity_substitution = remote_authority(grant_record(50, 6)?)?;
    identity_substitution
        .relationship
        .local_identity
        .identity
        .certificate_fingerprint = [42; 32];
    assert!(matches!(
        evaluate_authority(
            &local,
            &local_grant,
            &identity_substitution,
            UnixMicros::new(15)
        ),
        Err(EffectiveFederationGrantAuthorityError::ContradictoryAuthority)
    ));

    let narrowed_remote = remote_authority(grant_record(40, 6)?)?;
    assert!(matches!(
        evaluate_authority(&local, &local_grant, &narrowed_remote, UnixMicros::new(15)),
        Err(EffectiveFederationGrantAuthorityError::ContradictoryAuthority)
    ));

    let mut reflected = remote_authority(grant_record(50, 6)?)?;
    reflected.relationship.relationship.local_mesh_id = mesh(1)?;
    assert!(matches!(
        evaluate_authority(&local, &local_grant, &reflected, UnixMicros::new(15)),
        Err(EffectiveFederationGrantAuthorityError::ContradictoryAuthority)
    ));
    Ok(())
}

fn local_authority() -> Result<FederationConnectionAuthority, Box<dyn std::error::Error>> {
    let relationship_id = relationship_id()?;
    let local_mesh_id = mesh(1)?;
    let remote_mesh_id = mesh(2)?;
    Ok(FederationConnectionAuthority {
        authority_revision: Revision::new(9),
        relationship_kind: FederationRelationshipKind::Horizontal,
        governance_direction: FederationGovernanceDirection::None,
        peer: FederationPeerBinding {
            relationship_id,
            local_mesh_id,
            remote_mesh_id,
            authority_epoch: 3,
            identity_generation: 4,
            certificate_fingerprint: [5; 32],
            verifying_key: SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes(),
            valid_from: UnixMicros::new(1),
            valid_until: UnixMicros::new(100),
        },
        local_identity: FederationLocalIdentityBinding {
            relationship_id,
            local_mesh_id,
            remote_mesh_id,
            authority_epoch: 3,
            identity_generation: 7,
            certificate_fingerprint: [8; 32],
            verifying_key: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
            valid_from: UnixMicros::new(1),
            valid_until: UnixMicros::new(100),
        },
    })
}

fn remote_authority(
    grant: FederationGrantRecord,
) -> Result<CachedFederationGrantAuthority, Box<dyn std::error::Error>> {
    let relationship_id = relationship_id()?;
    Ok(CachedFederationGrantAuthority {
        authority_revision: Revision::new(7),
        relationship: FederationTransportAuthority {
            authority_revision: Revision::new(7),
            relationship: FederationRelationshipRecord {
                relationship_id,
                local_mesh_id: mesh(2)?,
                remote_mesh_id: mesh(1)?,
                kind: FederationRelationshipKind::Horizontal,
                governance_direction: FederationGovernanceDirection::None,
                state: FederationRelationshipState::Active,
                authority_epoch: 3,
                remote_display_name: "Local swarm".to_owned(),
                revision: Revision::new(2),
            },
            local_identity: identity(relationship_id, FederationIdentityOwner::Local, 4, 5, 6),
            remote_identity: identity(relationship_id, FederationIdentityOwner::Remote, 7, 8, 9),
        },
        grant,
        observed_at: UnixMicros::new(14),
    })
}

fn identity(
    relationship_id: FederationRelationshipId,
    owner: FederationIdentityOwner,
    generation: u64,
    fingerprint_seed: u8,
    key_seed: u8,
) -> FederationTrustIdentityRecord {
    FederationTrustIdentityRecord {
        relationship_id,
        owner,
        identity: FederationTrustIdentity {
            generation,
            certificate_fingerprint: [fingerprint_seed; 32],
            verifying_key: SigningKey::from_bytes(&[key_seed; 32])
                .verifying_key()
                .to_bytes(),
            valid_from: UnixMicros::new(1),
            valid_until: UnixMicros::new(100),
        },
        revision: Revision::new(2),
    }
}

fn grant_record(
    effective_maximum_bytes: u64,
    revision: u64,
) -> Result<FederationGrantRecord, Box<dyn std::error::Error>> {
    let mut restrictions = vec![
        FederationGrantRestriction {
            imposing_mesh_id: mesh(1)?,
            policy: storage_policy(effective_maximum_bytes, false)?,
        },
        FederationGrantRestriction {
            imposing_mesh_id: mesh(2)?,
            policy: storage_policy(100, true)?,
        },
    ];
    restrictions.sort_by_key(|restriction| restriction.imposing_mesh_id);
    let policies = restrictions
        .iter()
        .map(|restriction| restriction.policy)
        .collect::<Vec<_>>();
    Ok(FederationGrantRecord {
        grant: FederationGrant::new(
            grant_id()?,
            relationship_id()?,
            FederatedPrincipal::new(mesh(2)?, principal()?),
            FederationResourceScope::StorageCapacity {
                provider_mesh_id: mesh(1)?,
            },
            FederationPolicy::intersect(&policies)?,
            3,
            UnixMicros::new(10),
            Some(UnixMicros::new(20)),
        )?,
        restrictions,
        state: FederationGrantState::Active,
        issued_at: UnixMicros::new(9),
        termination: None,
        predecessor_grant_id: None,
        successor_grant_id: None,
        revision: Revision::new(revision),
    })
}

fn storage_policy(
    maximum_bytes: u64,
    protects: bool,
) -> Result<FederationPolicy, Box<dyn std::error::Error>> {
    Ok(FederationPolicy::Storage(StorageFederationPolicy::new(
        maximum_bytes,
        StorageParticipation::new(protects, true),
        Some(DurationMicros::new(10)),
    )?))
}

fn relationship_id() -> Result<FederationRelationshipId, Box<dyn std::error::Error>> {
    Ok(FederationRelationshipId::from_bytes([10; 16])?)
}

fn grant_id() -> Result<FederationGrantId, Box<dyn std::error::Error>> {
    Ok(FederationGrantId::from_bytes([11; 16])?)
}

fn principal() -> Result<PrincipalId, Box<dyn std::error::Error>> {
    Ok(PrincipalId::from_bytes([12; 16])?)
}

fn mesh(seed: u8) -> Result<MeshId, Box<dyn std::error::Error>> {
    Ok(MeshId::from_bytes([seed; 16])?)
}
