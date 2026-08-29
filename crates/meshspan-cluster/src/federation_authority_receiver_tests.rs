// SPDX-License-Identifier: GPL-2.0-only

use ed25519_dalek::SigningKey;
use meshspan_domain::{
    DurationMicros, FederatedPrincipal, FederationGrant, FederationGrantId, FederationPolicy,
    FederationRelationshipId, FederationRelationshipKind, FederationResourceScope, MeshId,
    PrincipalId, Revision, StorageFederationPolicy, StorageParticipation, UnixMicros,
};
use meshspan_metadata::{
    FederationGovernanceDirection, FederationGrantRecord, FederationGrantRestriction,
    FederationGrantState, FederationIdentityOwner, FederationRelationshipRecord,
    FederationRelationshipState, FederationTransportAuthority, FederationTrustIdentity,
    FederationTrustIdentityRecord,
};
use meshspan_protocol::v1::VersionedPayload;
use meshspan_transport::{FederationLocalIdentityBinding, FederationPeerBinding};

use super::{
    AuthorityPageView, FederationAuthorityImportError, FederationAuthorityImportLimits,
    FederationAuthorityUpdate, FederationRemoteAuthoritySnapshotReceiver,
};
use crate::FederationConnectionAuthority;

#[test]
fn terminal_page_atomically_exposes_the_complete_snapshot() -> Result<(), Box<dyn std::error::Error>>
{
    let authority = local_authority()?;
    let mut receiver = receiver(&authority, 0, 3)?;
    let relationship = relationship_payload(&authority, false)?;
    receiver.accept_page_view(&[], page(5, &[relationship], &[7]))?;
    assert_eq!(receiver.next_cursor(), Some([7].as_slice()));

    let grant = grant_payload(&authority, 20, 4)?;
    receiver.accept_page_view(&[7], page(5, &[grant], &[]))?;
    assert!(receiver.next_cursor().is_none());
    let FederationAuthorityUpdate::Snapshot(snapshot) = receiver.finish()? else {
        return Err("changed import returned unchanged".into());
    };
    assert_eq!(snapshot.after_revision, Revision::ZERO);
    assert_eq!(snapshot.authority_revision, Revision::new(5));
    assert_eq!(snapshot.grants.len(), 1);
    assert_eq!(snapshot.grants[0].grant.grant_id(), grant_id(20)?);
    Ok(())
}

#[test]
fn any_invalid_page_poisons_the_whole_import() -> Result<(), Box<dyn std::error::Error>> {
    let authority = local_authority()?;
    let mut receiver = receiver(&authority, 0, 3)?;
    let relationship = relationship_payload(&authority, false)?;
    receiver.accept_page_view(&[], page(5, &[relationship], &[7]))?;
    let grant = grant_payload(&authority, 20, 4)?;
    assert_eq!(
        receiver.accept_page_view(&[7], page(6, &[grant], &[])),
        Err(FederationAuthorityImportError::Invalid)
    );
    assert!(receiver.next_cursor().is_none());
    assert_eq!(
        receiver.finish(),
        Err(FederationAuthorityImportError::Invalid)
    );
    Ok(())
}

#[test]
fn reflection_order_version_and_capacity_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let authority = local_authority()?;
    let reflected = relationship_payload(&authority, true)?;
    assert_eq!(
        receiver(&authority, 0, 3)?.accept_page_view(&[], page(5, &[reflected], &[])),
        Err(FederationAuthorityImportError::Invalid)
    );

    let relationship = relationship_payload(&authority, false)?;
    let later = grant_payload(&authority, 21, 4)?;
    let earlier = grant_payload(&authority, 20, 3)?;
    assert_eq!(
        receiver(&authority, 0, 3)?
            .accept_page_view(&[], page(5, &[relationship.clone(), later, earlier], &[]),),
        Err(FederationAuthorityImportError::Invalid)
    );

    let mut unsupported = grant_payload(&authority, 20, 4)?;
    unsupported.format_version = 2;
    assert_eq!(
        receiver(&authority, 0, 3)?
            .accept_page_view(&[], page(5, &[relationship.clone(), unsupported], &[]),),
        Err(FederationAuthorityImportError::UnsupportedVersion)
    );
    assert_eq!(
        receiver(&authority, 0, 1)?.accept_page_view(
            &[],
            page(5, &[relationship, grant_payload(&authority, 20, 4)?], &[],),
        ),
        Err(FederationAuthorityImportError::CapacityExceeded)
    );
    Ok(())
}

fn receiver(
    authority: &FederationConnectionAuthority,
    after_revision: u64,
    maximum_records: usize,
) -> Result<FederationRemoteAuthoritySnapshotReceiver, FederationAuthorityImportError> {
    Ok(FederationRemoteAuthoritySnapshotReceiver::new(
        *authority,
        Revision::new(after_revision),
        FederationAuthorityImportLimits::new(4, maximum_records, 1_048_576)?,
    ))
}

const fn page<'a>(
    authority_revision: u64,
    records: &'a [VersionedPayload],
    next_cursor: &'a [u8],
) -> AuthorityPageView<'a> {
    AuthorityPageView {
        authority_revision,
        records,
        next_cursor,
    }
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
            valid_until: UnixMicros::new(1_000),
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
            valid_until: UnixMicros::new(1_000),
        },
    })
}

fn relationship_payload(
    local: &FederationConnectionAuthority,
    reflected: bool,
) -> Result<VersionedPayload, Box<dyn std::error::Error>> {
    let (source_local, source_remote) = if reflected {
        (local.peer.local_mesh_id, local.peer.remote_mesh_id)
    } else {
        (local.peer.remote_mesh_id, local.peer.local_mesh_id)
    };
    let authority = FederationTransportAuthority {
        authority_revision: Revision::new(5),
        relationship: FederationRelationshipRecord {
            relationship_id: local.peer.relationship_id,
            local_mesh_id: source_local,
            remote_mesh_id: source_remote,
            kind: FederationRelationshipKind::Horizontal,
            governance_direction: FederationGovernanceDirection::None,
            state: FederationRelationshipState::Active,
            authority_epoch: 3,
            remote_display_name: "Mirrored swarm".to_owned(),
            revision: Revision::new(2),
        },
        local_identity: identity_record(
            local.peer.relationship_id,
            FederationIdentityOwner::Local,
            local.peer.identity_generation,
            local.peer.certificate_fingerprint,
            local.peer.verifying_key,
        ),
        remote_identity: identity_record(
            local.peer.relationship_id,
            FederationIdentityOwner::Remote,
            local.local_identity.identity_generation,
            local.local_identity.certificate_fingerprint,
            local.local_identity.verifying_key,
        ),
    };
    Ok(VersionedPayload {
        format_version: 1,
        canonical_bytes: authority.canonical_bytes()?,
    })
}

fn identity_record(
    relationship_id: FederationRelationshipId,
    owner: FederationIdentityOwner,
    generation: u64,
    certificate_fingerprint: [u8; 32],
    verifying_key: [u8; 32],
) -> FederationTrustIdentityRecord {
    FederationTrustIdentityRecord {
        relationship_id,
        owner,
        identity: FederationTrustIdentity {
            generation,
            certificate_fingerprint,
            verifying_key,
            valid_from: UnixMicros::new(1),
            valid_until: UnixMicros::new(1_000),
        },
        revision: Revision::new(2),
    }
}

fn grant_payload(
    authority: &FederationConnectionAuthority,
    seed: u8,
    revision: u64,
) -> Result<VersionedPayload, Box<dyn std::error::Error>> {
    let restrictions = restrictions(authority)?;
    let policies = restrictions
        .iter()
        .map(|restriction| restriction.policy)
        .collect::<Vec<_>>();
    let record = FederationGrantRecord {
        grant: FederationGrant::new(
            grant_id(seed)?,
            authority.peer.relationship_id,
            FederatedPrincipal::new(authority.peer.local_mesh_id, principal(seed)?),
            FederationResourceScope::StorageCapacity {
                provider_mesh_id: authority.peer.remote_mesh_id,
            },
            FederationPolicy::intersect(&policies)?,
            authority.peer.authority_epoch,
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
    };
    Ok(VersionedPayload {
        format_version: 1,
        canonical_bytes: record.canonical_bytes()?,
    })
}

fn restrictions(
    authority: &FederationConnectionAuthority,
) -> Result<Vec<FederationGrantRestriction>, Box<dyn std::error::Error>> {
    let mut restrictions = vec![
        FederationGrantRestriction {
            imposing_mesh_id: authority.peer.local_mesh_id,
            policy: storage_policy(100, true)?,
        },
        FederationGrantRestriction {
            imposing_mesh_id: authority.peer.remote_mesh_id,
            policy: storage_policy(50, false)?,
        },
    ];
    restrictions.sort_by_key(|restriction| restriction.imposing_mesh_id);
    Ok(restrictions)
}

fn storage_policy(
    maximum_bytes: u64,
    protects: bool,
) -> Result<FederationPolicy, Box<dyn std::error::Error>> {
    Ok(FederationPolicy::Storage(StorageFederationPolicy::new(
        maximum_bytes,
        StorageParticipation::new(protects, true),
        Some(DurationMicros::new(100)),
    )?))
}

fn relationship_id() -> Result<FederationRelationshipId, Box<dyn std::error::Error>> {
    Ok(FederationRelationshipId::from_bytes([10; 16])?)
}

fn mesh(seed: u8) -> Result<MeshId, Box<dyn std::error::Error>> {
    Ok(MeshId::from_bytes([seed; 16])?)
}

fn grant_id(seed: u8) -> Result<FederationGrantId, Box<dyn std::error::Error>> {
    Ok(FederationGrantId::from_bytes([seed; 16])?)
}

fn principal(seed: u8) -> Result<PrincipalId, Box<dyn std::error::Error>> {
    Ok(PrincipalId::from_bytes([seed; 16])?)
}
