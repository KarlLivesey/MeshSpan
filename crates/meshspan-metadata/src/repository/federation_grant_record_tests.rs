// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    DurationMicros, FederationAccess, FederationGrant, FederationGrantId, FederationGrantRoute,
    FederationPolicy, FederationRelationshipId, FederationResourceScope, MeshId,
    NamespaceFederationPolicy, ObjectId, Revision, Rights, StorageFederationPolicy,
    StorageParticipation, UnixMicros, VolumeId,
};

use super::{FederationGrantRecord, FederationGrantRecordCodecError};
use crate::{
    FederationGrantRestriction, FederationGrantState, FederationGrantTermination,
    FederationGrantTerminationKind,
};

#[test]
fn namespace_and_storage_records_have_one_canonical_round_trip()
-> Result<(), Box<dyn std::error::Error>> {
    for record in [namespace_record()?, storage_record()?] {
        let encoded = record.canonical_bytes()?;
        assert_eq!(
            FederationGrantRecord::from_canonical_bytes(&encoded)?,
            record
        );
        assert_eq!(record.canonical_bytes()?, encoded);
    }
    Ok(())
}

#[test]
fn malformed_and_unknown_records_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = namespace_record()?.canonical_bytes()?;
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_invalid(&trailing);
    assert_invalid(&encoded[..encoded.len() - 1]);
    let mut wrong_domain = encoded.clone();
    wrong_domain[0] ^= 1;
    assert_invalid(&wrong_domain);
    let mut unknown_version = encoded;
    let version_offset = b"meshspan.federation.grant-authority".len() + 1;
    unknown_version[version_offset] = 3;
    assert_eq!(
        FederationGrantRecord::from_canonical_bytes(&unknown_version),
        Err(FederationGrantRecordCodecError::UnsupportedVersion)
    );
    Ok(())
}

#[test]
fn wire_policy_substitution_cannot_broaden_effective_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let record = namespace_record()?;
    let mut encoded = record.canonical_bytes()?;
    let remote = record.restrictions[1].imposing_mesh_id.as_bytes();
    let restriction_offset = encoded
        .windows(remote.len())
        .rposition(|window| window == remote)
        .ok_or("remote restriction missing")?;
    let rights_offset = restriction_offset + remote.len() + 1;
    encoded[rights_offset..rights_offset + 4].copy_from_slice(&Rights::ALL.bits().to_be_bytes());
    assert_invalid(&encoded);
    Ok(())
}

#[test]
fn authority_broadening_and_lifecycle_substitution_fail_before_encoding()
-> Result<(), Box<dyn std::error::Error>> {
    let mut record = namespace_record()?;
    record.restrictions[1].policy = namespace_policy(Rights::ALL, true, 500);
    assert_eq!(
        record.canonical_bytes(),
        Err(FederationGrantRecordCodecError::Invalid)
    );

    let mut record = storage_record()?;
    record.termination = None;
    assert_eq!(
        record.canonical_bytes(),
        Err(FederationGrantRecordCodecError::Invalid)
    );

    let mut record = namespace_record()?;
    record.restrictions.swap(0, 1);
    assert_eq!(
        record.canonical_bytes(),
        Err(FederationGrantRecordCodecError::Invalid)
    );
    Ok(())
}

fn namespace_record() -> Result<FederationGrantRecord, Box<dyn std::error::Error>> {
    let local = mesh(1)?;
    let remote = mesh(2)?;
    let restrictions = vec![
        FederationGrantRestriction {
            imposing_mesh_id: local,
            policy: namespace_policy(Rights::ALL, true, 500),
        },
        FederationGrantRestriction {
            imposing_mesh_id: remote,
            policy: namespace_policy(Rights::READ_DATA, false, 200),
        },
    ];
    let policy = intersect(&restrictions)?;
    Ok(FederationGrantRecord {
        grant: FederationGrant::new(
            grant_id(3)?,
            relationship(4)?,
            FederationGrantRoute::direct(remote, local)?,
            None,
            FederationResourceScope::File {
                owner_mesh_id: remote,
                volume_id: volume(6)?,
                object_id: object(7)?,
            },
            policy,
            8,
            UnixMicros::new(100),
            Some(UnixMicros::new(300)),
        )?,
        restrictions,
        state: FederationGrantState::Active,
        issued_at: UnixMicros::new(90),
        termination: None,
        predecessor_grant_id: Some(grant_id(9)?),
        successor_grant_id: None,
        revision: Revision::new(10),
    })
}

fn storage_record() -> Result<FederationGrantRecord, Box<dyn std::error::Error>> {
    let local = mesh(11)?;
    let remote = mesh(12)?;
    let restrictions = vec![
        FederationGrantRestriction {
            imposing_mesh_id: local,
            policy: storage_policy(100, true, true, 500)?,
        },
        FederationGrantRestriction {
            imposing_mesh_id: remote,
            policy: storage_policy(50, false, true, 200)?,
        },
    ];
    let policy = intersect(&restrictions)?;
    Ok(FederationGrantRecord {
        grant: FederationGrant::new(
            grant_id(13)?,
            relationship(14)?,
            FederationGrantRoute::direct(remote, local)?,
            None,
            FederationResourceScope::StorageCapacity {
                provider_mesh_id: remote,
            },
            policy,
            16,
            UnixMicros::new(100),
            Some(UnixMicros::new(300)),
        )?,
        restrictions,
        state: FederationGrantState::Revoked,
        issued_at: UnixMicros::new(90),
        termination: Some(FederationGrantTermination {
            kind: FederationGrantTerminationKind::Restricted,
            reason: Some("Reduced remote capacity".to_owned()),
            terminated_at: UnixMicros::new(250),
            revision: Revision::new(18),
        }),
        predecessor_grant_id: None,
        successor_grant_id: Some(grant_id(17)?),
        revision: Revision::new(18),
    })
}

fn namespace_policy(
    rights: Rights,
    allows_downstream_delegation: bool,
    offline_micros: u64,
) -> FederationPolicy {
    FederationPolicy::Namespace(NamespaceFederationPolicy::new(
        FederationAccess::new(rights, allows_downstream_delegation),
        Some(DurationMicros::new(offline_micros)),
    ))
}

fn storage_policy(
    bytes: u64,
    protects: bool,
    serves_reads: bool,
    offline_micros: u64,
) -> Result<FederationPolicy, Box<dyn std::error::Error>> {
    Ok(FederationPolicy::Storage(StorageFederationPolicy::new(
        bytes,
        StorageParticipation::new(protects, serves_reads),
        false,
        Some(DurationMicros::new(offline_micros)),
    )?))
}

fn intersect(
    restrictions: &[FederationGrantRestriction],
) -> Result<FederationPolicy, Box<dyn std::error::Error>> {
    let policies = restrictions
        .iter()
        .map(|restriction| restriction.policy)
        .collect::<Vec<_>>();
    Ok(FederationPolicy::intersect(&policies)?)
}

fn assert_invalid(bytes: &[u8]) {
    assert_eq!(
        FederationGrantRecord::from_canonical_bytes(bytes),
        Err(FederationGrantRecordCodecError::Invalid)
    );
}

fn mesh(seed: u8) -> Result<MeshId, Box<dyn std::error::Error>> {
    Ok(MeshId::from_bytes([seed; 16])?)
}

fn relationship(seed: u8) -> Result<FederationRelationshipId, Box<dyn std::error::Error>> {
    Ok(FederationRelationshipId::from_bytes([seed; 16])?)
}

fn grant_id(seed: u8) -> Result<FederationGrantId, Box<dyn std::error::Error>> {
    Ok(FederationGrantId::from_bytes([seed; 16])?)
}

fn volume(seed: u8) -> Result<VolumeId, Box<dyn std::error::Error>> {
    Ok(VolumeId::from_bytes([seed; 16])?)
}

fn object(seed: u8) -> Result<ObjectId, Box<dyn std::error::Error>> {
    Ok(ObjectId::from_bytes([seed; 16])?)
}
