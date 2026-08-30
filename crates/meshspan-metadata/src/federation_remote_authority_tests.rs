// SPDX-License-Identifier: GPL-2.0-only

use ed25519_dalek::SigningKey;
use meshspan_domain::{
    DurationMicros, FederationGrant, FederationGrantId, FederationGrantRoute, FederationPolicy,
    FederationRelationshipId, FederationRelationshipKind, FederationResourceScope, MeshId, NodeId,
    Revision, StorageFederationPolicy, StorageParticipation, UnixMicros,
};
use tempfile::TempDir;

use super::{
    CacheFault, FederationRemoteAuthorityCacheDisposition, FederationRemoteAuthorityCacheError,
    FederationRemoteAuthoritySnapshot, install,
};
use crate::{
    FederationGovernanceDirection, FederationGrantRecord, FederationGrantRestriction,
    FederationGrantState, FederationIdentityOwner, FederationRelationshipRecord,
    FederationRelationshipState, FederationTransportAuthority, FederationTrustIdentity,
    FederationTrustIdentityRecord, LocalDatabase,
};

#[test]
fn cache_applies_delta_replays_exactly_and_survives_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let database_path = directory.path().join("local.sqlite3");
    let node_id = node(1)?;
    let mut database = LocalDatabase::open(&database_path, node_id, UnixMicros::new(1))?;
    let initial = snapshot(Revision::ZERO, 5, 3, &[(20, 4)])?;

    assert_eq!(
        database.install_remote_federation_authority(&initial, UnixMicros::new(10))?,
        FederationRemoteAuthorityCacheDisposition::Applied
    );
    assert_eq!(
        database.remote_federation_authority_revision(relationship_id()?)?,
        Revision::new(5)
    );
    assert_eq!(
        database.install_remote_federation_authority(&initial, UnixMicros::new(11))?,
        FederationRemoteAuthorityCacheDisposition::Replayed
    );
    let delta = snapshot(Revision::new(5), 8, 3, &[(21, 7)])?;
    assert_eq!(
        database.install_remote_federation_authority(&delta, UnixMicros::new(12))?,
        FederationRemoteAuthorityCacheDisposition::Applied
    );
    let cached = database
        .remote_federation_authority(relationship_id()?)?
        .ok_or("cache missing")?;
    assert_eq!(cached.authority_revision, Revision::new(8));
    assert_eq!(
        database.remote_federation_authority_revision(relationship_id()?)?,
        Revision::new(8)
    );
    assert_eq!(cached.observed_at, UnixMicros::new(12));
    assert_eq!(
        cached
            .grants
            .iter()
            .map(|record| record.grant.grant_id())
            .collect::<Vec<_>>(),
        vec![grant_id(20)?, grant_id(21)?]
    );
    let exact = database
        .remote_federation_grant_authority(relationship_id()?, grant_id(21)?)?
        .ok_or("exact cached grant missing")?;
    assert_eq!(exact.authority_revision, Revision::new(8));
    assert_eq!(exact.grant, cached.grants[1]);
    assert_eq!(exact.relationship, cached.relationship);
    assert!(
        database
            .remote_federation_grant_authority(relationship_id()?, grant_id(99)?)?
            .is_none()
    );
    drop(database);

    let reopened = LocalDatabase::open(&database_path, node_id, UnixMicros::new(13))?;
    assert_eq!(
        reopened
            .remote_federation_authority(relationship_id()?)?
            .ok_or("reopened cache missing")?,
        cached
    );
    Ok(())
}

#[test]
fn cache_rejects_stale_and_changed_replay_input() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let mut database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        node(2)?,
        UnixMicros::new(1),
    )?;
    let initial = snapshot(Revision::ZERO, 5, 3, &[(20, 4)])?;
    database.install_remote_federation_authority(&initial, UnixMicros::new(10))?;

    let stale = snapshot(Revision::new(4), 8, 3, &[(21, 7)])?;
    assert!(matches!(
        database.install_remote_federation_authority(&stale, UnixMicros::new(11)),
        Err(FederationRemoteAuthorityCacheError::StaleRevision)
    ));
    let mut changed_replay = initial;
    changed_replay.relationship.relationship.remote_display_name = "Changed replay".to_owned();
    assert!(matches!(
        database.install_remote_federation_authority(&changed_replay, UnixMicros::new(12)),
        Err(FederationRemoteAuthorityCacheError::Conflict)
    ));
    Ok(())
}

#[test]
fn transaction_rolls_back_at_each_deterministic_interruption()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let mut database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        node(3)?,
        UnixMicros::new(1),
    )?;
    let initial = snapshot(Revision::ZERO, 5, 3, &[(20, 4)])?;
    database.install_remote_federation_authority(&initial, UnixMicros::new(10))?;
    let before = database
        .remote_federation_authority(relationship_id()?)?
        .ok_or("cache missing")?;
    let delta = snapshot(Revision::new(5), 8, 3, &[(21, 7)])?;

    for fault in [CacheFault::AfterRelationship, CacheFault::AfterGrants] {
        assert!(matches!(
            install(&mut database, &delta, UnixMicros::new(11), Some(fault)),
            Err(FederationRemoteAuthorityCacheError::InjectedFault)
        ));
        assert_eq!(
            database
                .remote_federation_authority(relationship_id()?)?
                .ok_or("cache disappeared")?,
            before
        );
    }
    Ok(())
}

#[test]
fn authority_epoch_change_atomically_discards_old_epoch_grants()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let mut database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        node(4)?,
        UnixMicros::new(1),
    )?;
    database.install_remote_federation_authority(
        &snapshot(Revision::ZERO, 5, 3, &[(20, 4)])?,
        UnixMicros::new(10),
    )?;
    database.install_remote_federation_authority(
        &snapshot(Revision::new(5), 8, 4, &[(21, 7)])?,
        UnixMicros::new(11),
    )?;

    let cached = database
        .remote_federation_authority(relationship_id()?)?
        .ok_or("cache missing")?;
    assert_eq!(cached.relationship.relationship.authority_epoch, 4);
    assert_eq!(cached.grants.len(), 1);
    assert_eq!(cached.grants[0].grant.grant_id(), grant_id(21)?);
    Ok(())
}

#[test]
fn cache_reads_fail_closed_on_persisted_byte_or_key_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let mut database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        node(5)?,
        UnixMicros::new(1),
    )?;
    database.install_remote_federation_authority(
        &snapshot(Revision::ZERO, 5, 3, &[(20, 4)])?,
        UnixMicros::new(10),
    )?;
    database.connection().execute(
        "UPDATE local_federation_authority_grants SET record_bytes = zeroblob(4)",
        [],
    )?;
    assert!(matches!(
        database.remote_federation_authority(relationship_id()?),
        Err(FederationRemoteAuthorityCacheError::Corrupt)
    ));

    database.install_remote_federation_authority(
        &snapshot(Revision::new(5), 8, 3, &[(20, 7)])?,
        UnixMicros::new(11),
    )?;
    database.connection().execute(
        "UPDATE local_federation_authority_snapshots SET relationship_digest = zeroblob(32)",
        [],
    )?;
    assert!(matches!(
        database.remote_federation_authority(relationship_id()?),
        Err(FederationRemoteAuthorityCacheError::Corrupt)
    ));
    Ok(())
}

#[test]
fn exact_grant_read_uses_the_relationship_grant_primary_key()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let mut database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        node(6)?,
        UnixMicros::new(1),
    )?;
    database.install_remote_federation_authority(
        &snapshot(Revision::ZERO, 5, 3, &[(20, 4)])?,
        UnixMicros::new(10),
    )?;
    let detail: String = database.connection().query_row(
        "EXPLAIN QUERY PLAN
         SELECT grant_id, record_revision, record_bytes, record_digest
         FROM local_federation_authority_grants
         WHERE relationship_id = ?1 AND grant_id = ?2",
        rusqlite::params![
            relationship_id()?.as_bytes().as_slice(),
            grant_id(20)?.as_bytes().as_slice(),
        ],
        |row| row.get(3),
    )?;
    assert!(
        detail.contains("sqlite_autoindex_local_federation_authority_grants_1"),
        "{detail}"
    );
    Ok(())
}

fn snapshot(
    after_revision: Revision,
    authority_revision: u64,
    authority_epoch: u64,
    grants: &[(u8, u64)],
) -> Result<FederationRemoteAuthoritySnapshot, Box<dyn std::error::Error>> {
    let relationship_id = relationship_id()?;
    let local_mesh_id = mesh(2)?;
    let remote_mesh_id = mesh(1)?;
    Ok(FederationRemoteAuthoritySnapshot {
        after_revision,
        authority_revision: Revision::new(authority_revision),
        relationship: FederationTransportAuthority {
            authority_revision: Revision::new(authority_revision),
            relationship: FederationRelationshipRecord {
                relationship_id,
                local_mesh_id,
                remote_mesh_id,
                kind: FederationRelationshipKind::Horizontal,
                governance_direction: FederationGovernanceDirection::None,
                state: FederationRelationshipState::Active,
                authority_epoch,
                remote_display_name: "Local swarm".to_owned(),
                revision: Revision::new(after_revision.get().saturating_add(1)),
            },
            local_identity: identity(relationship_id, FederationIdentityOwner::Local, 4),
            remote_identity: identity(relationship_id, FederationIdentityOwner::Remote, 7),
        },
        grants: grants
            .iter()
            .map(|(seed, revision)| {
                grant_record(
                    relationship_id,
                    local_mesh_id,
                    remote_mesh_id,
                    authority_epoch,
                    *seed,
                    *revision,
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn identity(
    relationship_id: FederationRelationshipId,
    owner: FederationIdentityOwner,
    seed: u8,
) -> FederationTrustIdentityRecord {
    FederationTrustIdentityRecord {
        relationship_id,
        owner,
        identity: FederationTrustIdentity {
            generation: u64::from(seed),
            certificate_fingerprint: [seed; 32],
            verifying_key: SigningKey::from_bytes(&[seed.saturating_add(1); 32])
                .verifying_key()
                .to_bytes(),
            valid_from: UnixMicros::new(1),
            valid_until: UnixMicros::new(1_000),
        },
        revision: Revision::new(2),
    }
}

fn grant_record(
    relationship_id: FederationRelationshipId,
    local_mesh_id: MeshId,
    remote_mesh_id: MeshId,
    authority_epoch: u64,
    seed: u8,
    revision: u64,
) -> Result<FederationGrantRecord, Box<dyn std::error::Error>> {
    let mut restrictions = vec![
        FederationGrantRestriction {
            imposing_mesh_id: local_mesh_id,
            policy: storage_policy(50, false)?,
        },
        FederationGrantRestriction {
            imposing_mesh_id: remote_mesh_id,
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
            grant_id(seed)?,
            relationship_id,
            FederationGrantRoute::direct(local_mesh_id, remote_mesh_id)?,
            None,
            FederationResourceScope::StorageCapacity {
                provider_mesh_id: local_mesh_id,
            },
            FederationPolicy::intersect(&policies)?,
            authority_epoch,
            UnixMicros::new(10),
            Some(UnixMicros::new(100)),
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
        false,
        Some(DurationMicros::new(100)),
    )?))
}

fn relationship_id() -> Result<FederationRelationshipId, Box<dyn std::error::Error>> {
    Ok(FederationRelationshipId::from_bytes([10; 16])?)
}

fn mesh(seed: u8) -> Result<MeshId, Box<dyn std::error::Error>> {
    Ok(MeshId::from_bytes([seed; 16])?)
}

fn node(seed: u8) -> Result<NodeId, Box<dyn std::error::Error>> {
    Ok(NodeId::from_bytes([seed; 16])?)
}

fn grant_id(seed: u8) -> Result<FederationGrantId, Box<dyn std::error::Error>> {
    Ok(FederationGrantId::from_bytes([seed; 16])?)
}
