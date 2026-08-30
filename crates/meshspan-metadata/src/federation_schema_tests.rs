// SPDX-License-Identifier: GPL-2.0-only

//! Hostile relational proofs for authoritative federation records.

use meshspan_domain::{PartitionId, UnixMicros};
use rusqlite::params;
use tempfile::tempdir;

use crate::PartitionDatabase;

#[test]
fn relationship_shape_and_live_peer_uniqueness_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    fixture.insert_mesh()?;

    assert!(
        fixture
            .insert_relationship([1; 16], fixture.local_mesh, 1, 0)
            .is_err()
    );
    assert!(fixture.insert_relationship([2; 16], [2; 16], 1, 1).is_err());
    fixture.insert_relationship([3; 16], [2; 16], 1, 0)?;
    assert!(fixture.insert_relationship([4; 16], [2; 16], 1, 0).is_err());
    Ok(())
}

#[test]
fn grant_policy_shapes_and_quarantine_evidence_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    fixture.insert_mesh()?;
    let relationship = [3_u8; 16];
    let remote = [2_u8; 16];
    fixture.insert_relationship(relationship, remote, 1, 0)?;
    let grant = [4_u8; 16];
    fixture.database.connection().execute(
        "INSERT INTO federation_grants(
            grant_id, relationship_id, issuer_mesh_id, recipient_mesh_id,
            upstream_grant_id, route_depth,
            resource_kind, authority_mesh_id, volume_id, object_id, authority_epoch,
            valid_from, valid_until, state, effective_policy_digest, issued_at,
            revoked_at, revision
         ) VALUES (?1, ?2, ?3, ?4, NULL, 0, 4, ?3, NULL, NULL, 1,
                   10, 20, 1, ?5, 10, NULL, 1)",
        params![
            grant.as_slice(),
            relationship.as_slice(),
            remote.as_slice(),
            fixture.local_mesh.as_slice(),
            [6_u8; 32].as_slice(),
        ],
    )?;
    fixture.insert_grant_route(grant, remote, fixture.local_mesh)?;

    let mixed_policy = fixture.database.connection().execute(
        "INSERT INTO federation_grant_restrictions(
            grant_id, imposing_mesh_id, policy_kind, rights, allows_downstream_delegation,
            maximum_storage_bytes, counts_towards_protection, serves_reads,
            maximum_offline_micros, policy_digest, revision
         ) VALUES (?1, ?2, 2, 1, NULL, 100, 1, 1, 10, ?3, 1)",
        params![grant.as_slice(), remote.as_slice(), [7_u8; 32].as_slice()],
    );
    assert!(mixed_policy.is_err());

    fixture.database.connection().execute(
        "INSERT INTO federation_grant_restrictions(
            grant_id, imposing_mesh_id, policy_kind, rights, allows_downstream_delegation,
            maximum_storage_bytes, counts_towards_protection, serves_reads,
            maximum_offline_micros, policy_digest, revision
         ) VALUES (?1, ?2, 2, NULL, 0, 100, 1, 0, 10, ?3, 1)",
        params![grant.as_slice(), remote.as_slice(), [7_u8; 32].as_slice()],
    )?;
    let quarantine = [8_u8; 16];
    fixture.database.connection().execute(
        "INSERT INTO federation_quarantine(
            quarantine_id, relationship_id, operation_id, grant_id,
            subject_home_mesh_id, subject_principal_id, accepted_at, reason_kind,
            payload_digest, acknowledgement_digest, state, surfaced_at, resolved_at,
            resolution_kind, resolution_operation_id, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 12, 3, ?7, ?8, 1,
                   NULL, NULL, NULL, NULL, 1)",
        params![
            quarantine.as_slice(),
            relationship.as_slice(),
            [9_u8; 16].as_slice(),
            grant.as_slice(),
            fixture.local_mesh.as_slice(),
            [5_u8; 16].as_slice(),
            [10_u8; 32].as_slice(),
            [11_u8; 32].as_slice(),
        ],
    )?;
    assert!(
        fixture
            .database
            .connection()
            .execute(
                "UPDATE federation_quarantine SET payload_digest = ?1 WHERE quarantine_id = ?2",
                params![[12_u8; 32].as_slice(), quarantine.as_slice()],
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn succession_identity_and_partial_lifecycle_rows_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    fixture.insert_mesh()?;
    let relationship = [3_u8; 16];
    let remote = [2_u8; 16];
    fixture.insert_relationship(relationship, remote, 1, 0)?;
    let insert = |successor: [u8; 16], state: i64, acceptance: Option<[u8; 32]>| {
        fixture.database.connection().execute(
            "INSERT INTO federation_ownership_successions(
                succession_id, relationship_id, retiring_mesh_id, successor_mesh_id,
                relationship_authority_epoch, succession_epoch, designation_digest,
                designation_signer_generation, designation_signature, acceptance_digest,
                acceptance_signer_generation, acceptance_signature, activation_digest,
                state, designated_at, accepted_at, activated_at, revoked_at, revision
             ) VALUES (?1, ?2, ?3, ?4, 1, 1, ?5, 1, ?6, ?7,
                       NULL, NULL, NULL, ?8, 1, NULL, NULL, NULL, 1)",
            params![
                [30_u8; 16].as_slice(),
                relationship.as_slice(),
                remote.as_slice(),
                successor.as_slice(),
                [31_u8; 32].as_slice(),
                [32_u8; 64].as_slice(),
                acceptance.as_ref().map(<[u8; 32]>::as_slice),
                state,
            ],
        )
    };
    assert!(insert(remote, 1, None).is_err());
    assert!(insert(fixture.local_mesh, 2, Some([33; 32])).is_err());
    insert(fixture.local_mesh, 1, None)?;
    assert!(
        fixture
            .database
            .connection()
            .execute(
                "UPDATE federation_ownership_successions SET retiring_mesh_id = ?1
                 WHERE succession_id = ?2",
                params![fixture.local_mesh.as_slice(), [30_u8; 16].as_slice()],
            )
            .is_err()
    );
    Ok(())
}

struct Fixture {
    _directory: tempfile::TempDir,
    database: PartitionDatabase,
    local_mesh: [u8; 16],
}

impl Fixture {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let database = PartitionDatabase::open(
            &directory.path().join("federation.sqlite3"),
            PartitionId::from_bytes([20; 16])?,
            UnixMicros::new(1),
        )?;
        Ok(Self {
            _directory: directory,
            database,
            local_mesh: [1; 16],
        })
    }

    fn insert_mesh(&self) -> Result<(), rusqlite::Error> {
        self.database.connection().execute(
            "INSERT INTO meshes(
                mesh_id, display_name, canonical_name, created_at,
                configuration_revision, identity_revision, namespace_revision, revision
             ) VALUES (?1, 'Local', 'local', 1, 1, 1, 1, 1)",
            [self.local_mesh.as_slice()],
        )?;
        Ok(())
    }

    fn insert_relationship(
        &self,
        relationship: [u8; 16],
        remote: [u8; 16],
        kind: i64,
        direction: i64,
    ) -> Result<(), rusqlite::Error> {
        self.database.connection().execute(
            "INSERT INTO federation_relationships(
                relationship_id, local_mesh_id, remote_mesh_id, relationship_kind,
                governance_direction, state, authority_epoch, remote_display_name,
                proposed_at, approved_at, restricted_at, revoked_at, retired_at, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 1, 'Remote', 1,
                       NULL, NULL, NULL, NULL, 1)",
            params![
                relationship.as_slice(),
                self.local_mesh.as_slice(),
                remote.as_slice(),
                kind,
                direction,
            ],
        )?;
        Ok(())
    }

    fn insert_grant_route(
        &self,
        grant: [u8; 16],
        issuer: [u8; 16],
        recipient: [u8; 16],
    ) -> Result<(), rusqlite::Error> {
        for (hop_index, mesh_id) in [(0_i64, issuer), (1_i64, recipient)] {
            self.database.connection().execute(
                "INSERT INTO federation_grant_route_hops(grant_id, hop_index, mesh_id, revision)
                 VALUES (?1, ?2, ?3, 1)",
                params![grant.as_slice(), hop_index, mesh_id.as_slice()],
            )?;
        }
        Ok(())
    }
}
