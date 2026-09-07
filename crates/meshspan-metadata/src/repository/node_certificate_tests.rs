// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{NodeId, PartitionId, PrincipalId, Revision, UnixMicros};
use rusqlite::params;
use sha2::{Digest as _, Sha256};

use super::{AuthoritativeRepository, tests::bootstrap_snapshot_repository};
use crate::PartitionDatabase;

#[test]
fn active_certificate_projection_keeps_its_exact_generation_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let file_path = directory.path().join("authority.sqlite3");
    let partition = PartitionId::from_bytes([11; 16])?;
    let node = NodeId::from_bytes([12; 16])?;
    let database = PartitionDatabase::open(&file_path, partition, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap_snapshot_repository(&mut repository, PrincipalId::from_bytes([13; 16])?, node)?;
    let database = repository.into_database();
    database.connection().execute(
        "UPDATE nodes SET state = 2 WHERE node_id = ?1",
        [node.as_bytes().as_slice()],
    )?;
    // This is a projection fixture, not an issuance operation: two active generations and a
    // higher retired generation ensure the query restores the selected row, not a constant.
    for generation in [1_i64, 2, 3] {
        let der = generation.to_le_bytes().to_vec();
        database.connection().execute(
            "INSERT INTO node_certificates(node_id, generation, certificate_der,
             certificate_fingerprint, valid_from, valid_until, state, revision)
             VALUES (?1, ?2, ?3, ?4, 10, ?5, ?6, ?2)",
            params![
                node.as_bytes().as_slice(),
                generation,
                &der,
                Sha256::digest(&der).as_slice(),
                50 + generation,
                if generation == 3 { 3 } else { 1 }
            ],
        )?;
    }
    let repository = AuthoritativeRepository::new(database);
    let selected = repository
        .active_node_certificate(node)?
        .ok_or("certificate missing")?;
    assert_eq!(selected.generation, 2);
    assert_eq!(selected.revision, Revision::new(2));
    assert_eq!(selected.incarnation, 1);
    assert_eq!(selected.valid_until, UnixMicros::new(52));
    assert_eq!(selected.certificate_der, 2_i64.to_le_bytes());
    drop(repository);
    let reopened = AuthoritativeRepository::new(PartitionDatabase::open(
        &file_path,
        partition,
        UnixMicros::new(20),
    )?);
    assert_eq!(reopened.active_node_certificate(node)?, Some(selected));
    Ok(())
}
