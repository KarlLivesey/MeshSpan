// SPDX-License-Identifier: GPL-2.0-only

//! Founding-node discovery must survive a joined gateway's process restart.

use super::*;

#[test]
fn founding_node_endpoint_is_atomic_durable_and_replay_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let database_path = directory.path().join("authority.sqlite3");
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let database = PartitionDatabase::open(&database_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    let (context, mut command) = fixture(partition_id)?;
    set_endpoint(&mut command, "files.example.test:9412")?;
    repository.apply_committed(LogPosition { index: 1, term: 1 }, context, &command)?;
    drop(repository);
    let mut repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &database_path,
        UnixMicros::new(20),
    )?);
    let page = repository.topology_nodes(None, super::super::PageLimit::new(8)?)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(
        page.items[0].private_endpoint.as_deref(),
        Some("files.example.test:9412")
    );
    assert!(repository.database.connection().execute(
        "INSERT INTO node_activations(node_id, incarnation, private_endpoint, capability_digest, activated_at, revision)
         VALUES (?1, 1, 'files.example.test:9412', ?2, 20, 2)",
        rusqlite::params![page.items[0].node_id.as_bytes().as_slice(), [7_u8; 32].as_slice()],
    ).is_err(), "an activation must not steal the founding node's endpoint");
    let replay =
        repository.apply_committed(LogPosition { index: 2, term: 1 }, context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    set_endpoint(&mut command, "elsewhere.example.test:9412")?;
    assert!(
        repository
            .apply_committed(LogPosition { index: 3, term: 1 }, context, &command)
            .is_err()
    );
    Ok(())
}

#[test]
fn malformed_founding_endpoints_reject_the_entire_bootstrap()
-> Result<(), Box<dyn std::error::Error>> {
    for endpoint in [
        "",
        "0.0.0.0:9412",
        "[::]:9412",
        "host:0",
        "host:65536",
        "host:port",
        "host\n:9412",
        "https://host:9412",
        "-host:9412",
    ] {
        let directory = tempdir()?;
        let partition_id = PartitionId::from_bytes([1; 16])?;
        let database = PartitionDatabase::open(
            &directory.path().join("authority.sqlite3"),
            partition_id,
            UnixMicros::new(1),
        )?;
        let mut repository = AuthoritativeRepository::new(database);
        let (context, mut command) = fixture(partition_id)?;
        set_endpoint(&mut command, endpoint)?;
        assert!(
            matches!(
                repository.apply_committed(LogPosition { index: 1, term: 1 }, context, &command),
                Err(RepositoryError::InvalidCommand)
            ),
            "accepted {endpoint:?}"
        );
        assert_eq!(repository.local_mesh_id()?, None);
    }
    Ok(())
}

fn set_endpoint(
    command: &mut AuthoritativeCommand,
    endpoint: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let AuthoritativeCommand::BootstrapAppliance(bootstrap) = command else {
        return Err("wrong fixture command".into());
    };
    bootstrap.private_endpoint = Some(endpoint.to_owned());
    Ok(())
}
