// SPDX-License-Identifier: GPL-2.0-only

//! Public HTTP proof projection, exact cleanup and migration of in-flight publications.

use super::*;
use meshspan_acme::{
    AcmeAuthorization, AcmeChallengePublication, AcmeChallengeRecord, AcmeDirectory,
    AcmeMachineEvent, AcmeOrder, AcmeResourceStatus, Http01Challenge, Http01Payload,
};
use meshspan_contracts::{
    BoundedBytes, CertificateChallenge as _, CertificateChallengeKind, CertificateChallengeRequest,
    ContractVersion, RequestContext,
};

const TOKEN: &str = "token-1";
const BODY: &[u8] = b"token-1.account-thumbprint";

#[test]
fn http01_projection_requires_publication_and_withdraws_before_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, mut machine, mut command) = prepared(Fixture::new()?)?;
    save(&mut fixture, &mut command, &machine, 6)?;
    assert_eq!(
        fixture
            .repository
            .public_http01_response(TOKEN, UnixMicros::new(20))?,
        None
    );
    publish(&mut machine)?;
    save(&mut fixture, &mut command, &machine, 7)?;
    assert_eq!(
        fixture
            .repository
            .public_http01_response(TOKEN, UnixMicros::new(999))?,
        Some((BODY.to_vec(), UnixMicros::new(1000)))
    );
    assert_eq!(
        fixture
            .repository
            .public_http01_response(TOKEN, UnixMicros::new(1000))?,
        None
    );
    assert_eq!(
        fixture
            .repository
            .public_http01_response("another-token", UnixMicros::new(20))?,
        None
    );
    assert!(
        fixture
            .repository
            .public_http01_response("../token", UnixMicros::new(20))
            .is_err()
    );
    machine.advance(AcmeMachineEvent::ChallengeNotified {
        replay_nonce: "nonce-5".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::AuthorizationPolled {
        authorization: authorization(AcmeResourceStatus::Valid),
        replay_nonce: "nonce-6".to_owned(),
    })?;
    assert!(
        machine.publication().is_some(),
        "cleanup still needs original material"
    );
    save(&mut fixture, &mut command, &machine, 8)?;
    assert_eq!(
        fixture
            .repository
            .public_http01_response(TOKEN, UnixMicros::new(20))?,
        None
    );
    Ok(())
}

#[test]
fn http01_projection_rejects_corrupt_checkpoint_and_false_index_candidates()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, mut machine, mut command) = prepared(Fixture::new()?)?;
    publish(&mut machine)?;
    save(&mut fixture, &mut command, &machine, 6)?;
    fixture.repository.database.connection().execute(
        "UPDATE certificate_order_checkpoints SET http01_token = 'substituted'",
        [],
    )?;
    assert!(matches!(
        fixture
            .repository
            .public_http01_response("substituted", UnixMicros::new(20)),
        Err(RepositoryError::CorruptState)
    ));
    fixture.repository.database.connection().execute("UPDATE certificate_order_checkpoints SET http01_token = 'token-1', checkpoint_digest = zeroblob(32)", [])?;
    assert!(matches!(
        fixture
            .repository
            .public_http01_response(TOKEN, UnixMicros::new(20)),
        Err(RepositoryError::Sqlite(rusqlite::Error::InvalidQuery))
    ));
    Ok(())
}

#[test]
fn http01_lookup_uses_the_token_index() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let detail: String = fixture.repository.database.connection().query_row(
        "EXPLAIN QUERY PLAN SELECT order_id FROM certificate_order_checkpoints WHERE http01_token = ?1 LIMIT 2",
        [TOKEN], |row| row.get(3),
    )?;
    assert!(detail.contains("SEARCH certificate_order_checkpoints USING INDEX certificate_order_checkpoints_http01_token"), "{detail}");
    Ok(())
}

#[test]
fn schema_86_indexes_existing_publication_without_changing_its_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("partition.sqlite3");
    let source = directory.path().join("source.sqlite3");
    let (mut fixture, mut machine, mut command) = prepared(Fixture::at(&source)?)?;
    publish(&mut machine)?;
    save(&mut fixture, &mut command, &machine, 6)?;
    let previous = fixture
        .repository
        .certificate_order_checkpoint(command.order_id)?;
    drop(fixture);
    drop(schema_85_copy(&source, &database)?);
    let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &database,
        UnixMicros::new(30),
    )?);
    assert_eq!(
        repository.certificate_order_checkpoint(command.order_id)?,
        previous
    );
    assert_eq!(
        repository.public_http01_response(TOKEN, UnixMicros::new(30))?,
        Some((BODY.to_vec(), UnixMicros::new(1000)))
    );
    Ok(())
}

#[test]
fn corrupt_migration_rolls_back_schema_and_preserves_previous_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("source.sqlite3");
    let (mut fixture, mut machine, mut command) = prepared(Fixture::at(&source)?)?;
    publish(&mut machine)?;
    save(&mut fixture, &mut command, &machine, 6)?;
    drop(fixture);
    let mut connection = schema_85_copy(&source, &directory.path().join("partition.sqlite3"))?;
    connection.execute(
        "UPDATE certificate_order_checkpoints SET checkpoint_digest = zeroblob(32)",
        [],
    )?;
    assert!(crate::migration::migrate_partition(&mut connection, 30).is_err());
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 85);
    assert!(
        connection
            .prepare("SELECT http01_token FROM certificate_order_checkpoints")
            .is_err()
    );
    Ok(())
}

// Build the actual historical schema, then project the seeded ACME state into its columns.
// Rewinding only user_version on today's database leaves future tables behind and makes
// this migration fixture break whenever another unrelated migration is added.
fn schema_85_copy(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    let mut connection = rusqlite::Connection::open(destination)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    crate::migration::migrate_partition_through(&mut connection, 85, 1)?;
    connection.execute(
        "ATTACH DATABASE ?1 AS seed",
        [source.to_str().ok_or("fixture path")?],
    )?;
    let tables = connection
        .prepare(
            "SELECT name FROM main.sqlite_schema WHERE type = 'table'
         AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations' ORDER BY name",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let triggers = connection
        .prepare("SELECT name, sql FROM main.sqlite_schema WHERE type = 'trigger' ORDER BY name")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let quote = |name: &str| format!("\"{}\"", name.replace('"', "\"\""));
    let transaction = connection.transaction()?;
    transaction.pragma_update(None, "defer_foreign_keys", true)?;
    // The seed is a completed state, not a replay of individual domain commands. Restore
    // every historical trigger before committing and verify all foreign keys afterwards.
    for (name, _) in &triggers {
        transaction.execute_batch(&format!("DROP TRIGGER {}", quote(name)))?;
    }
    for table in tables {
        let columns = transaction
            .prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")?
            .query_map([&table], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .map(|name| quote(name))
            .collect::<Vec<_>>()
            .join(", ");
        let table = quote(&table);
        transaction.execute_batch(&format!(
            "DELETE FROM main.{table};
             INSERT INTO main.{table} ({columns}) SELECT {columns} FROM seed.{table}"
        ))?;
    }
    transaction.execute("UPDATE applied_state SET schema_version = 85", [])?;
    for (_, sql) in triggers {
        transaction.execute_batch(&sql)?;
    }
    transaction.commit()?;
    connection.execute_batch("DETACH DATABASE seed")?;
    assert_eq!(
        connection.pragma_query_value(None, "integrity_check", |row| row.get::<_, String>(0))?,
        "ok"
    );
    assert!(!connection.prepare("PRAGMA foreign_key_check")?.exists([])?);
    assert_eq!(
        connection.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'node_certificate_rotations'",
            [],
            |row| row.get::<_, u32>(0),
        )?,
        0
    );
    Ok(connection)
}

fn save(
    fixture: &mut Fixture,
    command: &mut CheckpointCertificateOrder,
    machine: &AcmeOrderMachine,
    revision: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    command.checkpoint = machine.encode_checkpoint()?;
    fixture.apply(
        revision,
        11,
        &AuthoritativeCommand::CheckpointCertificateOrder(command.clone()),
    )?;
    Ok(())
}

fn prepared(
    mut fixture: Fixture,
) -> Result<(Fixture, AcmeOrderMachine, CheckpointCertificateOrder), Box<dyn std::error::Error>> {
    let config_id = AcmeConfigurationId::from_bytes([70; 16])?;
    let order_id = CertificateOrderId::from_bytes([71; 16])?;
    let mut config = fixture.configuration(config_id)?;
    config.challenge_kind = AcmeChallengeKind::Http01;
    config.challenge_settings = None;
    config.certificate_names = BoundedItems::new(vec!["files.example.test".to_owned()], 256)?;
    fixture.apply(3, 2, &AuthoritativeCommand::ConfigureAcme(config))?;
    fixture.apply(
        4,
        10,
        &AuthoritativeCommand::QueueCertificateOrder(QueueCertificateOrder {
            order_id,
            config_id,
            next_attempt_at: UnixMicros::new(10),
        }),
    )?;
    fixture.apply(
        5,
        10,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 1, 707, 100)),
    )?;
    let certificate_key = SecretGenerationReference {
        secret_id: order_id.as_bytes(),
        generation: 1,
    };
    fixture.insert_secret(PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND, certificate_key)?;
    let command = CheckpointCertificateOrder {
        order_id,
        claim_generation: 1,
        worker_node_id: fixture.node,
        worker_incarnation: 1,
        fence: 707,
        certificate_key,
        checkpoint: Vec::new(),
    };
    Ok((fixture, prepared_machine()?, command))
}

fn prepared_machine() -> Result<AcmeOrderMachine, Box<dyn std::error::Error>> {
    let mut machine = AcmeOrderMachine::new(
        "https://acme.example.test/directory".to_owned(),
        AcmeOrderRequest::new(vec!["files.example.test".to_owned()])?,
        AcmeChallengePreference::Http01,
        707,
    )?;
    machine.advance(AcmeMachineEvent::DirectoryDiscovered(AcmeDirectory {
        new_nonce: "https://acme.example.test/nonce".to_owned(),
        new_account: "https://acme.example.test/account".to_owned(),
        new_order: "https://acme.example.test/new-order".to_owned(),
    }))?;
    machine.advance(AcmeMachineEvent::NonceAcquired("nonce-1".to_owned()))?;
    machine.advance(AcmeMachineEvent::AccountCreated {
        account_url: "https://acme.example.test/account/1".to_owned(),
        replay_nonce: "nonce-2".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::OrderCreated {
        order_url: "https://acme.example.test/order/1".to_owned(),
        order: AcmeOrder {
            status: AcmeResourceStatus::Pending,
            dns_names: vec!["files.example.test".to_owned()],
            authorizations: vec!["https://acme.example.test/authorization/1".to_owned()],
            finalize: "https://acme.example.test/finalize/1".to_owned(),
            certificate: None,
        },
        replay_nonce: "nonce-3".to_owned(),
    })?;
    machine.advance(AcmeMachineEvent::AuthorizationFetched {
        authorization: authorization(AcmeResourceStatus::Pending),
        replay_nonce: "nonce-4".to_owned(),
    })?;
    machine.retain_publication(AcmeChallengePublication::capture(&publication()?)?)?;
    Ok(machine)
}

fn publication() -> Result<CertificateChallengeRequest, Box<dyn std::error::Error>> {
    Ok(CertificateChallengeRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([8; 16])?,
            deadline: UnixMicros::new(100),
            expected_revision: Some(Revision::new(3)),
        },
        kind: CertificateChallengeKind::Http01,
        identifier: BoundedBytes::copy_from(b"files.example.test", 253)?,
        challenge: Http01Payload::new(TOKEN, BODY)?.encode()?,
        order_epoch: 707,
        expires_at: UnixMicros::new(1000),
    })
}

fn publish(machine: &mut AcmeOrderMachine) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = Http01Challenge::new().expected_receipt(&publication()?)?;
    machine.advance(AcmeMachineEvent::ChallengePublished {
        publication_digest: receipt.publication_digest,
    })?;
    Ok(())
}

fn authorization(status: AcmeResourceStatus) -> AcmeAuthorization {
    AcmeAuthorization {
        dns_name: "files.example.test".to_owned(),
        wildcard: false,
        status,
        challenges: vec![AcmeChallengeRecord {
            kind: "http-01".to_owned(),
            url: "https://acme.example.test/challenge/1".to_owned(),
            token: TOKEN.to_owned(),
            status,
        }],
    }
}
