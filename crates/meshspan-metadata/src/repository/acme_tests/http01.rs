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
    let (mut fixture, mut machine, mut command) = prepared(Fixture::at(&database)?)?;
    publish(&mut machine)?;
    save(&mut fixture, &mut command, &machine, 6)?;
    let previous = fixture
        .repository
        .certificate_order_checkpoint(command.order_id)?;
    remove_new_index(&fixture)?;
    drop(fixture);
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
    let (mut fixture, mut machine, mut command) = prepared(Fixture::new()?)?;
    publish(&mut machine)?;
    save(&mut fixture, &mut command, &machine, 6)?;
    remove_new_index(&fixture)?;
    fixture.repository.database.connection().execute(
        "UPDATE certificate_order_checkpoints SET checkpoint_digest = zeroblob(32)",
        [],
    )?;
    let mut database = fixture.repository.into_database();
    assert!(crate::migration::migrate_partition(database.connection_mut(), 30).is_err());
    let version: u32 = database
        .connection()
        .pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 85);
    assert!(
        database
            .connection()
            .prepare("SELECT http01_token FROM certificate_order_checkpoints")
            .is_err()
    );
    Ok(())
}

fn remove_new_index(fixture: &Fixture) -> Result<(), rusqlite::Error> {
    fixture.repository.database.connection().execute_batch(
        "DROP INDEX certificate_order_checkpoints_http01_token;
         ALTER TABLE certificate_order_checkpoints DROP COLUMN http01_token;
         DROP TRIGGER node_activation_rejects_bootstrap_endpoint;
         DROP INDEX nodes_bootstrap_private_endpoint;
         ALTER TABLE nodes DROP COLUMN bootstrap_private_endpoint;
         DELETE FROM schema_migrations WHERE version >= 86;
         PRAGMA user_version = 85;",
    )
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
