// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;

use meshspan_acme::{
    AcmeAuthorization, AcmeChallengePublication, AcmeChallengeRecord, AcmeDirectory,
    AcmeMachineEvent, AcmeOrder, AcmeResourceStatus, Dns01Payload, ManualDnsTask,
};
use meshspan_contracts::{
    BoundedBytes, CertificateChallengeKind, CertificateChallengeRequest, ContractVersion,
    RequestContext,
};

use super::*;

#[test]
fn manual_task_survives_database_restart_and_natural_claim_expiry() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("metadata.sqlite");
    let (mut fixture, original) = published_task_in(Fixture::at(&database_path)?, 1_000)?;
    drop(fixture.repository);
    fixture.repository = AuthoritativeRepository::new(PartitionDatabase::open(
        &database_path,
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(100),
    )?);
    fixture.apply(
        8,
        100,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(original.order_id, 2, 7, 200)),
    )?;
    let replacement = replacement(&original);
    assert!(!fixture.repository.manual_dns_task_transition_satisfied(
        UnixMicros::new(150),
        &replacement,
        901,
    )?);
    fixture.apply(
        9,
        150,
        &AuthoritativeCommand::AdvanceManualDnsTask(replacement.clone()),
    )?;
    let task = fixture
        .repository
        .manual_dns_task(original.task_digest)?
        .ok_or("task lost")?;
    assert_eq!(task.state, ManualDnsTaskState::PublicationObserved);
    assert_eq!(task.task_digest, original.task_digest);
    assert_eq!(task.fence, 901);
    assert_eq!(task.expires_at, UnixMicros::new(1_000));
    assert_eq!(task.created_at, UnixMicros::new(11));
    assert_eq!(task.record_name, "_acme-challenge.files.example.test");
    assert_eq!(task.record_value, b"txt-value");
    assert!(fixture.repository.manual_dns_task_transition_satisfied(
        UnixMicros::new(151),
        &replacement,
        901,
    )?);
    assert_eq!(fixture.repository.current_revision()?, Revision::new(9));
    assert!(matches!(
        fixture.repository.manual_dns_task_transition_satisfied(
            UnixMicros::new(151),
            &original,
            901,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert!(matches!(
        fixture.repository.manual_dns_task_transition_satisfied(
            UnixMicros::new(200),
            &replacement,
            901,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

#[test]
fn legacy_expiry_candidate_belongs_to_the_original_claim_not_the_replacement()
-> Result<(), Box<dyn Error>> {
    let (fixture, original) = interrupted_task()?;
    let checkpoint = fixture
        .repository
        .certificate_order_checkpoint(original.order_id)?
        .ok_or("missing checkpoint")?;
    assert_eq!(checkpoint.legacy_lease_expiry_candidate, None);
    // An explicit old-format fixture, independent of the current checkpoint encoder.
    let bytes = LEGACY_CHECKPOINT;
    AcmeOrderMachine::decode_checkpoint(bytes)?;
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    fixture.repository.database.connection().execute(
        "UPDATE certificate_order_checkpoints SET checkpoint = ?1, checkpoint_digest = ?2 WHERE order_id = ?3",
        params![bytes, digest.as_slice(), original.order_id.as_bytes().as_slice()],
    )?;
    let loaded = fixture
        .repository
        .certificate_order_checkpoint(original.order_id)?
        .ok_or("missing legacy checkpoint")?;
    assert_eq!(
        loaded.legacy_lease_expiry_candidate,
        Some(UnixMicros::new(100))
    );
    assert_eq!(loaded.checkpoint, bytes);
    assert_eq!(loaded.checkpoint_digest, digest);
    assert_eq!(
        fixture
            .repository
            .certificate_order(original.order_id)?
            .ok_or("missing order")?
            .claim
            .ok_or("missing claim")?
            .lease_expires_at,
        UnixMicros::new(200)
    );
    Ok(())
}

const LEGACY_CHECKPOINT: &[u8] = br#"{
  "version": 2,
  "machine": {
    "directory_url": "https://acme.example.test/directory",
    "request": {"dns_names": ["files.example.test"]},
    "preference": "dns01", "order_epoch": 901, "phase": "publish_challenge",
    "directory": {
      "new_nonce": "https://acme.example.test/nonce",
      "new_account": "https://acme.example.test/account",
      "new_order": "https://acme.example.test/new-order"
    },
    "nonce": "nonce-4", "account_url": "https://acme.example.test/account/1",
    "order_url": "https://acme.example.test/order/1",
    "order": {
      "status": "pending", "dns_names": ["files.example.test"],
      "authorizations": ["https://acme.example.test/authorization/1"],
      "finalize": "https://acme.example.test/finalize/1", "certificate": null
    },
    "authorization_index": 0, "authorized_names": [],
    "authorization": {
      "dns_name": "files.example.test", "wildcard": false, "status": "pending",
      "challenges": [{"kind": "dns-01", "url": "https://acme.example.test/challenge/1",
                      "token": "token-1", "status": "pending"}]
    },
    "challenge": {"kind": "dns-01", "url": "https://acme.example.test/challenge/1",
                  "token": "token-1", "status": "pending"},
    "publication_digest": null, "certificate": null, "poll_not_before": null
  }
}"#;

#[test]
fn replacement_claim_advances_the_exact_retained_task_without_recreating_it()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("metadata.sqlite");
    let (mut fixture, original) = interrupted_task_in(Fixture::at(&database_path)?)
        .map_err(|error| format!("handoff fixture failed: {error}"))?;
    drop(fixture.repository);
    fixture.repository = AuthoritativeRepository::new(PartitionDatabase::open(
        &database_path,
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(21),
    )?);
    let before = fixture
        .repository
        .manual_dns_task(original.task_digest)?
        .ok_or("missing original task")?;
    let replacement = replacement(&original);
    assert!(matches!(
        fixture.repository.manual_dns_task_transition_satisfied(
            UnixMicros::new(21),
            &replacement,
            replacement.fence,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert!(
        !fixture
            .repository
            .manual_dns_task_transition_satisfied(UnixMicros::new(21), &replacement, 901)
            .map_err(|error| format!(
                "exact retained task rejected under the replacement claim: {error}"
            ))?
    );
    fixture.apply(
        10,
        21,
        &AuthoritativeCommand::AdvanceManualDnsTask(replacement.clone()),
    )?;
    let after = fixture
        .repository
        .manual_dns_task(original.task_digest)?
        .ok_or("missing continued task")?;
    assert_eq!(after.state, ManualDnsTaskState::PublicationObserved);
    assert_eq!(after.fence, 901);
    assert_eq!(after.created_at, before.created_at);
    assert_eq!(after.task_digest, before.task_digest);
    assert_eq!(after.record_value, b"txt-value");
    assert_eq!(after.expires_at, UnixMicros::new(80));
    assert_eq!(after.revision, Revision::new(10));
    assert!(fixture.repository.manual_dns_task_transition_satisfied(
        UnixMicros::new(22),
        &replacement,
        901
    )?);
    assert_eq!(fixture.repository.current_revision()?, Revision::new(10));
    let count: i64 = fixture.repository.database.connection().query_row(
        "SELECT count(*) FROM manual_dns_tasks",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    assert!(matches!(
        fixture.repository.manual_dns_task_transition_satisfied(
            UnixMicros::new(22),
            &original,
            901
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert!(matches!(
        fixture.apply(
            11,
            22,
            &AuthoritativeCommand::AdvanceManualDnsTask(original)
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

#[test]
fn replacement_cannot_borrow_an_unproven_or_substituted_publication() -> Result<(), Box<dyn Error>>
{
    for replace_checkpoint in [false, true] {
        let (mut fixture, original) = interrupted_task()?;
        if replace_checkpoint {
            let machine = challenge_machine(81)?;
            let certificate_key = SecretGenerationReference {
                secret_id: original.order_id.as_bytes(),
                generation: 1,
            };
            let mut machine = machine;
            machine.resume_under_fence(7)?;
            fixture.apply(
                10,
                21,
                &checkpoint_command(
                    &fixture,
                    original.order_id,
                    2,
                    7,
                    certificate_key,
                    machine.encode_checkpoint()?,
                ),
            )?;
        } else {
            fixture.repository.database.connection().execute(
                "DELETE FROM certificate_order_checkpoints WHERE order_id = ?1",
                [original.order_id.as_bytes().as_slice()],
            )?;
        }
        let replacement = replacement(&original);
        assert!(matches!(
            fixture.repository.manual_dns_task_transition_satisfied(
                UnixMicros::new(22),
                &replacement,
                901
            ),
            Err(RepositoryError::InvalidCommand)
        ));
        let attempted = fixture.apply(
            if replace_checkpoint { 11 } else { 10 },
            22,
            &AuthoritativeCommand::AdvanceManualDnsTask(replacement),
        );
        assert!(
            matches!(attempted, Err(RepositoryError::InvalidCommand)),
            "replacement checkpoint={replace_checkpoint}: {attempted:?}"
        );
        assert_eq!(
            fixture
                .repository
                .manual_dns_task(original.task_digest)?
                .ok_or("missing task")?
                .state,
            ManualDnsTaskState::AwaitingPublication
        );
    }
    Ok(())
}

fn replacement(original: &AdvanceManualDnsTask) -> AdvanceManualDnsTask {
    AdvanceManualDnsTask {
        claim_generation: 2,
        fence: 7,
        phase: ManualDnsTaskPhase::PublicationObserved,
        ..original.clone()
    }
}

fn interrupted_task() -> Result<(Fixture, AdvanceManualDnsTask), Box<dyn Error>> {
    interrupted_task_in(Fixture::new()?)
}

fn interrupted_task_in(
    fixture: Fixture,
) -> Result<(Fixture, AdvanceManualDnsTask), Box<dyn Error>> {
    let (mut fixture, task) = published_task_in(fixture, 80)?;
    let order_id = task.order_id;
    fixture.apply(
        8,
        12,
        &AuthoritativeCommand::CompleteCertificateOrder(fixture.retry(order_id, 1, 901, 20)),
    )?;
    fixture.apply(
        9,
        20,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 2, 7, 200)),
    )?;
    Ok((fixture, task))
}

fn published_task_in(
    mut fixture: Fixture,
    publication_expires_at: i64,
) -> Result<(Fixture, AdvanceManualDnsTask), Box<dyn Error>> {
    let config_id = AcmeConfigurationId::from_bytes([90; 16])?;
    let order_id = CertificateOrderId::from_bytes([91; 16])?;
    let mut config = fixture.configuration(config_id)?;
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
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 1, 901, 100)),
    )?;
    let certificate_key = SecretGenerationReference {
        secret_id: order_id.as_bytes(),
        generation: 1,
    };
    fixture.insert_secret(PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND, certificate_key)?;
    fixture.apply(
        6,
        11,
        &checkpoint_command(
            &fixture,
            order_id,
            1,
            901,
            certificate_key,
            challenge_machine(publication_expires_at)?.encode_checkpoint()?,
        ),
    )?;
    let identity = ManualDnsTask::from_challenge_request(
        &publication_request(publication_expires_at)?,
        meshspan_acme::ManualDnsTaskPhase::AwaitingPublication,
    )?;
    let task = AdvanceManualDnsTask {
        task_digest: identity.task_digest,
        order_id,
        claim_generation: 1,
        worker_node_id: fixture.node,
        worker_incarnation: 1,
        fence: 901,
        record_name: identity.record_name,
        record_value: identity.record_value,
        expires_at: identity.expires_at,
        phase: ManualDnsTaskPhase::AwaitingPublication,
    };
    fixture.apply(
        7,
        11,
        &AuthoritativeCommand::AdvanceManualDnsTask(task.clone()),
    )?;
    Ok((fixture, task))
}

fn publication_request(expires_at: i64) -> Result<CertificateChallengeRequest, Box<dyn Error>> {
    Ok(CertificateChallengeRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([92; 16])?,
            deadline: UnixMicros::new(50),
            expected_revision: Some(Revision::new(3)),
        },
        kind: CertificateChallengeKind::Dns01,
        identifier: BoundedBytes::copy_from(b"files.example.test", 253)?,
        challenge: Dns01Payload::new("_acme-challenge.files.example.test", b"txt-value")?
            .encode()?,
        order_epoch: 901,
        expires_at: UnixMicros::new(expires_at),
    })
}

fn challenge_machine(expires_at: i64) -> Result<AcmeOrderMachine, Box<dyn Error>> {
    let mut machine = AcmeOrderMachine::new(
        "https://acme.example.test/directory".to_owned(),
        AcmeOrderRequest::new(vec!["files.example.test".to_owned()])?,
        AcmeChallengePreference::Dns01,
        901,
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
        authorization: AcmeAuthorization {
            dns_name: "files.example.test".to_owned(),
            wildcard: false,
            status: AcmeResourceStatus::Pending,
            challenges: vec![AcmeChallengeRecord {
                kind: "dns-01".to_owned(),
                url: "https://acme.example.test/challenge/1".to_owned(),
                token: "token-1".to_owned(),
                status: AcmeResourceStatus::Pending,
            }],
        },
        replay_nonce: "nonce-4".to_owned(),
    })?;
    machine.retain_publication(AcmeChallengePublication::capture(&publication_request(
        expires_at,
    )?)?)?;
    Ok(machine)
}
