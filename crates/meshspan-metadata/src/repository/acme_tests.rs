// SPDX-License-Identifier: GPL-2.0-only

use meshspan_acme::{AcmeChallengePreference, AcmeOrderMachine, AcmeOrderRequest};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AcmeConfigurationId, ApiKeyId, AuditEventId, AuthenticationMethodId, CertificateOrderId,
    EntropyError, HostId, MeshId, NodeId, OperationId, PartitionId, PrincipalId, RandomSource,
    Revision, RoleId, UnixMicros,
};
use meshspan_secret_envelope::{SecretContext, WrappingPrivateKey, encrypt_secret};
use rusqlite::params;
use sha2::{Digest as _, Sha256};

use super::{
    AuthoritativeRepository, CertificateOrderState, EntityKind, LogPosition, ManualDnsTaskState,
    PageLimit, RepositoryError,
};
use crate::{
    ACME_ACCOUNT_KEY_SECRET_KIND, ACME_CHALLENGE_SETTINGS_SECRET_KIND,
    AcknowledgePublicCertificateInstallation, AcmeChallengeKind, AdvanceManualDnsTask,
    AuthoritativeCommand, BootstrapMesh, BootstrapRecoveryIdentity, CertificateOrderCompletion,
    CheckpointCertificateOrder, ClaimCertificateOrder, CommandContext, CommitSecretGeneration,
    CompleteCertificateOrder, ConfigureAcme, ConfirmRecoveryBundleSaved,
    CreateAuthenticationMethod, ManualDnsTaskPhase, NewAuthenticationCredential,
    PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND,
    PartitionDatabase, ProvisionAcme, QueueCertificateOrder, RecordName, RenewCertificateOrder,
    SecretGenerationReference,
};

#[test]
fn manual_dns_tasks_advance_and_replacement_fences_supersede_stale_work()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let config_id = AcmeConfigurationId::from_bytes([90; 16])?;
    let order_id = CertificateOrderId::from_bytes([91; 16])?;
    let mut configuration = fixture.configuration(config_id)?;
    configuration.challenge_settings = None;
    fixture.apply(3, 2, &AuthoritativeCommand::ConfigureAcme(configuration))?;
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
    let first = manual_task(
        &fixture,
        order_id,
        1,
        901,
        [1; 32],
        ManualDnsTaskPhase::AwaitingPublication,
    );
    fixture.apply(
        6,
        11,
        &AuthoritativeCommand::AdvanceManualDnsTask(first.clone()),
    )?;
    let mut observed = first.clone();
    observed.phase = ManualDnsTaskPhase::PublicationObserved;
    fixture.apply(7, 12, &AuthoritativeCommand::AdvanceManualDnsTask(observed))?;
    assert_eq!(
        fixture
            .repository
            .manual_dns_task([1; 32])?
            .ok_or("missing task")?
            .state,
        ManualDnsTaskState::PublicationObserved
    );

    fixture.apply(
        8,
        100,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 2, 902, 200)),
    )?;
    let replacement = manual_task(
        &fixture,
        order_id,
        2,
        902,
        [2; 32],
        ManualDnsTaskPhase::AwaitingPublication,
    );
    fixture.apply(
        9,
        101,
        &AuthoritativeCommand::AdvanceManualDnsTask(replacement),
    )?;
    assert_eq!(
        fixture
            .repository
            .manual_dns_task([1; 32])?
            .ok_or("missing stale task")?
            .state,
        ManualDnsTaskState::Superseded
    );
    let page = fixture
        .repository
        .actionable_manual_dns_tasks(None, PageLimit::new(10)?)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].task_digest, [2; 32]);
    Ok(())
}

fn manual_task(
    fixture: &Fixture,
    order_id: CertificateOrderId,
    claim_generation: u64,
    fence: u64,
    task_digest: [u8; 32],
    phase: ManualDnsTaskPhase,
) -> AdvanceManualDnsTask {
    AdvanceManualDnsTask {
        task_digest,
        order_id,
        claim_generation,
        worker_node_id: fixture.node,
        worker_incarnation: 1,
        fence,
        record_name: "_acme-challenge.files.example.test".to_owned(),
        record_value: b"txt-value".to_vec(),
        expires_at: UnixMicros::new(150),
        phase,
    }
}

#[test]
fn complete_acme_configuration_round_trips_from_authoritative_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let config_id = AcmeConfigurationId::from_bytes([60; 16])?;
    let expected = fixture.configuration(config_id)?;
    fixture.apply(3, 2, &AuthoritativeCommand::ConfigureAcme(expected.clone()))?;

    let actual = fixture
        .repository
        .acme_configuration(config_id)?
        .ok_or("configuration missing")?;
    assert_eq!(actual.config_id, expected.config_id);
    assert_eq!(actual.directory_url, expected.directory_url);
    assert_eq!(actual.account_key, expected.account_key);
    assert_eq!(actual.challenge_kind, expected.challenge_kind);
    assert_eq!(actual.challenge_settings, expected.challenge_settings);
    assert_eq!(
        actual.certificate_names,
        expected.certificate_names.as_slice()
    );
    assert_eq!(actual.configured_by, fixture.administrator);
    assert_eq!(actual.revision, Revision::new(3));
    Ok(())
}

#[test]
fn provisioning_atomically_commits_secrets_configuration_and_initial_order()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let config_id = AcmeConfigurationId::from_bytes([111; 16])?;
    let order_id = CertificateOrderId::from_bytes([112; 16])?;
    let account = SecretGenerationReference {
        secret_id: [113; 16],
        generation: 1,
    };
    let settings = SecretGenerationReference {
        secret_id: [114; 16],
        generation: 1,
    };
    let command = provision_command(&fixture, config_id, order_id, account, settings)?;
    fixture.apply(
        3,
        10,
        &AuthoritativeCommand::ProvisionAcme(Box::new(command)),
    )?;

    assert!(
        fixture
            .repository
            .secret_generation(SecretContext::new(
                ACME_ACCOUNT_KEY_SECRET_KIND,
                account.secret_id,
                account.generation
            )?,)?
            .is_some()
    );
    assert!(
        fixture
            .repository
            .secret_generation(SecretContext::new(
                ACME_CHALLENGE_SETTINGS_SECRET_KIND,
                settings.secret_id,
                settings.generation,
            )?,)?
            .is_some()
    );
    let stored_configuration = fixture
        .repository
        .acme_configuration(config_id)?
        .ok_or("configuration missing")?;
    assert_eq!(stored_configuration.config_id, config_id);
    assert_eq!(
        stored_configuration.provisioning_intent_digest,
        Some([126; 32])
    );
    assert_eq!(
        fixture
            .repository
            .certificate_order(order_id)?
            .map(|value| value.order_id),
        Some(order_id),
    );
    Ok(())
}

#[test]
fn rejected_provisioning_rolls_back_every_secret_and_configuration_row()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let config_id = AcmeConfigurationId::from_bytes([121; 16])?;
    let order_id = CertificateOrderId::from_bytes([122; 16])?;
    let account = SecretGenerationReference {
        secret_id: [123; 16],
        generation: 1,
    };
    let settings = SecretGenerationReference {
        secret_id: [124; 16],
        generation: 1,
    };
    let mut command = provision_command(&fixture, config_id, order_id, account, settings)?;
    command.initial_order.config_id = AcmeConfigurationId::from_bytes([125; 16])?;
    assert!(matches!(
        fixture.apply(
            3,
            10,
            &AuthoritativeCommand::ProvisionAcme(Box::new(command)),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(fixture.repository.acme_configuration(config_id)?, None);
    assert_eq!(fixture.repository.certificate_order(order_id)?, None);
    assert_eq!(
        fixture.repository.secret_generation(SecretContext::new(
            ACME_ACCOUNT_KEY_SECRET_KIND,
            account.secret_id,
            account.generation,
        )?)?,
        None,
    );
    Ok(())
}

fn provision_command(
    fixture: &Fixture,
    config_id: AcmeConfigurationId,
    order_id: CertificateOrderId,
    account: SecretGenerationReference,
    settings: SecretGenerationReference,
) -> Result<ProvisionAcme, Box<dyn std::error::Error>> {
    let recipients = [
        crate::test_support::node_wrapping_private_key()?.public_key(),
        fixture.recovery_key.public_key(),
    ];
    let account_generation =
        protected_generation(ACME_ACCOUNT_KEY_SECRET_KIND, account, &recipients, 115)?;
    let settings_generation = protected_generation(
        ACME_CHALLENGE_SETTINGS_SECRET_KIND,
        settings,
        &recipients,
        116,
    )?;
    let configuration = ConfigureAcme {
        config_id,
        directory_url: "https://acme.example.test/directory".to_owned(),
        account_key: account,
        challenge_kind: AcmeChallengeKind::Dns01,
        challenge_settings: Some(settings),
        certificate_names: BoundedItems::new(vec!["files.example.test".to_owned()], 256)?,
    };
    Ok(ProvisionAcme {
        intent_digest: [126; 32],
        configuration: configuration.clone(),
        account_key_generation: account_generation,
        challenge_settings_generation: Some(settings_generation),
        initial_order: QueueCertificateOrder {
            order_id,
            config_id,
            next_attempt_at: UnixMicros::new(10),
        },
    })
}

fn protected_generation(
    kind: u16,
    reference: SecretGenerationReference,
    recipients: &[meshspan_secret_envelope::WrappingPublicKey],
    seed: u8,
) -> Result<Box<CommitSecretGeneration>, Box<dyn std::error::Error>> {
    let (secret, envelopes) = encrypt_secret(
        SecretContext::new(kind, reference.secret_id, reference.generation)?,
        b"protected ACME input",
        recipients,
        &mut SecretRandom(seed),
    )?;
    Ok(Box::new(CommitSecretGeneration {
        secret: secret.parts(),
        recipients: envelopes.into_iter().map(|value| value.parts()).collect(),
    }))
}

#[test]
fn due_certificate_orders_page_queued_and_expired_claims_in_stable_order()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let first_config = AcmeConfigurationId::from_bytes([61; 16])?;
    let second_config = AcmeConfigurationId::from_bytes([62; 16])?;
    let first_order = CertificateOrderId::from_bytes([63; 16])?;
    let second_order = CertificateOrderId::from_bytes([64; 16])?;
    fixture.apply(
        3,
        2,
        &AuthoritativeCommand::ConfigureAcme(fixture.configuration(first_config)?),
    )?;
    fixture.apply(
        4,
        3,
        &AuthoritativeCommand::ConfigureAcme(fixture.configuration(second_config)?),
    )?;
    fixture.apply(
        5,
        10,
        &AuthoritativeCommand::QueueCertificateOrder(QueueCertificateOrder {
            order_id: first_order,
            config_id: first_config,
            next_attempt_at: UnixMicros::new(10),
        }),
    )?;
    fixture.apply(
        6,
        10,
        &AuthoritativeCommand::QueueCertificateOrder(QueueCertificateOrder {
            order_id: second_order,
            config_id: second_config,
            next_attempt_at: UnixMicros::new(10),
        }),
    )?;
    fixture.apply(
        7,
        12,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(first_order, 1, 610, 20)),
    )?;

    let before_expiry = fixture.repository.due_certificate_orders(
        UnixMicros::new(19),
        None,
        PageLimit::new(10)?,
    )?;
    assert_eq!(before_expiry.items.len(), 1);
    assert_eq!(before_expiry.items[0].order_id, second_order);

    let first_page =
        fixture
            .repository
            .due_certificate_orders(UnixMicros::new(20), None, PageLimit::new(1)?)?;
    assert_eq!(first_page.items.len(), 1);
    assert_eq!(first_page.items[0].order_id, first_order);
    assert_eq!(first_page.items[0].state, CertificateOrderState::Claimed);
    let cursor = first_page.next.ok_or("next cursor missing")?;
    let second_page = fixture.repository.due_certificate_orders(
        UnixMicros::new(20),
        Some(&cursor),
        PageLimit::new(1)?,
    )?;
    assert_eq!(second_page.items.len(), 1);
    assert_eq!(second_page.items[0].order_id, second_order);
    assert_eq!(second_page.items[0].state, CertificateOrderState::Queued);
    assert_eq!(second_page.next, None);
    Ok(())
}

#[test]
fn due_certificate_renewal_disappears_when_a_replacement_is_actionable()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let config_id = AcmeConfigurationId::from_bytes([65; 16])?;
    let source_order_id = CertificateOrderId::from_bytes([66; 16])?;
    let replacement_order_id = CertificateOrderId::from_bytes([67; 16])?;
    fixture.apply(
        3,
        2,
        &AuthoritativeCommand::ConfigureAcme(fixture.configuration(config_id)?),
    )?;
    fixture.apply(
        4,
        10,
        &AuthoritativeCommand::QueueCertificateOrder(QueueCertificateOrder {
            order_id: source_order_id,
            config_id,
            next_attempt_at: UnixMicros::new(10),
        }),
    )?;
    fixture.apply(
        5,
        10,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(source_order_id, 1, 651, 100)),
    )?;
    fixture.apply(
        6,
        20,
        &AuthoritativeCommand::CompleteCertificateOrder(CompleteCertificateOrder {
            order_id: source_order_id,
            claim_generation: 1,
            worker_node_id: fixture.node,
            worker_incarnation: 1,
            fence: 651,
            outcome: CertificateOrderCompletion::Issued {
                certificate: fixture.certificate(source_order_id)?,
                not_before: UnixMicros::new(15),
                not_after: UnixMicros::new(1_000),
                result_digest: [68; 32],
            },
        }),
    )?;

    assert!(
        fixture
            .repository
            .due_certificate_renewals(UnixMicros::new(999), None, PageLimit::new(10)?)?
            .items
            .is_empty()
    );
    let due = fixture.repository.due_certificate_renewals(
        UnixMicros::new(1_000),
        None,
        PageLimit::new(10)?,
    )?;
    assert_eq!(due.items.len(), 1);
    assert_eq!(due.items[0].source_order_id, source_order_id);
    assert_eq!(due.items[0].config_id, config_id);
    assert_eq!(due.items[0].configured_by, fixture.administrator);
    assert_eq!(due.items[0].not_after, UnixMicros::new(1_000));
    assert_eq!(due.items[0].revision, Revision::new(6));

    fixture.apply(
        7,
        21,
        &AuthoritativeCommand::QueueCertificateOrder(QueueCertificateOrder {
            order_id: replacement_order_id,
            config_id,
            next_attempt_at: UnixMicros::new(21),
        }),
    )?;
    assert!(
        fixture
            .repository
            .due_certificate_renewals(UnixMicros::new(1_000), None, PageLimit::new(10)?)?
            .items
            .is_empty()
    );
    Ok(())
}

#[test]
fn checkpoint_survives_worker_replacement_under_one_protected_leaf_key()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let config_id = AcmeConfigurationId::from_bytes([70; 16])?;
    let order_id = CertificateOrderId::from_bytes([71; 16])?;
    fixture.apply(
        3,
        2,
        &AuthoritativeCommand::ConfigureAcme(fixture.configuration(config_id)?),
    )?;
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
    let checkpoint = checkpoint(&fixture, config_id, 707)?;
    fixture.apply(
        6,
        11,
        &checkpoint_command(&fixture, order_id, 1, 707, certificate_key, checkpoint),
    )?;
    let first = fixture
        .repository
        .certificate_order_checkpoint(order_id)?
        .ok_or("checkpoint missing")?;
    assert_eq!(first.certificate_key, certificate_key);
    assert_eq!(first.fence, 707);

    fixture.apply(
        7,
        12,
        &AuthoritativeCommand::CompleteCertificateOrder(fixture.retry(order_id, 1, 707, 20)),
    )?;
    assert!(
        fixture
            .repository
            .certificate_order_checkpoint(order_id)?
            .is_some()
    );
    fixture.apply(
        8,
        20,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 2, 708, 100)),
    )?;
    let mut resumed = AcmeOrderMachine::decode_checkpoint(&first.checkpoint)?;
    resumed.resume_under_fence(708)?;
    fixture.apply(
        9,
        21,
        &checkpoint_command(
            &fixture,
            order_id,
            2,
            708,
            certificate_key,
            resumed.encode_checkpoint()?,
        ),
    )?;
    let replacement = fixture
        .repository
        .certificate_order_checkpoint(order_id)?
        .ok_or("replacement checkpoint missing")?;
    assert_eq!(replacement.certificate_key, certificate_key);
    assert_eq!(replacement.claim_generation, 2);
    assert_eq!(replacement.fence, 708);

    fixture.apply(
        10,
        22,
        &AuthoritativeCommand::CompleteCertificateOrder(CompleteCertificateOrder {
            order_id,
            claim_generation: 2,
            worker_node_id: fixture.node,
            worker_incarnation: 1,
            fence: 708,
            outcome: CertificateOrderCompletion::Issued {
                certificate: fixture.certificate(order_id)?,
                not_before: UnixMicros::new(20),
                not_after: UnixMicros::new(1_000),
                result_digest: [72; 32],
            },
        }),
    )?;
    assert_eq!(
        fixture.repository.certificate_order_checkpoint(order_id)?,
        None
    );
    Ok(())
}

fn checkpoint_command(
    fixture: &Fixture,
    order_id: CertificateOrderId,
    claim_generation: u64,
    fence: u64,
    certificate_key: SecretGenerationReference,
    checkpoint: Vec<u8>,
) -> AuthoritativeCommand {
    AuthoritativeCommand::CheckpointCertificateOrder(CheckpointCertificateOrder {
        order_id,
        claim_generation,
        worker_node_id: fixture.node,
        worker_incarnation: 1,
        fence,
        certificate_key,
        checkpoint,
    })
}

fn checkpoint(
    fixture: &Fixture,
    config_id: AcmeConfigurationId,
    fence: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let configuration = fixture.configuration(config_id)?;
    Ok(AcmeOrderMachine::new(
        configuration.directory_url,
        AcmeOrderRequest::new(configuration.certificate_names.as_slice().to_vec())?,
        AcmeChallengePreference::Dns01,
        fence,
    )?
    .encode_checkpoint()?)
}

#[test]
fn certificate_order_is_retried_reclaimed_and_stale_workers_are_fenced()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let config_id = AcmeConfigurationId::from_bytes([10; 16])?;
    fixture.apply(
        3,
        2,
        &AuthoritativeCommand::ConfigureAcme(fixture.configuration(config_id)?),
    )?;
    let order_id = CertificateOrderId::from_bytes([11; 16])?;
    let queued = fixture.apply(
        4,
        10,
        &AuthoritativeCommand::QueueCertificateOrder(QueueCertificateOrder {
            order_id,
            config_id,
            next_attempt_at: UnixMicros::new(10),
        }),
    )?;
    assert_eq!(queued.entity.kind, EntityKind::CertificateOrder);

    fixture.apply(
        5,
        10,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 1, 101, 100)),
    )?;
    fixture.apply(
        6,
        20,
        &AuthoritativeCommand::RenewCertificateOrder(fixture.renew(order_id, 1, 101, 120)),
    )?;
    fixture.apply(
        7,
        121,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 2, 202, 180)),
    )?;
    let stale = fixture.apply(
        8,
        122,
        &AuthoritativeCommand::CompleteCertificateOrder(fixture.retry(order_id, 1, 101, 200)),
    );
    assert!(matches!(stale, Err(RepositoryError::InvalidCommand)));
    fixture.apply(
        8,
        122,
        &AuthoritativeCommand::CompleteCertificateOrder(fixture.retry(order_id, 2, 202, 200)),
    )?;
    let queued = fixture
        .repository
        .certificate_order(order_id)?
        .ok_or("queued order missing")?;
    assert_eq!(queued.state, CertificateOrderState::Queued);
    assert_eq!(queued.attempt_count, 2);
    assert!(queued.claim.is_none());

    fixture.apply(
        9,
        200,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 3, 303, 260)),
    )?;
    fixture.reject_incomplete_issuance(order_id)?;
    fixture.apply(
        10,
        201,
        &AuthoritativeCommand::CompleteCertificateOrder(CompleteCertificateOrder {
            order_id,
            claim_generation: 3,
            worker_node_id: fixture.node,
            worker_incarnation: 1,
            fence: 303,
            outcome: CertificateOrderCompletion::Issued {
                certificate: fixture.certificate(order_id)?,
                not_before: UnixMicros::new(190),
                not_after: UnixMicros::new(1_000),
                result_digest: [44; 32],
            },
        }),
    )?;
    let complete = fixture
        .repository
        .certificate_order(order_id)?
        .ok_or("complete order missing")?;
    assert_eq!(complete.state, CertificateOrderState::Complete);
    assert_eq!(
        complete.certificate,
        Some(SecretGenerationReference {
            secret_id: order_id.as_bytes(),
            generation: 1,
        })
    );
    assert!(complete.claim.is_none());
    Ok(())
}

#[test]
fn gateway_installation_requires_exact_issued_recipient_and_is_idempotent()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let config_id = AcmeConfigurationId::from_bytes([50; 16])?;
    let order_id = CertificateOrderId::from_bytes([51; 16])?;
    fixture.apply(
        3,
        2,
        &AuthoritativeCommand::ConfigureAcme(fixture.configuration(config_id)?),
    )?;
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
        11,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 1, 501, 100)),
    )?;
    fixture.apply(
        6,
        12,
        &AuthoritativeCommand::CompleteCertificateOrder(CompleteCertificateOrder {
            order_id,
            claim_generation: 1,
            worker_node_id: fixture.node,
            worker_incarnation: 1,
            fence: 501,
            outcome: CertificateOrderCompletion::Issued {
                certificate: fixture.certificate(order_id)?,
                not_before: UnixMicros::new(1),
                not_after: UnixMicros::new(1_000),
                result_digest: [52; 32],
            },
        }),
    )?;
    let complete = fixture
        .repository
        .certificate_order(order_id)?
        .ok_or("completed order missing")?;
    let certificate = complete.certificate.ok_or("certificate missing")?;
    let acknowledgement = AcknowledgePublicCertificateInstallation {
        order_id,
        gateway_node_id: fixture.node,
        gateway_incarnation: 1,
        certificate,
        bundle_digest: [52; 32],
        observed_order_revision: complete.revision,
    };
    fixture.apply(
        7,
        13,
        &AuthoritativeCommand::AcknowledgePublicCertificateInstallation(acknowledgement),
    )?;
    let installation = fixture
        .repository
        .public_certificate_installation(order_id, fixture.node)?
        .ok_or("gateway installation missing")?;
    assert_eq!(installation.gateway_incarnation, 1);
    assert_eq!(installation.certificate, certificate);
    assert_eq!(installation.bundle_digest, [52; 32]);
    assert_eq!(installation.installed_at, UnixMicros::new(13));
    let summary = fixture
        .repository
        .public_certificate_rollout_summary(order_id)?;
    assert_eq!(summary.required_gateway_count, 1);
    assert_eq!(summary.installed_gateway_count, 1);
    assert!(summary.complete);

    fixture.apply(
        8,
        14,
        &AuthoritativeCommand::AcknowledgePublicCertificateInstallation(acknowledgement),
    )?;
    let mut substituted = acknowledgement;
    substituted.bundle_digest = [53; 32];
    assert!(matches!(
        fixture.apply(
            9,
            15,
            &AuthoritativeCommand::AcknowledgePublicCertificateInstallation(substituted)
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

#[test]
fn configuration_rejects_unsorted_names_and_http_publisher_secrets()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let mut invalid = fixture.configuration(AcmeConfigurationId::from_bytes([20; 16])?)?;
    invalid.certificate_names = BoundedItems::new(
        vec!["z.example.test".to_owned(), "a.example.test".to_owned()],
        256,
    )?;
    assert!(matches!(
        fixture.apply(3, 2, &AuthoritativeCommand::ConfigureAcme(invalid)),
        Err(RepositoryError::InvalidCommand)
    ));

    let mut invalid = fixture.configuration(AcmeConfigurationId::from_bytes([21; 16])?)?;
    invalid.challenge_kind = AcmeChallengeKind::Http01;
    assert!(matches!(
        fixture.apply(3, 2, &AuthoritativeCommand::ConfigureAcme(invalid)),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

struct Fixture {
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    node: NodeId,
    account_key: SecretGenerationReference,
    challenge_settings: SecretGenerationReference,
    recovery_key: WrappingPrivateKey,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let administrator = PrincipalId::from_bytes([2; 16])?;
        let node = NodeId::from_bytes([6; 16])?;
        let database = PartitionDatabase::open(
            std::path::Path::new(":memory:"),
            PartitionId::from_bytes([1; 16])?,
            UnixMicros::new(1),
        )?;
        let mut fixture = Self {
            repository: AuthoritativeRepository::new(database),
            administrator,
            node,
            account_key: SecretGenerationReference {
                secret_id: [7; 16],
                generation: 1,
            },
            challenge_settings: SecretGenerationReference {
                secret_id: [8; 16],
                generation: 1,
            },
            recovery_key: WrappingPrivateKey::from_bytes([19; 32])?,
        };
        let mesh_id = MeshId::from_bytes([3; 16])?;
        let certificate = vec![13; 64];
        let bootstrap = crate::test_support::bootstrap_appliance(
            BootstrapMesh {
                mesh_id,
                mesh_name: RecordName::new("ACME proof")?,
                administrator_id: administrator,
                administrator_name: RecordName::new("Administrator")?,
                administrator_role_id: RoleId::from_bytes([4; 16])?,
                host_id: HostId::from_bytes([5; 16])?,
                host_name: RecordName::new("Host")?,
                node_id: node,
                node_name: RecordName::new("Gateway")?,
                partition_name: RecordName::new("Authority")?,
            },
            CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([9; 16])?,
                principal_id: administrator,
                label: "Initial API key".to_owned(),
                service_scope: 7,
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: ApiKeyId::from_bytes([10; 16])?,
                    key_digest: [11; 32],
                    smb_verifier_ciphertext: Some(vec![12; 65]),
                    scopes: 7,
                    valid_from: UnixMicros::new(1),
                },
            },
            Box::new(BootstrapRecoveryIdentity {
                public_wrapping_key: fixture.recovery_key.public_key().as_bytes(),
                key_fingerprint: fixture.recovery_key.public_key().fingerprint(),
                online_authority_certificate_digest: Sha256::digest(&certificate).into(),
                online_authority_certificate_der: certificate.clone(),
                root_certificate_digest: Sha256::digest(&certificate).into(),
                root_certificate_der: certificate,
                bundle_digest: [14; 32],
                save_challenge_commitment: [15; 32],
            }),
        )?;
        fixture.apply(
            1,
            1,
            &AuthoritativeCommand::BootstrapAppliance(Box::new(bootstrap)),
        )?;
        fixture.apply(
            2,
            1,
            &AuthoritativeCommand::ConfirmRecoveryBundleSaved(ConfirmRecoveryBundleSaved {
                mesh_id,
                bundle_digest: [14; 32],
                save_challenge_commitment: [15; 32],
            }),
        )?;
        fixture.insert_secret(ACME_ACCOUNT_KEY_SECRET_KIND, fixture.account_key)?;
        fixture.insert_secret(
            ACME_CHALLENGE_SETTINGS_SECRET_KIND,
            fixture.challenge_settings,
        )?;
        Ok(fixture)
    }

    fn configuration(
        &self,
        config_id: AcmeConfigurationId,
    ) -> Result<ConfigureAcme, Box<dyn std::error::Error>> {
        Ok(ConfigureAcme {
            config_id,
            directory_url: "https://acme.example.test/directory".to_owned(),
            account_key: self.account_key,
            challenge_kind: AcmeChallengeKind::Dns01,
            challenge_settings: Some(self.challenge_settings),
            certificate_names: BoundedItems::new(
                vec![
                    "files.example.test".to_owned(),
                    "www.example.test".to_owned(),
                ],
                256,
            )?,
        })
    }

    fn claim(
        &self,
        order_id: CertificateOrderId,
        generation: u64,
        fence: u64,
        lease_expires_at: i64,
    ) -> ClaimCertificateOrder {
        ClaimCertificateOrder {
            order_id,
            claim_generation: generation,
            worker_node_id: self.node,
            worker_incarnation: 1,
            fence,
            lease_expires_at: UnixMicros::new(lease_expires_at),
        }
    }

    fn renew(
        &self,
        order_id: CertificateOrderId,
        generation: u64,
        fence: u64,
        lease_expires_at: i64,
    ) -> RenewCertificateOrder {
        RenewCertificateOrder {
            order_id,
            claim_generation: generation,
            worker_node_id: self.node,
            worker_incarnation: 1,
            fence,
            lease_expires_at: UnixMicros::new(lease_expires_at),
        }
    }

    fn retry(
        &self,
        order_id: CertificateOrderId,
        generation: u64,
        fence: u64,
        retry_at: i64,
    ) -> CompleteCertificateOrder {
        CompleteCertificateOrder {
            order_id,
            claim_generation: generation,
            worker_node_id: self.node,
            worker_incarnation: 1,
            fence,
            outcome: CertificateOrderCompletion::Retry {
                failure_digest: [33; 32],
                retry_at: UnixMicros::new(retry_at),
            },
        }
    }

    fn certificate(
        &self,
        order_id: CertificateOrderId,
    ) -> Result<Box<CommitSecretGeneration>, Box<dyn std::error::Error>> {
        let recipients = [
            crate::test_support::node_wrapping_private_key()?.public_key(),
            self.recovery_key.public_key(),
        ];
        Self::certificate_for_recipients(order_id, &recipients, 90)
    }

    fn certificate_for_recipients(
        order_id: CertificateOrderId,
        recipients: &[meshspan_secret_envelope::WrappingPublicKey],
        seed: u8,
    ) -> Result<Box<CommitSecretGeneration>, Box<dyn std::error::Error>> {
        let context = SecretContext::new(
            PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
            order_id.as_bytes(),
            1,
        )?;
        let (secret, recipients) = encrypt_secret(
            context,
            b"validated public certificate bundle",
            recipients,
            &mut SecretRandom(seed),
        )?;
        Ok(Box::new(CommitSecretGeneration {
            secret: secret.parts(),
            recipients: recipients
                .iter()
                .map(meshspan_secret_envelope::RecipientKeyEnvelope::parts)
                .collect(),
        }))
    }

    fn reject_incomplete_issuance(
        &mut self,
        order_id: CertificateOrderId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let certificate =
            Self::certificate_for_recipients(order_id, &[self.recovery_key.public_key()], 89)?;
        let incomplete = self.apply(
            10,
            201,
            &AuthoritativeCommand::CompleteCertificateOrder(CompleteCertificateOrder {
                order_id,
                claim_generation: 3,
                worker_node_id: self.node,
                worker_incarnation: 1,
                fence: 303,
                outcome: CertificateOrderCompletion::Issued {
                    certificate,
                    not_before: UnixMicros::new(190),
                    not_after: UnixMicros::new(1_000),
                    result_digest: [43; 32],
                },
            }),
        );
        assert!(matches!(incomplete, Err(RepositoryError::InvalidCommand)));
        let order = self
            .repository
            .certificate_order(order_id)?
            .ok_or("claimed order missing")?;
        assert_eq!(order.state, CertificateOrderState::Claimed);
        let context = SecretContext::new(
            PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
            order_id.as_bytes(),
            1,
        )?;
        assert_eq!(self.repository.secret_generation(context)?, None);
        Ok(())
    }

    fn insert_secret(
        &self,
        kind: u16,
        secret: SecretGenerationReference,
    ) -> Result<(), rusqlite::Error> {
        self.repository.database.connection().execute(
            "INSERT INTO secret_generations(
                secret_kind, secret_id, generation, format_version, nonce, ciphertext,
                ciphertext_digest, created_at, revision
             ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, 1, 1)",
            params![
                i64::from(kind),
                secret.secret_id.as_slice(),
                i64::try_from(secret.generation).unwrap_or(i64::MAX),
                [1_u8; 24].as_slice(),
                [2_u8; 17].as_slice(),
                [3_u8; 32].as_slice(),
            ],
        )?;
        Ok(())
    }

    fn apply(
        &mut self,
        index: u64,
        occurred_at: i64,
        command: &AuthoritativeCommand,
    ) -> Result<super::CommandReceipt, RepositoryError> {
        self.repository.apply_committed(
            LogPosition { index, term: 1 },
            CommandContext {
                operation_id: OperationId::from_bytes([u8::try_from(index).unwrap_or(250); 16])
                    .map_err(|_| RepositoryError::InvalidCommand)?,
                actor_principal_id: self.administrator,
                audit_event_id: AuditEventId::from_bytes(
                    [u8::try_from(index + 100).unwrap_or(251); 16],
                )
                .map_err(|_| RepositoryError::InvalidCommand)?,
                occurred_at: UnixMicros::new(occurred_at),
                expected_revision: Some(Revision::new(index - 1)),
            },
            command,
        )
    }
}

struct SecretRandom(u8);

impl RandomSource for SecretRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
}
