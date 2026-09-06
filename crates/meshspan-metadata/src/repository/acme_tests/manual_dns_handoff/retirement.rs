// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::repository::apply::{ApplyFaultPoint, apply_committed_with_fault};

#[test]
fn retirement_requires_exact_completed_cleanup_and_preserves_retry_and_key_on_reopen()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("retirement.sqlite");
    let (mut fixture, task) = published_task_in(Fixture::at(&database_path)?, 80)?;
    let checkpoint = fixture
        .repository
        .certificate_order_checkpoint(task.order_id)?
        .ok_or("checkpoint missing")?;
    let initial = restart_command(&fixture, task.order_id, checkpoint.checkpoint_digest);
    assert!(matches!(
        fixture.apply(8, 80, &initial),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(fixture.repository.current_revision()?, Revision::new(7));
    let retired = finish_cleanup(&mut fixture, &task)?;
    let wrong = restart_command(&fixture, task.order_id, [23; 32]);
    assert!(matches!(
        fixture.apply(11, 83, &wrong),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(
        fixture
            .repository
            .certificate_order_checkpoint(task.order_id)?,
        Some(retired.clone())
    );
    let command = restart_command(&fixture, task.order_id, retired.checkpoint_digest);
    let receipt = fixture.apply(11, 83, &command)?;
    assert_eq!(receipt.committed_revision, Revision::new(11));
    drop(fixture.repository);
    fixture.repository = AuthoritativeRepository::new(PartitionDatabase::open(
        &database_path,
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(84),
    )?);
    assert_eq!(
        fixture
            .repository
            .certificate_order_checkpoint(task.order_id)?,
        None
    );
    let order = fixture
        .repository
        .certificate_order(task.order_id)?
        .ok_or("order missing")?;
    assert_eq!(order.state, CertificateOrderState::Queued);
    assert_eq!(order.next_attempt_at, UnixMicros::new(200));
    assert!(order.claim.is_none());
    // This repository fixture uses a sentinel secret row without cryptographic recipients.
    // Prove exact preservation here; decryption belongs to the real preparation/key tests.
    let retained_secret: (Vec<u8>, Vec<u8>, Vec<u8>) = fixture.repository.database.connection().query_row(
        "SELECT nonce, ciphertext, ciphertext_digest FROM secret_generations WHERE secret_kind = ?1 AND secret_id = ?2 AND generation = 1",
        params![i64::from(PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND), task.order_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(retained_secret, (vec![1; 24], vec![2; 17], vec![3; 32]));
    assert!(matches!(
        fixture.apply(
            12,
            199,
            &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(task.order_id, 2, 7, 300))
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    fixture.apply(
        12,
        200,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(task.order_id, 2, 7, 300)),
    )?;
    assert_eq!(
        fixture
            .repository
            .certificate_order_checkpoint(task.order_id)?,
        None
    );
    let before = fixture.repository.certificate_order(task.order_id)?;
    let replay = fixture.repository.apply_committed(
        LogPosition { index: 13, term: 1 },
        CommandContext {
            operation_id: OperationId::from_bytes([11; 16])?,
            actor_principal_id: fixture.administrator,
            audit_event_id: AuditEventId::from_bytes([111; 16])?,
            occurred_at: UnixMicros::new(83),
            expected_revision: Some(Revision::new(10)),
        },
        &command,
    )?;
    assert_eq!(replay.disposition, crate::ApplyDisposition::Replayed);
    assert_eq!(replay.committed_revision, Revision::new(11));
    assert_eq!(fixture.repository.certificate_order(task.order_id)?, before);
    Ok(())
}

#[test]
fn every_restart_apply_fault_keeps_the_checkpoint_and_claim_after_reopen()
-> Result<(), Box<dyn Error>> {
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("fault.sqlite");
        let (mut fixture, task) = published_task_in(Fixture::at(&database_path)?, 80)?;
        let retired = finish_cleanup(&mut fixture, &task)?;
        let order = fixture.repository.certificate_order(task.order_id)?;
        let command = restart_command(&fixture, task.order_id, retired.checkpoint_digest);
        let context = CommandContext {
            operation_id: OperationId::from_bytes([11; 16])?,
            actor_principal_id: fixture.administrator,
            audit_event_id: AuditEventId::from_bytes([111; 16])?,
            occurred_at: UnixMicros::new(83),
            expected_revision: Some(Revision::new(10)),
        };
        assert!(matches!(
            apply_committed_with_fault(
                &mut fixture.repository.database,
                LogPosition { index: 11, term: 1 },
                context,
                &command,
                fault
            ),
            Err(RepositoryError::InjectedFault)
        ));
        drop(fixture.repository);
        fixture.repository = AuthoritativeRepository::new(PartitionDatabase::open(
            &database_path,
            PartitionId::from_bytes([1; 16])?,
            UnixMicros::new(84),
        )?);
        assert_eq!(fixture.repository.current_revision()?, Revision::new(10));
        assert_eq!(fixture.repository.certificate_order(task.order_id)?, order);
        assert_eq!(
            fixture
                .repository
                .certificate_order_checkpoint(task.order_id)?,
            Some(retired)
        );
        fixture.apply(11, 83, &command)?;
        assert_eq!(
            fixture
                .repository
                .certificate_order_checkpoint(task.order_id)?,
            None
        );
    }
    Ok(())
}

#[test]
fn never_observed_manual_publication_only_skips_to_cleanup_when_retirement_is_durable()
-> Result<(), Box<dyn Error>> {
    for remove_first in [false, true] {
        let (mut fixture, mut task) = published_task_in(Fixture::new()?, 80)?;
        task.phase = ManualDnsTaskPhase::Complete;
        assert!(matches!(
            fixture.apply(
                8,
                80,
                &AuthoritativeCommand::AdvanceManualDnsTask(task.clone())
            ),
            Err(RepositoryError::InvalidCommand)
        ));
        let checkpoint = fixture
            .repository
            .certificate_order_checkpoint(task.order_id)?
            .ok_or("checkpoint missing")?;
        let mut machine = AcmeOrderMachine::decode_checkpoint(&checkpoint.checkpoint)?;
        assert!(machine.expire_publication(UnixMicros::new(80), [9; 32])?);
        fixture.apply(
            8,
            80,
            &checkpoint_command(
                &fixture,
                task.order_id,
                1,
                901,
                checkpoint.certificate_key,
                machine.encode_checkpoint()?,
            ),
        )?;
        // Recovery may occur after preparing material but before creating the operator task.
        if remove_first {
            fixture.repository.database.connection().execute(
                "DELETE FROM manual_dns_tasks WHERE task_digest = ?1",
                [task.task_digest.as_slice()],
            )?;
        }
        fixture.apply(
            9,
            81,
            &AuthoritativeCommand::AdvanceManualDnsTask(task.clone()),
        )?;
        assert_eq!(
            fixture
                .repository
                .manual_dns_task(task.task_digest)?
                .ok_or("task missing")?
                .state,
            ManualDnsTaskState::Complete
        );
    }
    Ok(())
}

#[test]
fn a_retired_machine_cannot_discard_an_outstanding_manual_cleanup_task()
-> Result<(), Box<dyn Error>> {
    let (mut fixture, task) = published_task_in(Fixture::new()?, 80)?;
    let checkpoint = fixture
        .repository
        .certificate_order_checkpoint(task.order_id)?
        .ok_or("checkpoint missing")?;
    let mut machine = AcmeOrderMachine::decode_checkpoint(&checkpoint.checkpoint)?;
    machine.expire_publication(UnixMicros::new(80), [9; 32])?;
    machine.advance(AcmeMachineEvent::ChallengeCleaned)?;
    fixture.apply(
        8,
        80,
        &checkpoint_command(
            &fixture,
            task.order_id,
            1,
            901,
            checkpoint.certificate_key,
            machine.encode_checkpoint()?,
        ),
    )?;
    let retired = fixture
        .repository
        .certificate_order_checkpoint(task.order_id)?
        .ok_or("checkpoint missing")?;
    assert!(matches!(
        fixture.apply(
            9,
            81,
            &restart_command(&fixture, task.order_id, retired.checkpoint_digest)
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(
        fixture
            .repository
            .certificate_order_checkpoint(task.order_id)?,
        Some(retired)
    );
    assert_eq!(
        fixture
            .repository
            .manual_dns_task(task.task_digest)?
            .ok_or("task missing")?
            .state,
        ManualDnsTaskState::AwaitingPublication
    );
    Ok(())
}

fn finish_cleanup(
    fixture: &mut Fixture,
    original: &AdvanceManualDnsTask,
) -> Result<crate::CertificateOrderCheckpointRecord, Box<dyn Error>> {
    let checkpoint = fixture
        .repository
        .certificate_order_checkpoint(original.order_id)?
        .ok_or("checkpoint missing")?;
    let mut machine = AcmeOrderMachine::decode_checkpoint(&checkpoint.checkpoint)?;
    assert!(machine.expire_publication(UnixMicros::new(80), [9; 32])?);
    fixture.apply(
        8,
        80,
        &checkpoint_command(
            fixture,
            original.order_id,
            1,
            901,
            checkpoint.certificate_key,
            machine.encode_checkpoint()?,
        ),
    )?;
    let mut task = original.clone();
    task.phase = ManualDnsTaskPhase::Complete;
    fixture.apply(9, 81, &AuthoritativeCommand::AdvanceManualDnsTask(task))?;
    machine.advance(AcmeMachineEvent::ChallengeCleaned)?;
    fixture.apply(
        10,
        82,
        &checkpoint_command(
            fixture,
            original.order_id,
            1,
            901,
            checkpoint.certificate_key,
            machine.encode_checkpoint()?,
        ),
    )?;
    fixture
        .repository
        .certificate_order_checkpoint(original.order_id)?
        .ok_or_else(|| "retired checkpoint missing".into())
}

fn restart_command(
    fixture: &Fixture,
    order_id: CertificateOrderId,
    digest: [u8; 32],
) -> AuthoritativeCommand {
    AuthoritativeCommand::CompleteCertificateOrder(CompleteCertificateOrder {
        order_id,
        claim_generation: 1,
        worker_node_id: fixture.node,
        worker_incarnation: 1,
        fence: 901,
        outcome: CertificateOrderCompletion::Restart {
            failure_digest: [8; 32],
            retry_at: UnixMicros::new(200),
            retired_checkpoint_digest: digest,
        },
    })
}
