// SPDX-License-Identifier: GPL-2.0-only

use meshspan_acme::{
    AcmeAuthorization, AcmeChallengeRecord, AcmeDirectory, AcmeMachineAction, AcmeMachineEvent,
    AcmeOrder, AcmeResourceStatus,
};

use super::*;

mod legacy;

#[tokio::test]
async fn exact_challenge_material_is_checkpointed_before_publisher_io()
-> Result<(), Box<dyn std::error::Error>> {
    let challenge = Http01Challenge::new();
    let mut execution = CertificateOrderExecution::new(
        publication_order()?,
        OneResponseTransport(None),
        challenge.clone(),
    );
    let authority = RecordingCheckpointAuthority::default();
    let checkpoint = CertificateOrderCheckpointService::new(&authority);
    let now = UnixMicros::new(20);
    let mut context = request_context()?;
    context.deadline = UnixMicros::new(50);
    let actor = PrincipalId::from_bytes([2; 16])?;
    execution
        .execute_step(
            &checkpoint,
            actor,
            &FixedClock(now),
            context,
            UnixMicros::new(80),
        )
        .await?;
    assert_eq!(challenge.response("token-1", now)?, None);
    assert!(matches!(
        execution.machine().action()?,
        AcmeMachineAction::PublishChallenge { .. }
    ));
    let retained = execution
        .machine()
        .publication()
        .ok_or("missing publication")?;
    assert_eq!(retained.order_epoch(), 55);
    assert_eq!(retained.expires_at(), UnixMicros::new(80));
    assert_eq!(authority.commit_count()?, 1);

    // A later scheduling input must not silently change the already committed identity.
    execution
        .execute_step(
            &checkpoint,
            actor,
            &FixedClock(now),
            context,
            UnixMicros::new(99),
        )
        .await?;
    assert!(challenge.response("token-1", now)?.is_some());
    assert!(matches!(
        execution.machine().action()?,
        AcmeMachineAction::NotifyChallenge { .. }
    ));
    assert_eq!(
        execution
            .machine()
            .publication()
            .ok_or("missing publication")?
            .expires_at(),
        UnixMicros::new(80)
    );
    assert_eq!(authority.commit_count()?, 2);
    Ok(())
}

#[tokio::test]
async fn failed_prepublication_checkpoint_cannot_become_executable_on_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let prepared = publication_order()?;
    let original = prepared.machine.encode_checkpoint()?;
    let challenge = Http01Challenge::new();
    let mut execution =
        CertificateOrderExecution::new(prepared, OneResponseTransport(None), challenge.clone());
    let checkpoint = CertificateOrderCheckpointService::new(RefusingCheckpointAuthority);
    let mut context = request_context()?;
    context.deadline = UnixMicros::new(50);
    for _ in 0..2 {
        let outcome = execution
            .execute_step(
                &checkpoint,
                PrincipalId::from_bytes([2; 16])?,
                &FixedClock(UnixMicros::new(20)),
                context,
                UnixMicros::new(80),
            )
            .await;
        assert!(matches!(
            outcome,
            Err(crate::CertificateOrderExecutionError::Checkpoint(_))
        ));
        assert_eq!(execution.machine().encode_checkpoint()?, original);
        assert_eq!(challenge.response("token-1", UnixMicros::new(20))?, None);
    }
    Ok(())
}

struct RefusingCheckpointAuthority;

impl CertificateOrderCheckpointAuthority for RefusingCheckpointAuthority {
    fn resolve_certificate_order_checkpoint(
        &self,
        _operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, CertificateOrderCheckpointAuthorityError> {
        Ok(None)
    }

    fn checkpoint_certificate_order(
        &self,
        _context: CommandContext,
        _command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, CertificateOrderCheckpointAuthorityError> {
        Err(CertificateOrderCheckpointAuthorityError::Failed)
    }
}

#[tokio::test]
async fn replacement_worker_restores_visibility_without_repeating_ca_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut prepared, _) = published_order().await?;
    prepared
        .machine
        .advance(AcmeMachineEvent::ChallengeNotified {
            replay_nonce: "nonce-5".to_owned(),
        })?;
    let original_action = prepared.machine.action()?;
    let original_digest = prepared.machine.publication_digest();
    replace_worker(&mut prepared)?;
    let challenge = Http01Challenge::new();
    let mut execution =
        CertificateOrderExecution::new(prepared, OneResponseTransport(None), challenge.clone());
    let authority = RecordingCheckpointAuthority::default();
    let mut context = request_context()?;
    context.deadline = UnixMicros::new(50);
    let result = execution
        .execute_step(
            &CertificateOrderCheckpointService::new(&authority),
            PrincipalId::from_bytes([2; 16])?,
            &FixedClock(UnixMicros::new(21)),
            context,
            UnixMicros::new(200),
        )
        .await?;
    assert_eq!(result, CertificateOrderStepResult::Pending);
    assert_eq!(execution.machine().action()?, original_action);
    assert_eq!(execution.machine().publication_digest(), original_digest);
    assert_eq!(execution.machine().order_epoch(), 7);
    assert_eq!(execution.machine().publication_epoch(), Some(55));
    assert_eq!(authority.commit_count()?, 0);
    assert_eq!(
        challenge.response("token-1", UnixMicros::new(79))?,
        Some(b"token-1.xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M".to_vec())
    );
    assert_eq!(challenge.response("token-1", UnixMicros::new(80))?, None);
    Ok(())
}

#[tokio::test]
async fn replacement_worker_cleans_the_original_expired_receipt_without_republication()
-> Result<(), Box<dyn std::error::Error>> {
    for restart_with_empty_catalogue in [false, true] {
        let (mut prepared, original_catalogue) = published_order().await?;
        prepared
            .machine
            .advance(AcmeMachineEvent::ChallengeNotified {
                replay_nonce: "nonce-5".to_owned(),
            })?;
        prepared
            .machine
            .advance(AcmeMachineEvent::AuthorizationPolled {
                authorization: authorization(AcmeResourceStatus::Valid),
                replay_nonce: "nonce-6".to_owned(),
            })?;
        replace_worker(&mut prepared)?;
        let challenge = if restart_with_empty_catalogue {
            Http01Challenge::new()
        } else {
            original_catalogue
        };
        let mut execution =
            CertificateOrderExecution::new(prepared, OneResponseTransport(None), challenge.clone());
        let authority = RecordingCheckpointAuthority::default();
        let mut context = request_context()?;
        context.deadline = UnixMicros::new(150);
        let result = execution
            .execute_step(
                &CertificateOrderCheckpointService::new(&authority),
                PrincipalId::from_bytes([2; 16])?,
                &FixedClock(UnixMicros::new(120)),
                context,
                UnixMicros::new(200),
            )
            .await?;
        assert!(matches!(
            result,
            CertificateOrderStepResult::Checkpointed(_)
        ));
        assert!(matches!(
            execution.machine().action()?,
            AcmeMachineAction::PollOrder { .. }
        ));
        assert_eq!(challenge.response("token-1", UnixMicros::new(20))?, None);
        assert_eq!(authority.commit_count()?, 1);
    }
    Ok(())
}

fn replace_worker(
    prepared: &mut PreparedCertificateOrder,
) -> Result<(), Box<dyn std::error::Error>> {
    prepared.machine = AcmeOrderMachine::decode_checkpoint(&prepared.machine.encode_checkpoint()?)?;
    prepared.machine.resume_under_fence(7)?;
    let claim = prepared
        .assignment
        .order
        .claim
        .as_mut()
        .ok_or("missing claim")?;
    claim.generation = 2;
    claim.fence = 7; // Worker fences are opaque, not monotonic counters.
    claim.lease_expires_at = UnixMicros::new(200);
    Ok(())
}

async fn published_order()
-> Result<(PreparedCertificateOrder, Http01Challenge), Box<dyn std::error::Error>> {
    published_order_with_expiry(80).await
}

async fn published_order_with_expiry(
    expires_at: i64,
) -> Result<(PreparedCertificateOrder, Http01Challenge), Box<dyn std::error::Error>> {
    let challenge = Http01Challenge::new();
    let authority = RecordingCheckpointAuthority::default();
    let mut execution = CertificateOrderExecution::new(
        publication_order()?,
        OneResponseTransport(None),
        challenge.clone(),
    );
    let mut context = request_context()?;
    context.deadline = UnixMicros::new(50);
    for _ in 0..2 {
        execution
            .execute_step(
                &CertificateOrderCheckpointService::new(&authority),
                PrincipalId::from_bytes([2; 16])?,
                &FixedClock(UnixMicros::new(20)),
                context,
                UnixMicros::new(expires_at),
            )
            .await?;
    }
    let mut prepared = publication_order()?;
    prepared.machine = execution.machine().clone();
    Ok((prepared, challenge))
}

fn publication_order() -> Result<PreparedCertificateOrder, Box<dyn std::error::Error>> {
    let mut value = prepared(CertificateOrderId::from_bytes([1; 16])?)?;
    value
        .machine
        .advance(AcmeMachineEvent::DirectoryDiscovered(AcmeDirectory {
            new_nonce: "https://ca.example.test/nonce".to_owned(),
            new_account: "https://ca.example.test/account".to_owned(),
            new_order: "https://ca.example.test/new-order".to_owned(),
        }))?;
    value
        .machine
        .advance(AcmeMachineEvent::NonceAcquired("nonce-1".to_owned()))?;
    value.machine.advance(AcmeMachineEvent::AccountCreated {
        account_url: "https://ca.example.test/account/1".to_owned(),
        replay_nonce: "nonce-2".to_owned(),
    })?;
    value.machine.advance(AcmeMachineEvent::OrderCreated {
        order_url: "https://ca.example.test/order/1".to_owned(),
        order: AcmeOrder {
            status: AcmeResourceStatus::Pending,
            dns_names: vec!["files.example.test".to_owned()],
            authorizations: vec!["https://ca.example.test/authorization/1".to_owned()],
            finalize: "https://ca.example.test/finalize/1".to_owned(),
            certificate: None,
        },
        replay_nonce: "nonce-3".to_owned(),
    })?;
    value
        .machine
        .advance(AcmeMachineEvent::AuthorizationFetched {
            authorization: authorization(AcmeResourceStatus::Pending),
            replay_nonce: "nonce-4".to_owned(),
        })?;
    Ok(value)
}

fn authorization(status: AcmeResourceStatus) -> AcmeAuthorization {
    AcmeAuthorization {
        dns_name: "files.example.test".to_owned(),
        wildcard: false,
        status,
        challenges: vec![AcmeChallengeRecord {
            kind: "http-01".to_owned(),
            url: "https://ca.example.test/challenge/1".to_owned(),
            token: "token-1".to_owned(),
            status,
        }],
    }
}
