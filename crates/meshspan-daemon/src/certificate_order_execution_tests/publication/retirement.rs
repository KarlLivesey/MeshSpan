// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[tokio::test]
async fn expired_publication_is_checkpointed_then_cleaned_without_contacting_the_ca()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut prepared, challenge) = published_order().await?;
    prepared.machine.advance_with_retry(
        AcmeMachineEvent::ChallengeNotified {
            replay_nonce: "nonce-5".to_owned(),
        },
        UnixMicros::new(30),
        Some(meshspan_acme::AcmeRetryAfter::DelayMicros(1_000)),
    )?;
    replace_worker(&mut prepared)?;
    let retained = prepared.machine.publication().cloned();
    let digest = prepared.machine.publication_digest();
    let before = prepared.machine.clone();
    assert!(
        prepared
            .machine
            .expire_publication(UnixMicros::new(80), [22; 32])
            .is_err()
    );
    assert_eq!(prepared.machine, before);
    let mut execution =
        CertificateOrderExecution::new(prepared, OneResponseTransport(None), challenge.clone());
    let authority = RecordingCheckpointAuthority::default();
    let checkpoint = CertificateOrderCheckpointService::new(&authority);
    let mut context = request_context()?;
    context.deadline = UnixMicros::new(150);
    let clock = FixedClock(UnixMicros::new(80));
    let actor = PrincipalId::from_bytes([2; 16])?;
    execution
        .execute_step(&checkpoint, actor, &clock, context, UnixMicros::new(200))
        .await?;
    assert_eq!(
        execution.machine().retirement_reason(),
        Some(meshspan_acme::AcmeOrderRetirementReason::PublicationExpired)
    );
    assert_eq!(execution.machine().publication(), retained.as_ref());
    assert_eq!(execution.machine().publication_digest(), digest);
    // Observe the catalogue at a pre-expiry instant: retirement intent alone did not remove it.
    assert!(
        challenge
            .response("token-1", UnixMicros::new(20))?
            .is_some()
    );
    execution
        .execute_step(&checkpoint, actor, &clock, context, UnixMicros::new(200))
        .await?;
    assert_eq!(challenge.response("token-1", UnixMicros::new(20))?, None);
    assert_eq!(
        execution.machine().action()?,
        AcmeMachineAction::Retired {
            reason: meshspan_acme::AcmeOrderRetirementReason::PublicationExpired,
        }
    );
    assert_eq!(
        execution.machine().poll_not_before(),
        Some(UnixMicros::new(1_030))
    );
    assert_eq!(
        execution
            .execute_step(&checkpoint, actor, &clock, context, UnixMicros::new(200))
            .await?,
        CertificateOrderStepResult::Retired
    );
    // Returning the already-bound retired state resolves the same checkpoint receipt.
    assert_eq!(authority.commit_count()?, 2);
    Ok(())
}

#[tokio::test]
async fn failed_retirement_checkpoint_never_cleans_or_changes_the_running_state()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut prepared, challenge) = published_order().await?;
    replace_worker(&mut prepared)?;
    let original = prepared.machine.clone();
    let mut execution =
        CertificateOrderExecution::new(prepared, OneResponseTransport(None), challenge.clone());
    let mut context = request_context()?;
    context.deadline = UnixMicros::new(150);
    let result = execution
        .execute_step(
            &CertificateOrderCheckpointService::new(RefusingCheckpointAuthority),
            PrincipalId::from_bytes([2; 16])?,
            &FixedClock(UnixMicros::new(80)),
            context,
            UnixMicros::new(200),
        )
        .await;
    assert!(matches!(
        result,
        Err(crate::CertificateOrderExecutionError::Checkpoint(_))
    ));
    assert_eq!(execution.machine(), &original);
    assert!(
        challenge
            .response("token-1", UnixMicros::new(20))?
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn never_published_material_can_expire_and_complete_idempotent_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut prepared, _) = published_order().await?;
    let publication = prepared
        .machine
        .publication()
        .cloned()
        .ok_or("missing material")?;
    prepared.machine = publication_order()?.machine;
    prepared.machine.retain_publication(publication)?;
    assert_eq!(prepared.machine.publication_digest(), None);
    assert!(
        !prepared
            .machine
            .expire_publication(UnixMicros::new(79), [8; 32])?
    );
    replace_worker(&mut prepared)?;
    let mut execution = CertificateOrderExecution::new(
        prepared,
        OneResponseTransport(None),
        Http01Challenge::new(),
    );
    let authority = RecordingCheckpointAuthority::default();
    let checkpoint = CertificateOrderCheckpointService::new(&authority);
    let mut context = request_context()?;
    context.deadline = UnixMicros::new(150);
    for _ in 0..2 {
        execution
            .execute_step(
                &checkpoint,
                PrincipalId::from_bytes([2; 16])?,
                &FixedClock(UnixMicros::new(80)),
                context,
                UnixMicros::new(200),
            )
            .await?;
    }
    assert!(matches!(
        execution.machine().action()?,
        AcmeMachineAction::Retired { .. }
    ));
    Ok(())
}
