// SPDX-License-Identifier: GPL-2.0-only

use meshspan_metadata::CertificateOrderCheckpointRecord;
use sha2::{Digest as _, Sha256};

use super::*;

#[tokio::test]
async fn legacy_receipt_recovers_its_verified_lifetime_before_any_publication_io()
-> Result<(), Box<dyn std::error::Error>> {
    let prepared = legacy_order(Some(UnixMicros::new(100))).await?;
    let original_digest = prepared.machine.publication_digest();
    let original_action = prepared.machine.action()?;
    let challenge = Http01Challenge::new();
    let mut execution =
        CertificateOrderExecution::new(prepared, OneResponseTransport(None), challenge.clone());
    let authority = RecordingCheckpointAuthority::default();
    let checkpoint = CertificateOrderCheckpointService::new(&authority);
    let mut context = request_context()?;
    context.deadline = UnixMicros::new(50);
    let actor = PrincipalId::from_bytes([2; 16])?;
    execution
        .execute_step(
            &checkpoint,
            actor,
            &FixedClock(UnixMicros::new(21)),
            context,
            UnixMicros::new(200),
        )
        .await?;
    assert_eq!(authority.commit_count()?, 1);
    assert_eq!(challenge.response("token-1", UnixMicros::new(21))?, None);
    let publication = execution
        .machine()
        .publication()
        .ok_or("missing recovered publication")?;
    assert_eq!(publication.expires_at(), UnixMicros::new(100));
    assert_eq!(publication.order_epoch(), 55);
    assert_eq!(execution.machine().order_epoch(), 7);
    assert_eq!(execution.machine().action()?, original_action);
    assert_eq!(execution.machine().publication_digest(), original_digest);
    assert_eq!(
        execution
            .execute_step(
                &checkpoint,
                actor,
                &FixedClock(UnixMicros::new(21)),
                context,
                UnixMicros::new(200)
            )
            .await?,
        CertificateOrderStepResult::Pending
    );
    assert_eq!(
        challenge.response("token-1", UnixMicros::new(99))?,
        Some(b"token-1.xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M".to_vec())
    );
    assert_eq!(challenge.response("token-1", UnixMicros::new(100))?, None);
    assert_eq!(execution.machine().action()?, original_action);
    assert_eq!(authority.commit_count()?, 1);
    Ok(())
}

#[tokio::test]
async fn a_missing_or_mismatched_legacy_lifetime_cannot_become_a_new_publication()
-> Result<(), Box<dyn std::error::Error>> {
    for candidate in [None, Some(UnixMicros::new(101))] {
        let prepared = legacy_order(candidate).await?;
        let original = prepared.machine.encode_checkpoint()?;
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
            .await;
        assert!(matches!(
            result,
            Err(crate::CertificateOrderExecutionError::Worker(
                meshspan_acme::AcmeWorkerError::InvalidInput
            ))
        ));
        assert_eq!(execution.machine().encode_checkpoint()?, original);
        assert_eq!(authority.commit_count()?, 0);
        assert_eq!(challenge.response("token-1", UnixMicros::new(21))?, None);
    }
    Ok(())
}

#[tokio::test]
async fn a_fresh_challenge_does_not_reuse_the_previous_legacy_lifetime()
-> Result<(), Box<dyn std::error::Error>> {
    let mut prepared = legacy_order(Some(UnixMicros::new(100))).await?;
    prepared.machine = publication_order()?.machine;
    prepared.machine.resume_under_fence(7)?;
    let challenge = Http01Challenge::new();
    let mut execution =
        CertificateOrderExecution::new(prepared, OneResponseTransport(None), challenge.clone());
    let authority = RecordingCheckpointAuthority::default();
    let mut context = request_context()?;
    context.deadline = UnixMicros::new(50);
    execution
        .execute_step(
            &CertificateOrderCheckpointService::new(&authority),
            PrincipalId::from_bytes([2; 16])?,
            &FixedClock(UnixMicros::new(21)),
            context,
            UnixMicros::new(180),
        )
        .await?;
    let publication = execution
        .machine()
        .publication()
        .ok_or("missing publication")?;
    assert_eq!(publication.expires_at(), UnixMicros::new(180));
    assert_eq!(publication.order_epoch(), 7);
    assert_eq!(authority.commit_count()?, 1);
    assert_eq!(challenge.response("token-1", UnixMicros::new(21))?, None);
    Ok(())
}

async fn legacy_order(
    candidate: Option<UnixMicros>,
) -> Result<PreparedCertificateOrder, Box<dyn std::error::Error>> {
    let (mut prepared, _) = published_order_with_expiry(100).await?;
    let claim = prepared.assignment.order.claim.ok_or("missing claim")?;
    let mut legacy: serde_json::Value =
        serde_json::from_slice(&prepared.machine.encode_checkpoint()?)?;
    legacy["version"] = serde_json::Value::from(2);
    legacy["machine"]
        .as_object_mut()
        .ok_or("missing machine")?
        .remove("publication");
    let bytes = serde_json::to_vec(&legacy)?;
    prepared.machine = AcmeOrderMachine::decode_checkpoint(&bytes)?;
    prepared.assignment.checkpoint = Some(CertificateOrderCheckpointRecord {
        order_id: prepared.assignment.order.order_id,
        claim_generation: claim.generation,
        worker_node_id: claim.worker_node_id,
        worker_incarnation: claim.worker_incarnation,
        fence: claim.fence,
        certificate_key: prepared.certificate_key_reference,
        checkpoint_digest: Sha256::digest(&bytes).into(),
        checkpoint: bytes,
        legacy_lease_expiry_candidate: candidate,
        revision: Revision::new(10),
    });
    replace_worker(&mut prepared)?;
    Ok(prepared)
}
