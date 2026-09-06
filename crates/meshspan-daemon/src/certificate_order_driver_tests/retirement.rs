// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_acme::{
    AcmeDirectory, AcmeMachineEvent, AcmeOrder, AcmeResourceStatus, AcmeRetryAfter,
};
use sha2::{Digest as _, Sha256};

#[tokio::test]
async fn retired_order_is_checkpointed_and_requeued_with_its_exact_proof_and_ca_delay()
-> Result<(), Box<dyn std::error::Error>> {
    let mut prepared = prepared()?;
    prepared
        .machine
        .advance(AcmeMachineEvent::DirectoryDiscovered(AcmeDirectory {
            new_nonce: "https://ca.example.test/nonce".to_owned(),
            new_account: "https://ca.example.test/account".to_owned(),
            new_order: "https://ca.example.test/new-order".to_owned(),
        }))?;
    prepared
        .machine
        .advance(AcmeMachineEvent::NonceAcquired("nonce-1".to_owned()))?;
    prepared.machine.advance(AcmeMachineEvent::AccountCreated {
        account_url: "https://ca.example.test/account/1".to_owned(),
        replay_nonce: "nonce-2".to_owned(),
    })?;
    prepared.machine.advance_with_retry(
        AcmeMachineEvent::OrderCreated {
            order_url: "https://ca.example.test/order/1".to_owned(),
            replay_nonce: "nonce-3".to_owned(),
            order: AcmeOrder {
                status: AcmeResourceStatus::Invalid,
                dns_names: vec!["files.example.test".to_owned()],
                authorizations: vec!["https://ca.example.test/authorization/1".to_owned()],
                finalize: "https://ca.example.test/finalize/1".to_owned(),
                certificate: None,
            },
        },
        UnixMicros::new(19_000_000),
        Some(AcmeRetryAfter::At(UnixMicros::new(3_600_000_000))),
    )?;
    // A new worker can recover the retired checkpoint before it was atomically consumed.
    prepared.machine.resume_under_fence(7)?;
    prepared
        .assignment
        .order
        .claim
        .as_mut()
        .ok_or("claim missing")?
        .fence = 7;
    let digest: [u8; 32] = Sha256::digest(prepared.machine.encode_checkpoint()?).into();
    let authority = RecordingAuthority::default();
    let mut execution = CertificateOrderExecution::new(
        prepared,
        DirectoryTransport::unavailable(),
        Http01Challenge::new(),
    );
    let outcome = driver(
        authority.clone(),
        8,
        FixedClock(UnixMicros::new(20_000_000)),
    )?
    .drive(&mut execution)
    .await?;
    let CertificateOrderDriveOutcome::Retried {
        failure_class,
        commit,
    } = outcome
    else {
        return Err("retired order was not rescheduled".into());
    };
    assert_eq!(failure_class, CertificateOrderFailureClass::Protocol);
    assert_eq!(commit.retry_at, UnixMicros::new(3_600_000_000));
    assert_eq!(authority.checkpoint_count(), 1);
    let state = authority.0.lock().map_err(|_| "authority lock")?;
    assert!(
        matches!(&state.completion, Some(AuthoritativeCommand::CompleteCertificateOrder(command))
        if matches!(command.outcome, meshspan_metadata::CertificateOrderCompletion::Restart {
            retired_checkpoint_digest, retry_at, ..
        } if retired_checkpoint_digest == digest && retry_at == commit.retry_at))
    );
    Ok(())
}
