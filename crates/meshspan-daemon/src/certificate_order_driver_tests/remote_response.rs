// SPDX-License-Identifier: GPL-2.0-only

//! Remote semantic refusals are retries, not permission to replace the accepted checkpoint.

use meshspan_acme::{AcmeDirectory, AcmeMachineEvent, AcmeOrder, AcmeResourceStatus};
use serde_json::json;

use super::*;

#[tokio::test]
async fn foreign_or_unusable_authorization_is_requeued_without_advancing()
-> Result<(), Box<dyn std::error::Error>> {
    for (name, wildcard, kind) in [
        ("other.example.test", false, "http-01"),
        ("files.example.test", true, "http-01"),
        ("files.example.test", false, "dns-01"),
    ] {
        let response = json!({
            "status": "pending",
            "identifier": {"type": "dns", "value": name},
            "wildcard": wildcard,
            "challenges": [{
                "type": kind,
                "url": "https://ca.example.test/challenge/1",
                "token": "challenge-token",
                "status": "pending"
            }]
        });
        assert_requeued_unchanged(order(AcmeResourceStatus::Pending)?, response).await?;
    }
    Ok(())
}

#[tokio::test]
async fn substituted_order_resources_are_requeued_without_advancing()
-> Result<(), Box<dyn std::error::Error>> {
    for (authorization, finalize) in [
        ("authorization/other", "finalize/1"),
        ("authorization/1", "finalize/other"),
    ] {
        let response = json!({
            "status": "processing",
            "identifiers": [{"type": "dns", "value": "files.example.test"}],
            "authorizations": [format!("https://ca.example.test/{authorization}")],
            "finalize": format!("https://ca.example.test/{finalize}")
        });
        assert_requeued_unchanged(order(AcmeResourceStatus::Processing)?, response).await?;
    }
    Ok(())
}

async fn assert_requeued_unchanged(
    prepared: PreparedCertificateOrder,
    body: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let original = prepared.machine.encode_checkpoint()?;
    let authority = RecordingAuthority::default();
    let response = AcmeHttpResponse::new(
        200,
        AcmeResponseHeaders::new(vec![
            ("replay-nonce".to_owned(), "nonce-4".to_owned()),
            ("retry-after".to_owned(), "7200".to_owned()),
        ])?,
        serde_json::to_vec(&body)?,
    )?;
    let mut execution = CertificateOrderExecution::new(
        prepared,
        DirectoryTransport(Some(Ok(response))),
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
        return Err("semantic CA refusal did not queue a retry".into());
    };
    assert_eq!(failure_class, CertificateOrderFailureClass::Protocol);
    assert_eq!(commit.retry_at, UnixMicros::new(7_220_000_000));
    assert_eq!(execution.machine().encode_checkpoint()?, original);
    assert_eq!(authority.checkpoint_count(), 0);
    assert_eq!(authority.completion_count(), 1);
    let state = authority.0.lock().map_err(|_| "authority lock")?;
    assert!(matches!(
        &state.completion,
        Some(AuthoritativeCommand::CompleteCertificateOrder(command))
        if matches!(command.outcome, meshspan_metadata::CertificateOrderCompletion::Retry { .. })
    ));
    Ok(())
}

fn order(
    status: AcmeResourceStatus,
) -> Result<PreparedCertificateOrder, Box<dyn std::error::Error>> {
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
    prepared.machine.advance(AcmeMachineEvent::OrderCreated {
        order_url: "https://ca.example.test/order/1".to_owned(),
        replay_nonce: "nonce-3".to_owned(),
        order: AcmeOrder {
            status,
            dns_names: vec!["files.example.test".to_owned()],
            authorizations: vec!["https://ca.example.test/authorization/1".to_owned()],
            finalize: "https://ca.example.test/finalize/1".to_owned(),
            certificate: None,
        },
    })?;
    Ok(prepared)
}
