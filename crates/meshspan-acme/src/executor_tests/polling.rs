// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[tokio::test]
async fn every_successful_polling_transition_preserves_validated_retry_guidance()
-> Result<(), Box<dyn std::error::Error>> {
    for action in actions()? {
        for (header, expected) in [
            ("120", AcmeRetryAfter::DelayMicros(120_000_000)),
            (
                "Sun, 06 Nov 1994 08:49:37 GMT",
                AcmeRetryAfter::At(UnixMicros::new(784_111_777_000_000)),
            ),
        ] {
            let transport = RecordingTransport::new([response(
                200,
                vec![
                    ("replay-nonce", "nonce_2"),
                    ("retry-after", header),
                    ("location", "https://ca.example.test/orders/1"),
                ],
                body(&action)?,
            )?]);
            let mut executor = AcmeStepExecutor::new(
                transport,
                RecordingSigner::default(),
                Http01Challenge::new(),
            );
            assert!(matches!(executor.execute(&action, execution()?).await?,
                AcmeStepOutcome::AdvancedWithRetry { retry_after, .. } if retry_after == expected));
            assert_eq!(executor.into_parts().0.requests.len(), 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn ambiguous_successful_hints_fail_without_an_inline_retry()
-> Result<(), Box<dyn std::error::Error>> {
    for action in actions()? {
        let transport = RecordingTransport::new([response(
            200,
            vec![
                ("replay-nonce", "nonce_2"),
                ("retry-after", "120"),
                ("retry-after", "120"),
                ("location", "https://ca.example.test/orders/1"),
            ],
            body(&action)?,
        )?]);
        let mut executor = AcmeStepExecutor::new(
            transport,
            RecordingSigner::default(),
            Http01Challenge::new(),
        );
        assert_eq!(
            executor.execute(&action, execution()?).await,
            Err(AcmeWorkerError::Protocol)
        );
        assert_eq!(executor.into_parts().0.requests.len(), 1);
    }
    Ok(())
}

fn actions() -> Result<Vec<AcmeMachineAction>, Box<dyn std::error::Error>> {
    let url = "https://ca.example.test/resource".to_owned();
    let nonce = "nonce_1".to_owned();
    let account_url = "https://ca.example.test/account/1".to_owned();
    Ok(vec![
        AcmeMachineAction::CreateOrder {
            url: url.clone(),
            nonce: nonce.clone(),
            account_url: account_url.clone(),
            request: crate::AcmeOrderRequest::new(vec!["files.example.test".to_owned()])?,
        },
        AcmeMachineAction::NotifyChallenge {
            url: url.clone(),
            nonce: nonce.clone(),
            account_url: account_url.clone(),
        },
        AcmeMachineAction::PollAuthorization {
            url: url.clone(),
            nonce: nonce.clone(),
            account_url: account_url.clone(),
        },
        AcmeMachineAction::FinalizeOrder {
            url: url.clone(),
            nonce: nonce.clone(),
            account_url: account_url.clone(),
        },
        AcmeMachineAction::PollOrder {
            url,
            nonce,
            account_url,
        },
    ])
}

fn body(action: &AcmeMachineAction) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&match action {
        AcmeMachineAction::PollAuthorization { .. } => json!({
            "status": "pending", "identifier": {"type": "dns", "value": "files.example.test"},
            "challenges": [{"type": "http-01", "url": "https://ca.example.test/challenge/1", "token": "token_1", "status": "pending"}]
        }),
        AcmeMachineAction::NotifyChallenge { .. } => json!({"status": "processing"}),
        _ => json!({
            "status": "processing", "identifiers": [{"type": "dns", "value": "files.example.test"}],
            "authorizations": ["https://ca.example.test/authorization/1"], "finalize": "https://ca.example.test/finalize/1"
        }),
    })
}
