// SPDX-License-Identifier: GPL-2.0-only

//! Valid server guidance survives rejection of any remote action's response payload.

use super::*;

#[tokio::test]
async fn malformed_successful_payload_retains_valid_retry_guidance()
-> Result<(), Box<dyn std::error::Error>> {
    for action in actions()? {
        for (header, expected) in [
            ("120", AcmeRetryAfter::DelayMicros(120_000_000)),
            (
                "Sun, 06 Nov 1994 08:49:37 GMT",
                AcmeRetryAfter::At(UnixMicros::new(784_111_777_000_000)),
            ),
        ] {
            let mut executor = AcmeStepExecutor::new(
                RecordingTransport::new([response(
                    200,
                    vec![("retry-after", header)],
                    Vec::new(),
                )?]),
                RecordingSigner::default(),
                Http01Challenge::new(),
            );
            assert_eq!(
                executor.execute(&action, execution()?).await,
                Err(AcmeWorkerError::RemoteRetry {
                    retry_after: Some(expected)
                }),
                "{action:?}"
            );
            assert_eq!(executor.into_parts().0.requests.len(), 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn malformed_payload_with_absent_or_invalid_guidance_uses_no_server_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    for action in actions()? {
        for headers in [
            Vec::new(),
            vec![("retry-after", "invalid")],
            vec![("retry-after", "120"), ("retry-after", "120")],
        ] {
            let mut executor = AcmeStepExecutor::new(
                RecordingTransport::new([response(200, headers, Vec::new())?]),
                RecordingSigner::default(),
                Http01Challenge::new(),
            );
            assert_eq!(
                executor.execute(&action, execution()?).await,
                Err(AcmeWorkerError::Protocol)
            );
            assert_eq!(executor.into_parts().0.requests.len(), 1);
        }
    }
    Ok(())
}

fn actions() -> Result<Vec<AcmeMachineAction>, Box<dyn std::error::Error>> {
    let url = "https://ca.example.test/resource".to_owned();
    let nonce = "nonce_1".to_owned();
    let account_url = "https://ca.example.test/account/1".to_owned();
    let mut actions = polling::actions()?;
    actions.extend([
        AcmeMachineAction::DiscoverDirectory { url: url.clone() },
        AcmeMachineAction::AcquireNonce { url: url.clone() },
        AcmeMachineAction::CreateAccount {
            url: url.clone(),
            nonce: nonce.clone(),
        },
        AcmeMachineAction::FetchAuthorization {
            url: url.clone(),
            nonce: nonce.clone(),
            account_url: account_url.clone(),
        },
        AcmeMachineAction::DownloadCertificate {
            url,
            nonce,
            account_url,
        },
    ]);
    Ok(actions)
}
