// SPDX-License-Identifier: GPL-2.0-only

//! A hostile CA poll cannot replace or clean the exact already-published challenge.

use meshspan_acme::AcmeMachineError;
use serde_json::json;

use super::*;

#[tokio::test]
async fn substituted_challenge_poll_preserves_the_accepted_publication()
-> Result<(), Box<dyn std::error::Error>> {
    for (kind, url, token) in [
        (
            "http-01",
            "https://ca.example.test/challenge/1",
            "other-token",
        ),
        (
            "http-01",
            "https://ca.example.test/challenge/other",
            "token-1",
        ),
        ("dns-01", "https://ca.example.test/challenge/1", "token-1"),
    ] {
        let body = json!({
            "status": "pending",
            "identifier": {"type": "dns", "value": "files.example.test"},
            "challenges": [{"type": kind, "url": url, "token": token, "status": "pending"}]
        });
        let expected_error = if kind == "dns-01" {
            AcmeMachineError::UnsupportedChallenge
        } else {
            AcmeMachineError::InvalidRemoteState
        };
        assert_publication_preserved(body, expected_error).await?;
    }
    Ok(())
}

async fn assert_publication_preserved(
    body: serde_json::Value,
    expected_error: AcmeMachineError,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut prepared, challenge) = published_order().await?;
    prepared
        .machine
        .advance(AcmeMachineEvent::ChallengeNotified {
            replay_nonce: "nonce-5".to_owned(),
        })?;
    let original = prepared.machine.encode_checkpoint()?;
    let published_bytes = challenge.response("token-1", UnixMicros::new(40))?;
    assert!(published_bytes.is_some());
    let response = AcmeHttpResponse::new(
        200,
        AcmeResponseHeaders::new(vec![
            ("replay-nonce".to_owned(), "nonce-6".to_owned()),
            ("retry-after".to_owned(), "3600".to_owned()),
        ])?,
        serde_json::to_vec(&body)?,
    )?;
    let mut execution = CertificateOrderExecution::new(
        prepared,
        OneResponseTransport(Some(response)),
        challenge.clone(),
    );
    let authority = RecordingCheckpointAuthority::default();
    let checkpoint = CertificateOrderCheckpointService::new(&authority);
    let actor = PrincipalId::from_bytes([2; 16])?;
    let mut context = request_context()?;
    context.deadline = UnixMicros::new(70);
    let clock = FixedClock(UnixMicros::new(40));
    // A resumed executor independently restores visibility before any CA poll.
    assert_eq!(
        execution
            .execute_step(&checkpoint, actor, &clock, context, UnixMicros::new(80))
            .await?,
        CertificateOrderStepResult::Pending
    );
    let result = execution
        .execute_step(&checkpoint, actor, &clock, context, UnixMicros::new(80))
        .await;
    assert!(
        matches!(result, Err(crate::CertificateOrderExecutionError::RejectedResponse {
        reason, retry_not_before: Some(instant)
    }) if reason == expected_error && instant == UnixMicros::new(3_600_000_040))
    );
    assert_eq!(execution.machine().encode_checkpoint()?, original);
    assert_eq!(authority.commit_count()?, 0);
    assert_eq!(
        challenge.response("token-1", UnixMicros::new(40))?,
        published_bytes
    );
    assert_eq!(
        challenge.response("other-token", UnixMicros::new(40))?,
        None
    );
    Ok(())
}
