// SPDX-License-Identifier: GPL-2.0-only

use base64::Engine as _;
use meshspan_acme::AcmeResourceStatus;

use super::*;

#[tokio::test]
async fn malformed_successful_body_commits_the_ca_retry_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    assert_retried(
        prepared()?,
        Vec::new(),
        CertificateOrderFailureClass::Protocol,
    )
    .await
}

#[tokio::test]
async fn malformed_downloaded_certificate_retains_the_ca_retry_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    assert_retried(
        remote_response::order(AcmeResourceStatus::Valid)?,
        b"not a certificate".to_vec(),
        CertificateOrderFailureClass::Certificate,
    )
    .await
}

#[tokio::test]
async fn untrusted_downloaded_certificate_is_requeued_instead_of_stopping_the_worker()
-> Result<(), Box<dyn std::error::Error>> {
    let prepared = remote_response::order(AcmeResourceStatus::Valid)?;
    let certificate = CertificateAuthority::new()?.issue_public_endpoint(
        &prepared.assignment.configuration.certificate_names,
        &prepared.certificate_key,
    )?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(certificate);
    let pem =
        format!("-----BEGIN CERTIFICATE-----\n{encoded}\n-----END CERTIFICATE-----\n").into_bytes();
    assert_retried(prepared, pem, CertificateOrderFailureClass::Certificate).await
}

async fn assert_retried(
    mut prepared: PreparedCertificateOrder,
    body: Vec<u8>,
    expected_class: CertificateOrderFailureClass,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = crate::OperatingSystemClock.now();
    prepared
        .assignment
        .order
        .claim
        .as_mut()
        .ok_or("claim missing")?
        .lease_expires_at = now
        .checked_add(DurationMicros::new(120_000_000))
        .ok_or("time overflow")?;
    let original = prepared.machine.encode_checkpoint()?;
    let authority = RecordingAuthority::default();
    let response = AcmeHttpResponse::new(
        200,
        AcmeResponseHeaders::new(vec![("retry-after".to_owned(), "7200".to_owned())])?,
        body,
    )?;
    let mut execution = CertificateOrderExecution::new(
        prepared,
        DirectoryTransport(Some(Ok(response))),
        Http01Challenge::new(),
    );
    let outcome = driver(authority.clone(), 8, FixedClock(now))?
        .drive(&mut execution)
        .await?;
    let CertificateOrderDriveOutcome::Retried {
        failure_class,
        commit,
    } = outcome
    else {
        return Err("rejected CA result did not retry".into());
    };
    assert_eq!(failure_class, expected_class);
    assert_eq!(commit.retry_at.get(), now.get() + 7_200_000_000);
    assert_eq!(authority.checkpoint_count(), 0);
    assert_eq!(authority.completion_count(), 1);
    assert_eq!(execution.machine().encode_checkpoint()?, original);
    Ok(())
}
