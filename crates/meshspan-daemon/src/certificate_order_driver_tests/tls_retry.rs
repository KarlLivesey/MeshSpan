// SPDX-License-Identifier: GPL-2.0-only

//! Real CA-side TLS response through the ACME client, executor and authoritative retry command.

use std::sync::{
    Arc,
    atomic::{AtomicI64, AtomicUsize, Ordering},
};
use std::time::Duration;

use axum::{Router, http::StatusCode, routing::get};
use meshspan_acme::RustlsAcmeTransport;
use rustls::{ClientConfig, ServerConfig, pki_types::PrivatePkcs8KeyDer};
use tokio::sync::oneshot;

use super::*;

#[tokio::test]
async fn tls_ca_deadline_is_committed_without_an_immediate_second_request()
-> Result<(), Box<dyn std::error::Error>> {
    assert_tls_retry(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        UnixMicros::new(784_111_777_000_000),
    )
    .await
}

#[tokio::test]
async fn tls_relative_delay_starts_when_the_response_arrives_not_when_the_request_started()
-> Result<(), Box<dyn std::error::Error>> {
    assert_tls_retry("3600", UnixMicros::new(3_625_000_000)).await
}

async fn assert_tls_retry(
    hint: &'static str,
    expected: UnixMicros,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca = CertificateAuthority::new()?;
    let issued = ca.issue_node("localhost")?.into_parts();
    let tls = ServerConfig::builder_with_provider(Arc::new(meshspan_rustls_provider::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(issued.0)],
            PrivatePkcs8KeyDer::from(issued.1).into(),
        )?;
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let clock = ResponseClock(Arc::new(AtomicI64::new(20_000_000)));
    let response_clock = Arc::clone(&clock.0);
    let router = Router::new().route(
        "/directory",
        get(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            response_clock.store(25_000_000, Ordering::SeqCst);
            async move {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [("retry-after", hint)],
                    "temporarily unavailable",
                )
            }
        }),
    );
    let server = crate::HttpsServer::bind("127.0.0.1:0".parse()?, Arc::new(tls), router).await?;
    let endpoint = format!(
        "https://localhost:{}/directory",
        server.local_addr()?.port()
    );
    let transport = client(&ca)?;
    let authority = RecordingAuthority::default();
    let mut prepared = prepared()?;
    prepared
        .assignment
        .configuration
        .directory_url
        .clone_from(&endpoint);
    prepared.machine = AcmeOrderMachine::new(
        endpoint,
        AcmeOrderRequest::new(prepared.assignment.configuration.certificate_names.clone())?,
        AcmeChallengePreference::Http01,
        55,
    )?;
    let mut execution = CertificateOrderExecution::new(prepared, transport, Http01Challenge::new());
    let mut driver = driver(authority.clone(), 8, clock)?;
    let (stop, stopped) = oneshot::channel();
    let worker = tokio::spawn(server.run_until(async {
        drop(stopped.await);
    }));
    let outcome = driver.drive(&mut execution).await;
    stop.send(())
        .map_err(|()| "TLS fixture stopped unexpectedly")?;
    worker.await??;

    let CertificateOrderDriveOutcome::Retried { commit, .. } = outcome? else {
        return Err("TLS CA retry must produce an authoritative retry receipt".into());
    };
    assert_eq!(commit.retry_at, expected);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert_eq!(authority.checkpoint_count(), 0);
    assert_eq!(authority.completion_count(), 1);
    assert_eq!(authority.retry_deadline(), Some(expected));
    Ok(())
}

struct ResponseClock(Arc<AtomicI64>);

impl Clock for ResponseClock {
    fn now(&self) -> UnixMicros {
        UnixMicros::new(self.0.load(Ordering::SeqCst))
    }
}

fn client(ca: &CertificateAuthority) -> Result<RustlsAcmeTransport, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca.certificate_der().to_vec()))?;
    let config =
        ClientConfig::builder_with_provider(Arc::new(meshspan_rustls_provider::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(RustlsAcmeTransport::new(
        Arc::new(config),
        Duration::from_secs(2),
        Duration::from_secs(2),
    )?)
}
