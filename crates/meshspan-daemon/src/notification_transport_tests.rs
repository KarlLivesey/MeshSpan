// SPDX-License-Identifier: GPL-2.0-only

use std::{sync::Arc, time::Duration};

use axum::{
    body::{Body, to_bytes},
    http::{Request, Response},
};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use meshspan_api_contract::{NotificationDestination, NotificationMailbox, NotificationSmtpTls};
use meshspan_domain::{
    AuditEventId, ComponentInstanceId, NodeId, Revision, UnixMicros, WorkId, uuid_v8,
};
use meshspan_metadata::{
    NotificationDeliveryOutcome, NotificationDeliveryRecord, NotificationDeliveryState,
    NotificationEventKind,
};
use meshspan_test_certificates::CertificateAuthority;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

use crate::NotificationTransport;

#[tokio::test]
async fn notification_webhook_sends_only_fixed_redacted_fields_with_stable_auth_and_identity()
-> Result<(), Box<dyn std::error::Error>> {
    for (code, expected) in [
        (201, NotificationDeliveryOutcome::Accepted),
        (302, NotificationDeliveryOutcome::Rejected),
        (429, NotificationDeliveryOutcome::Retry),
        (503, NotificationDeliveryOutcome::Retry),
    ] {
        let (client, server) = tls()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let delivery = delivery()?;
        let expected_id = "01010101-0101-8101-8101-010101010101".to_owned();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(|_| "accept")?;
            let tls = TlsAcceptor::from(server)
                .accept(tcp)
                .await
                .map_err(|_| "TLS")?;
            let service = service_fn(move |request: Request<Incoming>| {
                let expected_id = expected_id.clone();
                async move {
                    assert_eq!(request.method(), "POST");
                    assert_eq!(request.uri().path(), "/notify");
                    assert_eq!(
                        request.headers()["authorization"],
                        "Bearer local-notification-token"
                    );
                    assert_eq!(request.headers()["idempotency-key"], expected_id);
                    let bytes = to_bytes(Body::new(request.into_body()), 4096)
                        .await
                        .map_err(std::io::Error::other)?;
                    let event: serde_json::Value =
                        serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
                    assert_eq!(
                        event,
                        serde_json::json!({"version": 1, "delivery_id": expected_id,
                        "event_id": "02020202-0202-8202-8202-020202020202",
                        "kind": "manual_dns_task_changed", "occurred_at_epoch_micros": "1000000"})
                    );
                    Response::builder()
                        .status(code)
                        .header("Location", "https://unlisted.invalid/do-not-follow")
                        .body(Body::empty())
                        .map_err(std::io::Error::other)
                }
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await
                .map_err(|_| "HTTP")
        });
        let destination = NotificationDestination::Webhook {
            endpoint: format!("https://localhost:{port}/notify"),
            bearer_token: "local-notification-token".to_owned(),
        };
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(5),
                NotificationTransport::new(client).deliver(&destination, &delivery)
            )
            .await?,
            expected
        );
        server.await??;
    }
    Ok(())
}

#[tokio::test]
async fn notification_email_uses_real_tls_and_fresh_auth_after_starttls()
-> Result<(), Box<dyn std::error::Error>> {
    for mode in [NotificationSmtpTls::Implicit, NotificationSmtpTls::Starttls] {
        let (client, server) = tls()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.map_err(|_| "accept")?;
            let tcp = if mode == NotificationSmtpTls::Starttls {
                let mut stream = BufReader::new(tcp);
                stream
                    .write_all(b"220 localhost\r\n")
                    .await
                    .map_err(|_| "greeting")?;
                assert_line(&mut stream, "EHLO meshspan.invalid\r\n").await?;
                stream
                    .write_all(b"250-localhost\r\n250 STARTTLS\r\n")
                    .await
                    .map_err(|_| "capabilities")?;
                assert_line(&mut stream, "STARTTLS\r\n").await?;
                stream
                    .write_all(b"220 begin TLS\r\n")
                    .await
                    .map_err(|_| "STARTTLS")?;
                assert!(stream.buffer().is_empty());
                stream.into_inner()
            } else {
                tcp
            };
            let encrypted = TlsAcceptor::from(server)
                .accept(tcp)
                .await
                .map_err(|_| "TLS")?;
            let mut stream = BufReader::new(encrypted);
            if mode == NotificationSmtpTls::Implicit {
                stream
                    .write_all(b"220 localhost\r\n")
                    .await
                    .map_err(|_| "greeting")?;
            }
            receive_mail(&mut stream).await
        });
        let destination = email_destination(port, mode);
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(5),
                NotificationTransport::new(client).deliver(&destination, &delivery()?)
            )
            .await?,
            NotificationDeliveryOutcome::Accepted
        );
        let message = server.await??;
        assert!(
            message.contains(
                "Message-ID: <01010101-0101-8101-8101-010101010101@meshspan.invalid>\r\n"
            )
        );
        assert!(message.contains("Subject: MeshSpan manual_dns_task_changed\r\n"));
        assert!(message.contains("Date: Thu, 01 Jan 1970 00:00:01 GMT\r\n"));
        assert!(!message.contains("AUTH"));
        assert!(!message.contains("pass"));
        assert!(message.ends_with("\r\n.\r\n"));
    }
    Ok(())
}

#[tokio::test]
async fn notification_smtp_never_downgrades_or_sends_credentials_without_starttls()
-> Result<(), Box<dyn std::error::Error>> {
    let (client, _) = tls()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.map_err(|_| "accept")?;
        let mut stream = BufReader::new(tcp);
        stream
            .write_all(b"220 localhost\r\n")
            .await
            .map_err(|_| "greeting")?;
        assert_line(&mut stream, "EHLO meshspan.invalid\r\n").await?;
        stream
            .write_all(b"250-localhost\r\n250 AUTH PLAIN\r\n")
            .await
            .map_err(|_| "capabilities")?;
        let mut remaining = String::new();
        let count = stream.read_line(&mut remaining).await.map_err(|_| "read")?;
        assert_eq!(count, 0, "plaintext credentials or message were sent");
        Ok::<(), &'static str>(())
    });
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(5),
            NotificationTransport::new(client).deliver(
                &email_destination(port, NotificationSmtpTls::Starttls),
                &delivery()?
            )
        )
        .await?,
        NotificationDeliveryOutcome::Rejected
    );
    server.await??;
    Ok(())
}

async fn receive_mail<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufReader<S>,
) -> Result<String, &'static str> {
    for (expected, reply) in [
        (
            "EHLO meshspan.invalid\r\n",
            "250-localhost\r\n250 AUTH PLAIN\r\n",
        ),
        ("AUTH PLAIN AHVzZXIAcGFzcw==\r\n", "235 authenticated\r\n"),
        (
            "MAIL FROM:<meshspan@example.test>\r\n",
            "250 sender accepted\r\n",
        ),
        (
            "RCPT TO:<operator@example.test>\r\n",
            "250 recipient accepted\r\n",
        ),
        ("DATA\r\n", "354 send data\r\n"),
    ] {
        assert_line(stream, expected).await?;
        stream
            .write_all(reply.as_bytes())
            .await
            .map_err(|_| "reply")?;
    }
    let mut message = String::new();
    loop {
        let mut line = String::new();
        let count = stream.read_line(&mut line).await.map_err(|_| "DATA")?;
        if count == 0 || message.len() + line.len() > 4096 {
            return Err("incomplete or oversized DATA");
        }
        message.push_str(&line);
        if line == ".\r\n" {
            break;
        }
    }
    stream
        .write_all(b"250 relay accepted\r\n")
        .await
        .map_err(|_| "final reply")?;
    Ok(message)
}

async fn assert_line<S: AsyncRead + Unpin>(
    stream: &mut BufReader<S>,
    expected: &str,
) -> Result<(), &'static str> {
    let mut line = String::new();
    stream.read_line(&mut line).await.map_err(|_| "command")?;
    assert_eq!(line, expected);
    Ok(())
}

fn email_destination(port: u16, tls: NotificationSmtpTls) -> NotificationDestination {
    NotificationDestination::Email {
        host: "localhost".to_owned(),
        port,
        tls,
        username: "user".to_owned(),
        password: "pass".to_owned(),
        sender: "meshspan@example.test".to_owned(),
        recipients: vec![NotificationMailbox("operator@example.test".to_owned())],
    }
}

fn delivery() -> Result<NotificationDeliveryRecord, Box<dyn std::error::Error>> {
    Ok(NotificationDeliveryRecord {
        delivery_id: WorkId::from_bytes(uuid_v8([1; 16]))?,
        channel_id: ComponentInstanceId::from_bytes(uuid_v8([3; 16]))?,
        channel_sequence: 1,
        event_id: AuditEventId::from_bytes(uuid_v8([2; 16]))?,
        event_kind: NotificationEventKind::ManualDnsTaskChanged,
        occurred_at: UnixMicros::new(1_000_000),
        attempt: 1,
        state: NotificationDeliveryState::Claimed,
        next_attempt_at: UnixMicros::new(61_000_000),
        claim: Some((
            NodeId::from_bytes(uuid_v8([4; 16]))?,
            1,
            UnixMicros::new(61_000_000),
        )),
        revision: Revision::new(5),
    })
}

fn tls() -> Result<(Arc<ClientConfig>, Arc<ServerConfig>), Box<dyn std::error::Error>> {
    let ca = CertificateAuthority::new()?;
    let issued = ca.issue_node("localhost")?.into_parts();
    let provider = Arc::new(meshspan_rustls_provider::provider());
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(issued.0)],
            PrivatePkcs8KeyDer::from(issued.1).into(),
        )?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca.certificate_der().to_vec()))?;
    let client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok((Arc::new(client), Arc::new(server)))
}
