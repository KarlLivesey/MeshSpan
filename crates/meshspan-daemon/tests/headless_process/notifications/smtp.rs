// SPDX-License-Identifier: GPL-2.0-only

//! Public settings through encrypted metadata and the owned daemon outbox to a real TLS relay.

use super::{Error, NotificationDeliveryState, ProcessFixture, Value, WorkId, json};
use std::{io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

#[tokio::test]
async fn notification_daemon_delivers_email_over_implicit_tls() -> Result<(), Box<dyn Error>> {
    prove_email(false).await
}

#[tokio::test]
async fn notification_daemon_delivers_email_over_starttls() -> Result<(), Box<dyn Error>> {
    prove_email(true).await
}

async fn prove_email(starttls: bool) -> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let mut relay = Relay::start(starttls).await?;
    let trust = root.temporary.path().join("notification-trust.pem");
    std::fs::write(&trust, &relay.anchor)?;
    let mut processes = vec![root.command().env("SSL_CERT_FILE", &trust).spawn()?];
    let proof = async {
        let claim = super::super::wait_for_claim(&root.claim_path).await?;
        let client = super::super::wait_for_client(&root.identity_path).await?;
        super::super::wait_for_status(root.address, &client, "claim_required").await?;
        let created = super::super::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("missing bootstrap key")?;
        super::super::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        let mut request = super::configuration("unused");
        request["settings"]["destination"] = json!({
            "kind": "email", "host": "localhost", "port": relay.port,
            "tls": if starttls { "starttls" } else { "implicit" },
            "username": "user", "password": "pass",
            "sender": "meshspan@example.test", "recipients": ["operator@example.test"]
        });
        assert_eq!(
            super::configure(&root, &client, key, &request).await?["sequence"],
            1
        );
        // No external CA is contacted: queuing is itself the durable event under test.
        super::queue_certificate(&root, &client, key, "https://localhost:1/events").await?;
        let message = tokio::time::timeout(Duration::from_secs(15), relay.messages.recv())
            .await?
            .ok_or("SMTP relay stopped")?;
        let event: Value = serde_json::from_str(
            message
                .lines()
                .find(|line| line.starts_with('{'))
                .ok_or("missing event JSON")?,
        )?;
        let delivery = event["delivery_id"].as_str().ok_or("missing delivery ID")?;
        assert_eq!(event["kind"], "certificate_order_queued");
        assert_eq!(event["version"], 1);
        assert_eq!(event.as_object().ok_or("invalid event")?.len(), 5);
        assert!(message.contains(&format!("Message-ID: <{delivery}@meshspan.invalid>\r\n")));
        assert!(message.contains("Subject: MeshSpan certificate_order_queued\r\n"));
        assert!(!message.contains("pass"));
        assert!(!message.contains(key));
        super::await_delivery(
            &root,
            WorkId::from_bytes(super::parse(delivery)?)?,
            NotificationDeliveryState::Accepted,
            1,
        )
        .await?;
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    super::super::stop_processes(&mut processes);
    let stopped = relay.stop().await;
    super::super::retain_failure_state(proof, [root.temporary])?;
    stopped
}

struct Relay {
    port: u16,
    anchor: String,
    messages: mpsc::Receiver<String>,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<io::Result<()>>,
}

impl Relay {
    async fn start(starttls: bool) -> Result<Self, Box<dyn Error>> {
        let (tls, anchor) = super::receiver_tls()?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let (send, messages) = mpsc::channel(4);
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            tokio::select! {
                result = serve(listener, tls, starttls, send) => result,
                _ = stopped => Ok(()),
            }
        });
        Ok(Self {
            port,
            anchor,
            messages,
            shutdown,
            task,
        })
    }

    async fn stop(self) -> Result<(), Box<dyn Error>> {
        // A failed relay may already have dropped shutdown; its observed task is authoritative.
        match self.shutdown.send(()) {
            Ok(()) | Err(()) => self.task.await??,
        }
        Ok(())
    }
}

async fn serve(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    starttls: bool,
    messages: mpsc::Sender<String>,
) -> io::Result<()> {
    loop {
        let (tcp, _) = listener.accept().await?;
        let tcp = if starttls {
            let mut stream = BufReader::new(tcp);
            stream.write_all(b"220 localhost\r\n").await?;
            exchange(
                &mut stream,
                "EHLO meshspan.invalid\r\n",
                "250-localhost\r\n250 STARTTLS\r\n",
            )
            .await?;
            exchange(&mut stream, "STARTTLS\r\n", "220 begin TLS\r\n").await?;
            assert!(stream.buffer().is_empty(), "credentials sent before TLS");
            stream.into_inner()
        } else {
            tcp
        };
        let mut stream = BufReader::new(TlsAcceptor::from(tls.clone()).accept(tcp).await?);
        if !starttls {
            stream.write_all(b"220 localhost\r\n").await?;
        }
        for (command, reply) in [
            (
                "EHLO meshspan.invalid\r\n",
                "250-localhost\r\n250 AUTH PLAIN\r\n",
            ),
            ("AUTH PLAIN AHVzZXIAcGFzcw==\r\n", "235 authenticated\r\n"),
            ("MAIL FROM:<meshspan@example.test>\r\n", "250 sender\r\n"),
            ("RCPT TO:<operator@example.test>\r\n", "250 recipient\r\n"),
            ("DATA\r\n", "354 send data\r\n"),
        ] {
            exchange(&mut stream, command, reply).await?;
        }
        let mut message = String::new();
        loop {
            let mut line = String::new();
            let count = stream.read_line(&mut line).await?;
            if count == 0 || message.len() + line.len() > 4096 {
                return Err(io::Error::other("incomplete or oversized SMTP DATA"));
            }
            message.push_str(&line);
            if line == ".\r\n" {
                break;
            }
        }
        stream.write_all(b"250 relay accepted\r\n").await?;
        messages.send(message).await.map_err(io::Error::other)?;
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufReader<S>,
    expected: &str,
    reply: &str,
) -> io::Result<()> {
    let mut line = String::new();
    stream.read_line(&mut line).await?;
    assert_eq!(line, expected);
    stream.write_all(reply.as_bytes()).await
}
