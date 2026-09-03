// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use meshspan_acme::{Http01Challenge, Http01Payload};
use meshspan_contracts::{
    BoundedBytes, CertificateChallenge, CertificateChallengeKind, CertificateChallengeRequest,
    ContractVersion, RequestContext,
};
use meshspan_domain::{OperationId, Revision, UnixMicros};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use super::Http01Server;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_plain_http_listener_serves_only_exact_unexpired_challenges()
-> Result<(), Box<dyn Error>> {
    let now = current_time()?;
    let mut challenges = Http01Challenge::new();
    let request = CertificateChallengeRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([1; 16])?,
            deadline: UnixMicros::new(now.get() + 1_000_000),
            expected_revision: Some(Revision::new(7)),
        },
        kind: CertificateChallengeKind::Http01,
        identifier: BoundedBytes::copy_from(b"files.example.test", 253)?,
        challenge: Http01Payload::new("exact-token", b"exact-token.thumbprint")?.encode()?,
        expires_at: UnixMicros::new(now.get() + 60_000_000),
        order_epoch: 9,
    };
    challenges.publish(&request).await?;
    let server = Http01Server::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        challenges,
    )
    .await?;
    let address = server.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(server.run_until(async move {
        drop(shutdown_rx.await);
    }));

    let found = request_path(address, "/.well-known/acme-challenge/exact-token").await?;
    assert!(found.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(found.ends_with("exact-token.thumbprint"));
    assert!(found.contains("cache-control: no-store"));
    let absent = request_path(address, "/.well-known/acme-challenge/absent").await?;
    assert!(absent.starts_with("HTTP/1.1 404 Not Found\r\n"));
    let api = request_path(address, "/api/latest/health").await?;
    assert!(api.starts_with("HTTP/1.1 404 Not Found\r\n"));

    assert!(shutdown_tx.send(()).is_ok());
    task.await??;
    Ok(())
}

async fn request_path(address: SocketAddr, path: &str) -> Result<String, Box<dyn Error>> {
    let mut stream = TcpStream::connect(address).await?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: files.example.test\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8(response)?)
}

fn current_time() -> Result<UnixMicros, Box<dyn Error>> {
    let micros = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    Ok(UnixMicros::new(i64::try_from(micros)?))
}
