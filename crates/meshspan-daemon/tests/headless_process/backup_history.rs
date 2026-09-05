// SPDX-License-Identifier: GPL-2.0-only

use super::{
    ClientConfig, Error, Instant, RETRY_INTERVAL, SocketAddr, WAIT_LIMIT, request_with_headers,
    require_status, response_body, sleep,
};

pub(super) async fn automatic_backup_history(
    address: SocketAddr,
    client: &ClientConfig,
    authorization: &str,
) -> Result<(), Box<dyn Error>> {
    let rejected = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/admin/backups/runs?limit=0",
        None,
        &[],
    )
    .await?;
    require_status(
        &rejected,
        "401 Unauthorized",
        "reject unauthenticated history before invalid query",
    )?;
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let response = request_with_headers(
            address,
            client,
            "GET",
            "/api/latest/admin/backups/runs?limit=1",
            None,
            &[("Authorization", authorization)],
        )
        .await?;
        require_status(&response, "200 OK", "read live automatic backup history")?;
        let page: meshspan_api_contract::ListBackupRunsResponse =
            serde_json::from_str(response_body(&response)?)?;
        meshspan_api_contract::encode_list_backup_runs_response(&page)?;
        if let Some(run) = page.runs.first() {
            assert!(run.run_sequence.parse::<u64>()? > 0);
            assert!(run.scheduled_for_epoch_micros > 0);
            assert!(run.minimum_verified_copies > 0);
            if run.state == meshspan_api_contract::BackupRunStatus::Protected {
                return encrypted_export(address, client, authorization, &run.backup_id).await;
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "automatic backup did not finish its protected run; observed history: {:?}",
                page.runs
            )
            .into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn encrypted_export(
    address: SocketAddr,
    client: &ClientConfig,
    authorization: &str,
    backup_id: &str,
) -> Result<(), Box<dyn Error>> {
    use super::{Arc, CERTIFICATE_NAME, ServerName, TcpStream, TlsConnector};
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let connector = TlsConnector::from(Arc::new(client.clone()));
    let mut stream = connector
        .connect(
            ServerName::try_from(CERTIFICATE_NAME)?.to_owned(),
            TcpStream::connect(address).await?,
        )
        .await?;
    stream.write_all(format!("GET /api/latest/admin/backups/{backup_id}/export HTTP/1.1\r\nHost: {CERTIFICATE_NAME}\r\nAuthorization: {authorization}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
    let mut received = Vec::new();
    tokio::time::timeout(
        WAIT_LIMIT,
        stream.take(32 * 1024 * 1024).read_to_end(&mut received),
    )
    .await??;
    let offset = received
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or("export response headers missing")?
        + 4;
    let headers = std::str::from_utf8(&received[..offset])?;
    require_status(headers, "200 OK", "export real encrypted metadata backup")?;
    let bytes = &received[offset..];
    assert_eq!(
        bytes.len(),
        super::response_header(headers, "content-length")?.parse::<usize>()?
    );
    assert_eq!(
        super::response_header(headers, "meshspan-backup-id")?,
        backup_id
    );
    let mut digest = String::from("sha256:");
    for byte in Sha256::digest(bytes) {
        write!(&mut digest, "{byte:02x}")?;
    }
    assert_eq!(
        super::response_header(headers, "meshspan-backup-digest")?,
        digest
    );
    assert!(bytes.starts_with(b"MSBACKUP"));
    assert!(
        !bytes
            .windows(16)
            .any(|window| window == b"SQLite format 3\0")
    );
    Ok(())
}
