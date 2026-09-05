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
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("automatic backup history did not appear".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}
