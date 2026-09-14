// SPDX-License-Identifier: GPL-2.0-only

//! Backup controls exercised against the real appliance HTTPS listener.

use super::backup_history::automatic_backup_history;
use super::{
    ClientConfig, Error, Instant, RETRY_INTERVAL, SocketAddr, WAIT_LIMIT, request_with_headers,
    require_status, response_body, sleep,
};
use serde_json::{Value, json};

const DESTINATIONS: &str = "/api/latest/admin/backups/destinations";

pub(super) async fn backup_destination_controls(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<String, Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    automatic_backup_configuration(address, client, &authorization).await?;
    let backup_id = automatic_backup_history(address, client, &authorization).await?;
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/admin/storage-folders?limit=1",
        None,
        &[("Authorization", &authorization)],
    )
    .await?;
    require_status(&response, "200 OK", "choose registered backup target")?;
    let inventory: Value = serde_json::from_str(response_body(&response)?)?;
    let folder = inventory["folders"]
        .as_array()
        .and_then(|folders| folders.first())
        .ok_or("registered folder missing")?;
    let request = json!({
        "operation_id": "00000000-0000-4000-8000-000000000081",
        "destination_id": "00000000-0000-4000-8000-000000000082",
        "expected_revision": 0, "name": "Recovery folder",
        "provider": {"kind":"registered_target", "target_id": folder["target_id"]}, "provider_generation": folder["generation"], "enabled": true
    });
    let first = configure(address, client, &authorization, &request).await?;
    let mut pause = request.clone();
    pause["operation_id"] = json!("00000000-0000-4000-8000-000000000083");
    pause["expected_revision"] = first["committed_revision"].clone();
    pause["enabled"] = json!(false);
    let paused = configure(address, client, &authorization, &pause).await?;
    assert_eq!(
        configure(address, client, &authorization, &request).await?,
        first
    );
    let response = request_with_headers(
        address,
        client,
        "GET",
        DESTINATIONS,
        None,
        &[("Authorization", &authorization)],
    )
    .await?;
    require_status(&response, "200 OK", "list paused backup destination")?;
    let page: Value = serde_json::from_str(response_body(&response)?)?;
    let destination = page["destinations"]
        .as_array()
        .ok_or("destination list missing")?
        .iter()
        .find(|destination| destination["destination_id"] == request["destination_id"])
        .ok_or("explicit destination missing")?;
    assert_eq!(destination["state"], "paused");
    assert_eq!(destination["revision"], paused["committed_revision"]);
    assert_eq!(destination["failure_relationship"], "overlapping");
    assert!(page["next_page_url"].is_null());
    Ok(backup_id)
}

async fn automatic_backup_configuration(
    address: SocketAddr,
    client: &ClientConfig,
    authorization: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let response = request_with_headers(
            address,
            client,
            "GET",
            "/api/latest/admin/backups/schedule",
            None,
            &[("Authorization", authorization)],
        )
        .await?;
        require_status(&response, "200 OK", "read automatic backup schedule")?;
        let schedule: Value = serde_json::from_str(response_body(&response)?)?;
        if !schedule["schedule"].is_null() {
            let policy = &schedule["schedule"]["policy"];
            assert_eq!(policy["interval_seconds"], 86_400);
            assert_eq!(policy["retained_generations"], 3);
            assert_eq!(policy["enabled"], true);
            assert_eq!(policy["minimum_independent_copies"], 0);
            let response = request_with_headers(
                address,
                client,
                "GET",
                DESTINATIONS,
                None,
                &[("Authorization", authorization)],
            )
            .await?;
            require_status(&response, "200 OK", "read automatic backup destinations")?;
            let page: Value = serde_json::from_str(response_body(&response)?)?;
            let destinations = page["destinations"]
                .as_array()
                .ok_or("destinations missing")?;
            assert!(!destinations.is_empty());
            // A gateway's own folders share its partition replica's
            // source-machine boundary, regardless of drive.
            assert!(
                destinations
                    .iter()
                    .all(|destination| destination["state"] == "active"
                        && destination["failure_relationship"] == "overlapping")
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("automatic backup configuration did not appear".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

pub(super) async fn configure(
    address: SocketAddr,
    client: &ClientConfig,
    authorization: &str,
    request: &Value,
) -> Result<Value, Box<dyn Error>> {
    let body = serde_json::to_vec(request)?;
    let response = request_with_headers(
        address,
        client,
        "PUT",
        DESTINATIONS,
        Some(&body),
        &[("Authorization", authorization)],
    )
    .await?;
    require_status(&response, "200 OK", "configure backup destination")?;
    Ok(serde_json::from_str(response_body(&response)?)?)
}

pub(super) async fn request_fresh_backup(
    address: SocketAddr,
    client: &ClientConfig,
    authorization: &str,
) -> Result<u64, Box<dyn Error>> {
    let endpoint = "/api/latest/admin/backups/schedule";
    let response = request_with_headers(
        address,
        client,
        "GET",
        endpoint,
        None,
        &[("Authorization", authorization)],
    )
    .await?;
    require_status(
        &response,
        "200 OK",
        "read backup policy before fresh capture",
    )?;
    let response: meshspan_api_contract::BackupScheduleResponse =
        serde_json::from_str(response_body(&response)?)?;
    let schedule = response
        .schedule
        .ok_or("automatic backup schedule missing")?;
    // Policy replacement schedules an immediate occurrence. Its new sequence fences
    // earlier archives that may predate the content or recipients this proof needs.
    let request = json!({
        "operation_id": "00000000-0000-4000-8000-000000000088",
        "expected_sequence": schedule.sequence, "policy": schedule.policy,
    });
    let response = request_with_headers(
        address,
        client,
        "PUT",
        endpoint,
        Some(&serde_json::to_vec(&request)?),
        &[("Authorization", authorization)],
    )
    .await?;
    require_status(&response, "200 OK", "schedule a fresh backup")?;
    let configured: meshspan_api_contract::ConfigureBackupScheduleResponse =
        serde_json::from_str(response_body(&response)?)?;
    assert!(configured.sequence > schedule.sequence);
    Ok(configured.sequence)
}
