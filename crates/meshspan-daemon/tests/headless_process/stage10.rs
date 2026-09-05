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
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    automatic_backup_configuration(address, client, &authorization).await?;
    automatic_backup_history(address, client, &authorization).await?;
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
        "target_id": folder["target_id"], "target_generation": folder["generation"], "enabled": true
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
    Ok(())
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
            // Both joined nodes hold partition replicas. Their own folders
            // therefore share a source-machine boundary, regardless of drive.
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

async fn configure(
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
