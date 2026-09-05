// SPDX-License-Identifier: GPL-2.0-only

//! Backup controls exercised against the real appliance HTTPS listener.

use super::{ClientConfig, Error, SocketAddr, request_with_headers, require_status, response_body};
use serde_json::{Value, json};

const DESTINATIONS: &str = "/api/latest/admin/backups/destinations";

pub(super) async fn backup_destination_controls(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
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
    assert_eq!(
        page["destinations"]
            .as_array()
            .ok_or("destination list missing")?
            .len(),
        1
    );
    assert_eq!(page["destinations"][0]["state"], "paused");
    assert_eq!(
        page["destinations"][0]["revision"],
        paused["committed_revision"]
    );
    assert_eq!(page["destinations"][0]["failure_relationship"], "unknown");
    assert!(page["next_page_url"].is_null());
    Ok(())
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
