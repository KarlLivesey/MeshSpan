// SPDX-License-Identifier: GPL-2.0-only

//! Real authenticated exporter enable, exact retry, disable, re-enable and scrape proof.

use super::{
    ClientConfig, Error, SocketAddr, request_with_headers, require_status, response_body,
    response_header,
};
use meshspan_api_contract::{ConfigureMetricsExporterResponse, MetricsExporterResponse};
use serde_json::{Value, json};

const POLICY: &str = "/api/latest/admin/metrics/exporter";
const SCRAPE: &str = "/api/latest/metrics";

/// Independent real-process case: does not serialise behind backup or file acceptance.
#[tokio::test]
async fn exporter_policy_survives_restart_and_reaches_another_gateway() -> Result<(), Box<dyn Error>>
{
    let root = super::ProcessFixture::new()?;
    let peer = super::ProcessFixture::new()?;
    let mut processes = vec![root.start()?];
    let proof = async {
        let claim = super::wait_for_claim(&root.claim_path).await?;
        let client = super::wait_for_client(&root.identity_path).await?;
        super::wait_for_status(root.address, &client, "claim_required").await?;
        let administrator = super::bootstrap_administrator_id(&claim, &root.identity_path)?;
        let created = super::create_process_mesh(&root, &client, &claim).await?;
        let api_key = created["api_key"]
            .as_str()
            .ok_or("missing bootstrap API key")?;
        super::save_and_verify_recovery_bundle(&root, &client, api_key, &created).await?;
        super::wait_for_storage_folder_visibility(&root, &client, api_key).await?;
        configure_and_verify(root.address, &client, api_key, &administrator).await?;
        processes[0].kill()?;
        processes[0].wait()?;
        processes[0] = root.start()?;
        super::wait_for_status(root.address, &client, "configured").await?;
        verify(root.address, &client, api_key).await?;
        let join_code = super::issue_join_code(&root, &client, api_key).await?;
        processes.push(peer.start_join(&join_code)?);
        let peer_client = super::wait_for_client(&peer.identity_path).await?;
        super::wait_for_status(peer.address, &peer_client, "configured").await?;
        super::wait_for_storage_folder_visibility(&peer, &peer_client, api_key).await?;
        verify(peer.address, &peer_client, api_key).await?;
        processes[0].kill()?;
        processes[0].wait()?;
        verify(peer.address, &peer_client, api_key).await
    }
    .await;
    super::stop_processes(&mut processes);
    proof
}

async fn configure_and_verify(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    administrator_id: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let anonymous = request_with_headers(address, client, "GET", SCRAPE, None, &[]).await?;
    require_status(&anonymous, "401 Unauthorized", "reject anonymous scrape")?;
    let disabled = request_with_headers(
        address,
        client,
        "GET",
        SCRAPE,
        None,
        &[("Authorization", &authorization)],
    )
    .await?;
    require_status(
        &disabled,
        "403 Forbidden",
        "exporter defaults off even for administrators",
    )?;
    let response = request_with_headers(
        address,
        client,
        "GET",
        POLICY,
        None,
        &[("Authorization", &authorization)],
    )
    .await?;
    require_status(&response, "200 OK", "read initial exporter policy")?;
    let policy: MetricsExporterResponse = serde_json::from_str(response_body(&response)?)?;
    assert_eq!(policy.configuration, None);
    let enable = json!({"operation_id": "00000000-0000-4000-8000-000000000090", "expected_sequence": 0,
        "policy": {"enabled": true, "allowed_principals": [administrator_id]}});
    let first = configure(address, client, &authorization, &enable).await?;
    assert_eq!(first.sequence, 1);
    verify(address, client, api_key).await?;
    let ambiguous = request_with_headers(
        address,
        client,
        "GET",
        SCRAPE,
        None,
        &[
            ("Authorization", &authorization),
            ("Cookie", "unrelated=value"),
        ],
    )
    .await?;
    require_status(
        &ambiguous,
        "401 Unauthorized",
        "scrape rejects mixed cookie credentials",
    )?;
    let disable = json!({"operation_id": "00000000-0000-4000-8000-000000000091", "expected_sequence": 1,
        "policy": {"enabled": false, "allowed_principals": []}});
    assert_eq!(
        configure(address, client, &authorization, &disable)
            .await?
            .sequence,
        2
    );
    assert_eq!(
        configure(address, client, &authorization, &enable).await?,
        first
    );
    let disabled = request_with_headers(
        address,
        client,
        "GET",
        SCRAPE,
        None,
        &[("Authorization", &authorization)],
    )
    .await?;
    require_status(
        &disabled,
        "403 Forbidden",
        "old enable receipt never re-enables exporter",
    )?;
    let mut resume = enable;
    resume["operation_id"] = json!("00000000-0000-4000-8000-000000000092");
    resume["expected_sequence"] = json!(2);
    assert_eq!(
        configure(address, client, &authorization, &resume)
            .await?
            .sequence,
        3
    );
    verify(address, client, api_key).await
}

async fn verify(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        SCRAPE,
        None,
        &[("Authorization", &authorization)],
    )
    .await?;
    require_status(&response, "200 OK", "scrape enabled runtime observations")?;
    assert_eq!(
        response_header(&response, "content-type")?,
        meshspan_daemon::OPENMETRICS_CONTENT_TYPE
    );
    assert_eq!(response_header(&response, "cache-control")?, "no-store");
    let body = response_body(&response)?;
    assert!(body.len() <= meshspan_api_contract::MAX_METRICS_EXPORT_BYTES);
    assert!(body.ends_with("# EOF\n"));
    assert!(!body.contains(api_key));
    assert!(!body.contains("target_id"));
    let completed = body
        .lines()
        .find_map(|line| line.strip_prefix("meshspan_v1_storage_reconciliation_cycles_total "))
        .ok_or("missing real reconciliation counter")?
        .parse::<u64>()?;
    assert!(completed > 0);
    let policy = request_with_headers(
        address,
        client,
        "GET",
        POLICY,
        None,
        &[("Authorization", &authorization)],
    )
    .await?;
    require_status(&policy, "200 OK", "read current exporter policy")?;
    let policy: MetricsExporterResponse = serde_json::from_str(response_body(&policy)?)?;
    meshspan_api_contract::encode_metrics_exporter_response(&policy)?;
    let policy = policy.configuration.ok_or("exporter policy missing")?;
    assert!(policy.policy.enabled);
    assert_eq!(policy.policy.allowed_principals.len(), 1);
    Ok(())
}

async fn configure(
    address: SocketAddr,
    client: &ClientConfig,
    authorization: &str,
    request: &Value,
) -> Result<ConfigureMetricsExporterResponse, Box<dyn Error>> {
    let body = serde_json::to_vec(request)?;
    let response = request_with_headers(
        address,
        client,
        "PUT",
        POLICY,
        Some(&body),
        &[("Authorization", authorization)],
    )
    .await?;
    require_status(&response, "200 OK", "commit exporter policy")?;
    let receipt: ConfigureMetricsExporterResponse =
        serde_json::from_str(response_body(&response)?)?;
    meshspan_api_contract::encode_configure_metrics_exporter_response(&receipt)?;
    assert_eq!(
        receipt.operation_id.as_str(),
        request["operation_id"].as_str().ok_or("operation absent")?
    );
    Ok(receipt)
}
