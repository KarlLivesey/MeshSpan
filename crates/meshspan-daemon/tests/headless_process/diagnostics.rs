// SPDX-License-Identifier: GPL-2.0-only

use super::{
    ClientConfig, Error, SocketAddr, request_with_headers, require_status, response_body,
    response_header,
};
use meshspan_api_contract::{
    DiagnosticsBundleResponse, MetadataDiagnosticsResponse, encode_diagnostics_bundle_response,
    encode_metadata_diagnostics_response,
};

pub(super) async fn verify(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let endpoint = "/api/latest/admin/diagnostics/metadata";
    let rejected = request_with_headers(address, client, "GET", endpoint, None, &[]).await?;
    require_status(
        &rejected,
        "401 Unauthorized",
        "anonymous diagnostics rejection",
    )?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        endpoint,
        None,
        &[("Authorization", &authorization)],
    )
    .await?;
    require_status(&response, "200 OK", "collect native metadata diagnostics")?;
    assert_eq!(response_header(&response, "cache-control")?, "no-store");
    assert_eq!(
        response_header(&response, "content-disposition")?,
        "attachment; filename=\"meshspan-metadata-diagnostics.json\""
    );
    let body = response_body(&response)?;
    let snapshot: MetadataDiagnosticsResponse = serde_json::from_str(body)?;
    encode_metadata_diagnostics_response(&snapshot)?;
    assert_eq!(snapshot.daemon_version, env!("CARGO_PKG_VERSION"));
    let consensus = snapshot
        .consensus
        .ok_or("live reactor observation absent")?;
    assert_eq!(consensus.node_id, snapshot.node_id);
    assert_eq!(consensus.partition_id, snapshot.partition_id);
    assert!(consensus.applied_index.0.parse::<u64>()? > 0);
    assert_eq!(snapshot.nodes.items.len(), 2);
    assert!(!snapshot.nodes.truncated);
    assert!(!snapshot.targets.items.is_empty());
    assert!(!snapshot.recent_operations.items.is_empty());
    require_redaction(body, api_key);
    verify_bundle(address, client, api_key).await
}

async fn verify_bundle(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let started = super::Instant::now();
    loop {
        let response = request_with_headers(
            address,
            client,
            "GET",
            "/api/latest/admin/diagnostics/bundle",
            None,
            &[("Authorization", &authorization)],
        )
        .await?;
        require_status(
            &response,
            "200 OK",
            "collect native runtime diagnostic bundle",
        )?;
        assert_eq!(response_header(&response, "cache-control")?, "no-store");
        assert_eq!(
            response_header(&response, "content-disposition")?,
            "attachment; filename=\"meshspan-diagnostics.json\""
        );
        let body = response_body(&response)?;
        require_redaction(body, api_key);
        let bundle: DiagnosticsBundleResponse = serde_json::from_str(body)?;
        encode_diagnostics_bundle_response(&bundle)?;
        if let Some(runtime) = bundle.runtime {
            assert!(runtime.reconciliation_cycles.0.parse::<u64>()? > 0);
            assert!(runtime.storage_reconciliation.is_some());
            assert!(runtime.target_checks.len() <= 100);
            assert!(runtime.recent_events.len() <= 100);
            return Ok(());
        }
        // Null is a valid non-blocking observation under contention; retry the read,
        // never trigger maintenance or treat unavailable evidence as a healthy sample.
        if started.elapsed() >= super::WAIT_LIMIT {
            return Err("runtime observation store did not become readable".into());
        }
        tokio::time::sleep(super::RETRY_INTERVAL).await;
    }
}

fn require_redaction(body: &str, api_key: &str) {
    for (index, forbidden) in [
        api_key,
        "Root node",
        "Root host",
        "Administrator",
        "display_name",
        "private_endpoint",
        "storage_path",
        "actor_principal_id",
        "request_digest",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            !body.contains(forbidden),
            "diagnostic redaction omitted field {index}"
        );
    }
}

pub(super) async fn failure_evidence(
    address: SocketAddr,
    client: &ClientConfig,
    authorization: &str,
) -> String {
    let evidence = async {
        let response = request_with_headers(
            address,
            client,
            "GET",
            "/api/latest/admin/diagnostics/bundle",
            None,
            &[("Authorization", authorization)],
        )
        .await?;
        require_status(&response, "200 OK", "collect failure evidence")?;
        let bundle: DiagnosticsBundleResponse = serde_json::from_str(response_body(&response)?)?;
        encode_diagnostics_bundle_response(&bundle)?;
        let runtime = bundle.runtime.ok_or("runtime observation unavailable")?;
        Ok::<_, Box<dyn Error>>(format!(
            "cycles={}, failed_cycles={}, last_cycle={:?}, recent_events={:?}, consensus={:?}",
            runtime.reconciliation_cycles.0,
            runtime.reconciliation_failures.0,
            runtime.storage_reconciliation,
            runtime.recent_events.iter().take(3).collect::<Vec<_>>(),
            bundle.metadata.consensus,
        ))
    }
    .await;
    // Do not echo arbitrary HTTP bodies or errors from a failed diagnostic boundary.
    evidence.unwrap_or_else(|_| "validated runtime failure evidence unavailable".to_owned())
}
