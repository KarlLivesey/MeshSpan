// SPDX-License-Identifier: GPL-2.0-only

use super::{
    ClientConfig, Error, SocketAddr, request_with_headers, require_status, response_body,
    response_header,
};
use meshspan_api_contract::{MetadataDiagnosticsResponse, encode_metadata_diagnostics_response};

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
    Ok(())
}
