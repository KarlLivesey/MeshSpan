// SPDX-License-Identifier: GPL-2.0-only

//! Compare daemon-collected inventory with separate public administration responses.

use super::{ClientConfig, Error, Value, json};
use crate::ProcessFixture;
use rustls::pki_types::{CertificateDer, pem::PemObject as _};

#[tokio::test]
async fn operational_inventory_matches_public_state_and_returns_after_restart()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let mut processes = vec![root.start()?];
    let proof = async {
        let claim = crate::wait_for_claim(&root.claim_path).await?;
        let client = crate::wait_for_client(&root.identity_path).await?;
        let administrator = crate::bootstrap_administrator_id(&claim, &root.identity_path)?;
        crate::wait_for_status(root.address, &client, "claim_required").await?;
        let created = crate::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("bootstrap key absent")?;
        crate::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        let issued = crate::local_certificates::provision(root.address, &client, key, 1).await?;
        let anchor = CertificateDer::from_pem_slice(issued.trust_anchor_pem.as_bytes())?;
        let client = crate::client_config(anchor.as_ref())?;
        crate::local_certificates::wait_for_installation(root.address, &client, key, 1).await?;
        super::configure(
            root.address,
            &client,
            &format!("Bearer {key}"),
            &json!({
                "operation_id": "00000000-0000-4000-8000-000000000090", "expected_sequence": 0,
                "policy": {"enabled": true, "allowed_principals": [administrator]}
            }),
        )
        .await?;
        verify(&root, &client, key).await?;
        crate::stop_processes(&mut processes);
        processes[0] = root.start()?;
        crate::wait_for_status(root.address, &client, "configured").await?;
        verify(&root, &client, key).await
    }
    .await;
    crate::stop_processes(&mut processes);
    crate::retain_failure_state(proof, [root.temporary])
}

async fn verify(
    root: &ProcessFixture,
    client: &ClientConfig,
    key: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + crate::WAIT_LIMIT;
    loop {
        let certificate: Value = serde_json::from_str(
            &get(root, client, key, "/api/latest/admin/certificates/status").await?,
        )?;
        let backups: Value = serde_json::from_str(
            &get(root, client, key, "/api/latest/admin/backups/runs?limit=25").await?,
        )?;
        let metrics = get(root, client, key, super::SCRAPE).await?;
        if matches_inventory(&metrics, &certificate, &backups)? {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(
                "operational inventory did not match public certificate/backup/update state".into(),
            );
        }
        tokio::time::sleep(crate::RETRY_INTERVAL).await;
    }
}

fn matches_inventory(
    metrics: &str,
    certificate: &Value,
    backups: &Value,
) -> Result<bool, Box<dyn Error>> {
    let value = |name: &str| -> Option<u64> {
        metrics
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.parse().ok())
    };
    let certificate = &certificate["certificate"];
    if certificate.is_null()
        || value("meshspan_v1_certificate_selected ") != Some(1)
        || value("meshspan_v1_certificate_required_gateways ")
            != certificate["required_gateway_count"].as_u64()
        || value("meshspan_v1_certificate_installed_gateways ")
            != certificate["installed_gateway_count"].as_u64()
        || value("meshspan_v1_certificate_expired ") != Some(0)
        || value("meshspan_v1_certificate_not_yet_valid ") != Some(0)
    {
        return Ok(false);
    }
    assert!(
        backups["next_page_url"].is_null(),
        "fixture unexpectedly exceeded one backup page"
    );
    let runs = backups["runs"].as_array().ok_or("backup runs absent")?;
    for state in ["queued", "claimed", "recorded", "protected", "incomplete"] {
        let count = u64::try_from(
            runs.iter()
                .filter(|run| run["state"].as_str() == Some(state))
                .count(),
        )?;
        if value(&format!("meshspan_v1_backup_{state}_occurrences ")) != Some(count) {
            return Ok(false);
        }
    }
    for state in ["running", "paused", "completed", "cancelled"] {
        if value(&format!("meshspan_v1_update_{state}_rollouts ")) != Some(0) {
            return Ok(false);
        }
    }
    if value("meshspan_v1_update_selected ") != Some(0) {
        return Ok(false);
    }
    for name in [
        "certificate_observation_age_seconds",
        "backup_inventory_age_seconds",
        "update_inventory_age_seconds",
    ] {
        assert!(
            metrics
                .lines()
                .any(|line| line.starts_with(&format!("meshspan_v1_{name} ")))
        );
    }
    Ok(true)
}

async fn get(
    root: &ProcessFixture,
    client: &ClientConfig,
    key: &str,
    endpoint: &str,
) -> Result<String, Box<dyn Error>> {
    let response = crate::request_with_headers(
        root.address,
        client,
        "GET",
        endpoint,
        None,
        &[("Authorization", &format!("Bearer {key}"))],
    )
    .await?;
    crate::require_status(&response, "200 OK", "read operational observations")?;
    Ok(crate::response_body(&response)?.to_owned())
}
