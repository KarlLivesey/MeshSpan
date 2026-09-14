// SPDX-License-Identifier: GPL-2.0-only

//! Real local-catalogue observations distinguish missing storage from restored receipt evidence.

use super::*;

#[tokio::test]
async fn protection_metrics_survive_restart_and_show_unknown_during_folder_loss()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let mut processes = vec![root.start()?];
    let proof = async {
        let claim = wait_for_claim(&root.claim_path).await?;
        let client = wait_for_client(&root.identity_path).await?;
        wait_for_status(root.address, &client, "claim_required").await?;
        let administrator = bootstrap_administrator_id(&claim, &root.identity_path)?;
        let created = create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("missing API key")?;
        save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        wait_for_storage_folder_visibility(&root, &client, key).await?;
        let volume = create_volume(root.address, &client, key, &administrator).await?;
        upload_file(
            root.address,
            &client,
            key,
            &volume,
            b"one observable protected stripe",
        )
        .await?;
        let configuration = serde_json::to_vec(&serde_json::json!({
            "operation_id": "00000000-0000-4000-8000-000000000098", "expected_sequence": 0,
            "policy": {"enabled": true, "allowed_principals": [administrator]}
        }))?;
        let response = request_with_headers(
            root.address,
            &client,
            "PUT",
            "/api/latest/admin/metrics/exporter",
            Some(&configuration),
            &[("Authorization", &format!("Bearer {key}"))],
        )
        .await?;
        require_status(&response, "200 OK", "enable protection observations")?;
        verify_io_metrics(root.address, &client, key, "write").await?;
        verify_file_write_metrics(root.address, &client, key).await?;
        stop_processes(&mut processes);
        processes.push(root.start()?);
        wait_for_status(root.address, &client, "configured").await?;
        wait_for_counts(root.address, &client, key, [1, 0, 0, 0, 1, 0]).await?;

        stop_processes(&mut processes);
        let disconnected = root.temporary.path().join("disconnected-storage");
        fs::rename(&root.storage_path, &disconnected)?;
        processes.push(root.start()?);
        wait_for_status(root.address, &client, "configured").await?;
        wait_for_counts(root.address, &client, key, [0, 1, 0, 0, 0, 0]).await?;

        stop_processes(&mut processes);
        fs::rename(disconnected, &root.storage_path)?;
        processes.push(root.start()?);
        wait_for_status(root.address, &client, "configured").await?;
        wait_for_counts(root.address, &client, key, [1, 0, 0, 0, 1, 0]).await?;
        assert_file_surfaces(
            root.address,
            &client,
            key,
            &volume,
            b"one observable protected stripe",
        )
        .await?;
        verify_io_metrics(root.address, &client, key, "read").await?;
        verify_file_read_metrics(root.address, &client, key, &volume).await?;
        verify_progress_metrics(root.address, &client, key).await?;
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    stop_processes(&mut processes);
    retain_failure_state(proof, [root.temporary])
}

async fn verify_io_metrics(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    kind: &str,
) -> Result<(), Box<dyn Error>> {
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/metrics",
        None,
        &[("Authorization", &format!("Bearer {key}"))],
    )
    .await?;
    require_status(&response, "200 OK", "read real provider IO observations")?;
    let body = response_body(&response)?;
    for measurement in ["calls", "payload_bytes"] {
        let prefix = format!("meshspan_v1_storage_io_{kind}_{measurement}_total ");
        let value = body
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .ok_or("provider IO counter absent")?
            .parse::<u64>()?;
        assert!(value > 0, "{kind} {measurement} was not observed");
    }
    let coding = if kind == "write" {
        "encode"
    } else {
        "reconstruct"
    };
    for suffix in [
        format!("coding_{coding}_calls_total"),
        format!("coding_{coding}_output_bytes_total"),
        "https_received_bytes_total".to_owned(),
        "https_sent_bytes_total".to_owned(),
    ] {
        let prefix = format!("meshspan_v1_{suffix} ");
        let value = body
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .ok_or("data-path measurement absent")?
            .parse::<u64>()?;
        assert!(value > 0, "{suffix} was not observed");
    }
    Ok(())
}

async fn verify_progress_metrics(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
) -> Result<(), Box<dyn Error>> {
    let body = wait_for_lifecycle_metrics(address, client, key).await?;
    verify_pack_measurements(&body)?;
    let unavailable = body
        .lines()
        .find_map(|line| line.strip_prefix("meshspan_v1_maintenance_progress_unavailable_jobs "))
        .ok_or("durable progress coverage absent")?
        .parse::<u64>()?;
    let verified = body.lines().find_map(|line| {
        line.strip_prefix("meshspan_v1_maintenance_progress_reconciliation_verified_bytes ")
    });
    if unavailable == 0 {
        verified
            .ok_or("complete pass omitted verified-byte gauge")?
            .parse::<u64>()?;
    } else {
        assert!(
            verified.is_none(),
            "partial progress must not be a complete byte total"
        );
    }
    Ok(())
}

async fn wait_for_lifecycle_metrics(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
) -> Result<String, Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let response = tokio::time::timeout_at(
            deadline.into(),
            request_with_headers(
                address,
                client,
                "GET",
                "/api/latest/metrics",
                None,
                &[("Authorization", &format!("Bearer {key}"))],
            ),
        )
        .await??;
        require_status(&response, "200 OK", "read operational worker observations")?;
        let body = response_body(&response)?;
        let missing = [
            "certificate_automation",
            "certificate_installation",
            "backup",
            "update_preparation",
        ]
        .into_iter()
        .filter(|worker| {
            let prefix = format!("meshspan_v1_{worker}_observation_age_seconds ");
            !body.lines().any(|line| line.starts_with(&prefix))
        })
        .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(body.to_owned());
        }
        if Instant::now() >= deadline {
            return Err(format!("operational worker observations missing: {missing:?}").into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn verify_file_write_metrics(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
) -> Result<(), Box<dyn Error>> {
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/metrics",
        None,
        &[("Authorization", &format!("Bearer {key}"))],
    )
    .await?;
    require_status(&response, "200 OK", "read filesystem write measurements")?;
    let body = response_body(&response)?;
    for (suffix, expected) in [
        ("filesystem_stage_write_calls", 1),
        ("filesystem_stage_write_returned_errors", 0),
        ("filesystem_staged_write_bytes", 31),
        ("filesystem_upload_commit_calls", 1),
        ("filesystem_upload_commit_returned_errors", 0),
        ("file_publications_node_local", 1),
        ("file_publications_cell_replicated", 0),
        ("file_publications_globally_converged", 0),
    ] {
        require_file_counter(body, suffix, expected)?;
    }
    Ok(())
}

async fn verify_file_read_metrics(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    volume: &str,
) -> Result<(), Box<dyn Error>> {
    let headers = [("Authorization", format!("Bearer {key}"))];
    let borrowed = [(headers[0].0, headers[0].1.as_str())];
    let missing = request_with_headers(
        address,
        client,
        "GET",
        &format!("/api/latest/volumes/{volume}/file-content?path=absent.bin&offset=0&length=1"),
        None,
        &borrowed,
    )
    .await?;
    require_status(
        &missing,
        "404 Not Found",
        "reject missing file before coding",
    )?;
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/metrics",
        None,
        &borrowed,
    )
    .await?;
    require_status(&response, "200 OK", "read filesystem outcome measurements")?;
    let body = response_body(&response)?;
    for (suffix, expected) in [
        ("filesystem_open_calls", 3),
        ("filesystem_open_returned_errors", 1),
        ("filesystem_read_calls", 2),
        ("filesystem_read_returned_errors", 0),
        ("filesystem_read_bytes", 43),
        ("filesystem_close_calls", 2),
        ("filesystem_close_returned_errors", 0),
        ("file_publications_node_local", 0),
    ] {
        require_file_counter(body, suffix, expected)?;
    }
    Ok(())
}

fn require_file_counter(body: &str, suffix: &str, expected: u64) -> Result<(), Box<dyn Error>> {
    let prefix = format!("meshspan_v1_{suffix}_total ");
    let actual = body
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or("file-operation metric missing")?
        .parse::<u64>()?;
    assert_eq!(actual, expected, "{suffix}");
    Ok(())
}

fn verify_pack_measurements(body: &str) -> Result<(), Box<dyn Error>> {
    let read = |suffix: &str| -> Result<u64, Box<dyn Error>> {
        let prefix = format!("meshspan_v1_{suffix} ");
        Ok(body
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .ok_or("pack measurement missing")?
            .parse::<u64>()?)
    };
    assert_eq!(read("storage_sampled_pack_targets")?, 1);
    assert_eq!(read("storage_unavailable_pack_targets")?, 0);
    let database = read("storage_pack_database_bytes")?;
    assert!(database > 0);
    assert!(read("storage_pack_reusable_bytes")? <= database);
    Ok(())
}

async fn wait_for_counts(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    expected: [u64; 6],
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let response = tokio::time::timeout_at(
            deadline.into(),
            request_with_headers(
                address,
                client,
                "GET",
                "/api/latest/metrics",
                None,
                &[("Authorization", &format!("Bearer {key}"))],
            ),
        )
        .await??;
        require_status(&response, "200 OK", "read protection observations")?;
        let body = response_body(&response)?;
        let actual = [
            "assessed_stripes",
            "unassessable_stripes",
            "missing_shard_receipts",
            "insufficient_receipts_stripes",
            "protection_debt_stripes",
            "locality_debt_stripes",
        ]
        .map(|suffix| {
            let prefix = format!("meshspan_v1_protection_catalogue_{suffix} ");
            body.lines()
                .find_map(|line| line.strip_prefix(&prefix))
                .and_then(|value| value.parse::<u64>().ok())
        });
        if actual == expected.map(Some) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                format!("protection counts expected {expected:?}, observed {actual:?}").into(),
            );
        }
        sleep(RETRY_INTERVAL).await;
    }
}
