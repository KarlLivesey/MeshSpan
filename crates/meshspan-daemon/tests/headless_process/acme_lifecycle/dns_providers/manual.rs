// SPDX-License-Identifier: GPL-2.0-only

//! An administrator follows durable DNS tasks; only observed DNS, not a button, advances ACME.

use meshspan_api_contract::{
    ListManualDnsTasksResponse, ManualDnsTaskAction, ManualDnsTaskSummary,
};

use super::super::challenge::ValidationTarget;
use super::super::*;
use super::{Record, SharedRecords, dns, require_isolated_dns};

#[tokio::test]
#[ignore = "requires a dedicated offline Linux container with loopback authoritative DNS"]
async fn manual_dns01_tasks_drive_issuance_and_exact_cleanup() -> Result<(), Box<dyn Error>> {
    require_isolated_dns().await?;
    let records = SharedRecords::default();
    let dns = dns::Server::start(Arc::clone(&records))
        .await
        .map_err(|error| error.to_string())?;
    let ca =
        authority::TestAuthority::start(ValidationTarget::Dns01("127.0.0.1:53".parse()?)).await?;
    let mut root = ProcessFixture::new()?;
    // The container runner removes successful cases and retains failed private fixture state.
    root.temporary.disable_cleanup(true);
    root.smb_address.set_port(0);
    let trust_file = root.temporary.path().join("test-ca.pem");
    fs::write(&trust_file, &ca.anchor_pem)?;
    let mut processes = vec![root.command().env("SSL_CERT_FILE", &trust_file).spawn()?];
    let proof = manual_lifecycle(&root, &ca, &records, &mut processes[0]).await;
    stop_processes(&mut processes);
    let ca_result = ca.stop().await;
    let dns_result = dns.stop().await.map_err(|error| error.to_string());
    proof?;
    ca_result?;
    dns_result?;
    Ok(())
}

async fn manual_lifecycle(
    root: &ProcessFixture,
    ca: &authority::TestAuthority,
    records: &SharedRecords,
    process: &mut Child,
) -> Result<(), Box<dyn Error>> {
    let claim = wait_for_claim(&root.claim_path).await?;
    let bootstrap = wait_for_client(&root.identity_path).await?;
    wait_for_status(root.address, &bootstrap, "claim_required").await?;
    let created = create_process_mesh(root, &bootstrap, &claim).await?;
    let key = created["api_key"].as_str().ok_or("missing API key")?;
    save_and_verify_recovery_bundle(root, &bootstrap, key, &created).await?;
    let authorization = format!("Bearer {key}");
    let body = serde_json::to_vec(&json!({
        "operation_id": "00000000-0000-4000-8000-000000000201",
        "directory_url": format!("{}/directory", ca.endpoint),
        "certificate_names": [CERTIFICATE_NAME],
        "challenge": {"kind": "dns01_manual"}
    }))?;
    let response = request_with_headers(
        root.address,
        &bootstrap,
        "POST",
        "/api/latest/admin/certificates/acme",
        Some(&body),
        &[("Authorization", &authorization)],
    )
    .await?;
    require_status(&response, "201 Created", "queue manual DNS certificate")?;

    fulfil_manual_tasks(root, ca, &bootstrap, key, records).await?;
    let issued = await_issuance(root, ca, key, process, None).await?;
    assert!(tasks(root, &issued, key).await?.tasks.is_empty());
    process.kill()?;
    process.wait()?;
    *process = root
        .command()
        .env("SSL_CERT_FILE", root.temporary.path().join("test-ca.pem"))
        .spawn()?;
    wait_for_active(root.address, &issued, key, 1).await?;
    assert!(
        tasks(root, &issued, key).await?.tasks.is_empty(),
        "completed manual task reappeared after restart"
    );
    ca.assert_issued_once()?;
    ca.assert_challenge_removed().await?;
    Ok(())
}

async fn fulfil_manual_tasks(
    root: &ProcessFixture,
    ca: &authority::TestAuthority,
    bootstrap: &ClientConfig,
    key: &str,
    records: &SharedRecords,
) -> Result<(), Box<dyn Error>> {
    let publish = wait_task(root, bootstrap, key, ManualDnsTaskAction::Publish).await?;
    assert_eq!(publish.record_name, "_acme-challenge.meshspan.local");
    assert_eq!(publish.record_value.len(), 43);
    assert!(publish.expires_at_epoch_micros > publish.created_at_epoch_micros);
    assert!(
        !ca.observations()
            .iter()
            .any(|event| event == "POST /challenge"),
        "CA notified before authoritative DNS contained the exact record"
    );
    let denied = request(
        root.address,
        bootstrap,
        "GET",
        "/api/latest/admin/certificate-tasks/manual-dns",
        None,
    )
    .await?;
    require_status(
        &denied,
        "401 Unauthorized",
        "deny anonymous DNS task inventory",
    )?;
    {
        let mut state = records.lock().map_err(|_| "DNS records poisoned")?;
        state.managed = Some(Record {
            name: publish.record_name.clone(),
            value: publish.record_value.clone(),
            ownership: publish.task_digest.clone(),
        });
        state.publications += 1;
    }
    // Cleanup is required before installation, so the current bootstrap certificate remains valid.
    let remove = wait_task(root, bootstrap, key, ManualDnsTaskAction::Remove).await?;
    assert_eq!(remove.task_digest, publish.task_digest);
    assert_eq!(remove.order_id, publish.order_id);
    assert_eq!(remove.record_name, publish.record_name);
    assert_eq!(remove.record_value, publish.record_value);
    assert_eq!(
        remove.expires_at_epoch_micros,
        publish.expires_at_epoch_micros
    );
    assert!(remove.revision > publish.revision);
    {
        let mut state = records.lock().map_err(|_| "DNS records poisoned")?;
        assert_eq!(
            state.managed.take().ok_or("missing manual TXT")?.value,
            remove.record_value
        );
        state.removals += 1;
    }
    Ok(())
}

async fn wait_task(
    root: &ProcessFixture,
    client: &ClientConfig,
    key: &str,
    action: ManualDnsTaskAction,
) -> Result<ManualDnsTaskSummary, Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let page = tasks(root, client, key).await?;
        assert!(page.tasks.len() <= 1, "duplicate manual DNS task");
        assert!(page.next_page_url.is_none());
        if let Some(task) = page.tasks.into_iter().find(|task| task.action == action) {
            return Ok(task);
        }
        if Instant::now() >= deadline {
            return Err(format!("manual DNS task did not reach {action:?}").into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn tasks(
    root: &ProcessFixture,
    client: &ClientConfig,
    key: &str,
) -> Result<ListManualDnsTasksResponse, Box<dyn Error>> {
    let authorization = format!("Bearer {key}");
    let response = request_with_headers(
        root.address,
        client,
        "GET",
        "/api/latest/admin/certificate-tasks/manual-dns",
        None,
        &[("Authorization", &authorization)],
    )
    .await?;
    require_status(&response, "200 OK", "read manual DNS tasks")?;
    Ok(serde_json::from_str(response_body(&response)?)?)
}
