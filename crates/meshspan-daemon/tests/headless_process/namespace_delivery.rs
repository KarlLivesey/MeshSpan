// SPDX-License-Identifier: GPL-2.0-only

//! A returning source must discover new peers and replay acknowledged pre-enrolment work.

use super::*;

#[tokio::test]
async fn disconnected_gateways_accept_distinct_writes_and_reconcile_after_reconnect()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let peer = ProcessFixture::new()?;
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
        let common = b"common bytes before the partition";
        upload_file(root.address, &client, key, &volume, common).await?;
        let join = issue_join_code(&root, &client, key).await?;
        processes.push(peer.start_join(&join)?);
        let peer_client = wait_for_client(&peer.identity_path).await?;
        wait_for_status(peer.address, &peer_client, "configured").await?;
        wait_for_file_surfaces(peer.address, &peer_client, key, &volume, common).await?;

        stop_processes(&mut processes[1..]);
        upload_named_file(
            root.address,
            &client,
            key,
            &volume,
            FileUploadProof {
                path: "home.txt",
                content: b"written at home",
                operation_base: 300,
            },
        )
        .await?;
        stop_processes(&mut processes[..1]);
        processes[1] = peer.start()?;
        wait_for_status(peer.address, &peer_client, "configured").await?;
        upload_named_file(
            peer.address,
            &peer_client,
            key,
            &volume,
            FileUploadProof {
                path: "office.txt",
                content: b"written at the office while home was offline",
                operation_base: 310,
            },
        )
        .await?;

        processes[0] = root.start()?;
        wait_for_status(root.address, &client, "configured").await?;
        wait_for_reconciled_files(root.address, &client, key, &volume)
            .await
            .map_err(|error| format!("first reconnect, root: {error}"))?;
        wait_for_reconciled_files(peer.address, &peer_client, key, &volume)
            .await
            .map_err(|error| format!("first reconnect, peer: {error}"))?;
        stop_processes(&mut processes);
        processes[0] = root.start()?;
        processes[1] = peer.start()?;
        wait_for_status(root.address, &client, "configured").await?;
        wait_for_status(peer.address, &peer_client, "configured").await?;
        wait_for_reconciled_files(root.address, &client, key, &volume)
            .await
            .map_err(|error| format!("full restart, root: {error}"))?;
        wait_for_reconciled_files(peer.address, &peer_client, key, &volume)
            .await
            .map_err(|error| format!("full restart, peer: {error}"))?;
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    stop_processes(&mut processes);
    retain_failure_state(proof, [root.temporary, peer.temporary])
}

async fn wait_for_reconciled_files(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    volume: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    let authorization = format!("Bearer {key}");
    loop {
        let mut complete = true;
        for (name, expected) in [
            ("home.txt", "written at home"),
            ("office.txt", "written at the office while home was offline"),
            ("process-proof.bin", "common bytes before the partition"),
        ] {
            let response = request_with_headers(
                address,
                client,
                "GET",
                &format!(
                    "/api/latest/volumes/{volume}/file-content?path={name}&offset=0&length={}",
                    expected.len()
                ),
                None,
                &[("Authorization", authorization.as_str())],
            )
            .await?;
            if !response.starts_with("HTTP/1.1 200 OK\r\n") || response_body(&response)? != expected
            {
                if Instant::now() >= deadline {
                    let evidence = tokio::time::timeout(
                        Duration::from_secs(3),
                        diagnostics::failure_evidence(address, client, &authorization),
                    )
                    .await
                    .unwrap_or_else(|_| "diagnostics timed out".to_owned());
                    return Err(format!(
                        "reconnected gateway {address} did not return exact bytes for {name}: {}; {evidence}",
                        response.lines().next().unwrap_or("missing status")
                    )
                    .into());
                }
                complete = false;
                break;
            }
        }
        if complete {
            return Ok(());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

#[tokio::test]
async fn namespace_delivery_replays_pre_enrolment_files_after_source_restart()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let peer = ProcessFixture::new()?;
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
        let content = b"acknowledged before any peer existed";
        upload_file(root.address, &client, key, &volume, content).await?;

        // No peer or in-memory notification can carry this write across the source's loss.
        stop_processes(&mut processes);
        processes.push(root.start()?);
        wait_for_status(root.address, &client, "configured").await?;
        let join = issue_join_code(&root, &client, key).await?;
        processes.push(peer.start_join(&join)?);
        let peer_client = wait_for_client(&peer.identity_path).await?;
        wait_for_status(peer.address, &peer_client, "configured").await?;
        wait_for_volume_visibility(peer.address, &peer_client, key).await?;
        wait_for_file_surfaces(peer.address, &peer_client, key, &volume, content).await?;

        // Both persisted cursors and imported namespace/content survive another full restart.
        stop_processes(&mut processes);
        processes.push(root.start()?);
        processes.push(peer.start()?);
        wait_for_status(root.address, &client, "configured").await?;
        wait_for_status(peer.address, &peer_client, "configured").await?;
        wait_for_file_surfaces(peer.address, &peer_client, key, &volume, content).await?;
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    stop_processes(&mut processes);
    retain_failure_state(proof, [root.temporary, peer.temporary])
}
