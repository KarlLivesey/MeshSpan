// SPDX-License-Identifier: GPL-2.0-only

//! Lose a live worker's source, recover from its admitted copy, then finish that same generation.

use super::*;
use meshspan_api_contract::{BackupRunStatus, BackupScheduleResponse, ListBackupRunsResponse};
use serde_json::json;

#[tokio::test]
async fn backup_worker_recovers_lost_source_and_completes_original_generation()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let mut cleanup = ProcessCleanup(vec![root.start()?]);
    let processes = &mut cleanup.0;
    let mut phase = "recover source and publish the original generation";
    let proof = async {
        let claim = wait_for_claim(&root.claim_path).await?;
        let client = wait_for_client(&root.identity_path).await?;
        wait_for_status(root.address, &client, "claim_required").await?;
        let created = create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("bootstrap key missing")?;
        save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        wait_for_storage_folder_visibility(&root, &client, key).await?;
        let authorization = format!("Bearer {key}");
        offline_backup::protected_backup(&root, &client, &authorization).await?;
        require_two_copies(&root, &client, &authorization).await?;
        let id = wait_for_recorded(&root, &client, &authorization).await?;
        let backup_id = meshspan_domain::BackupId::parse(&id.replace('-', ""))?;
        let staging = root
            .state_path
            .join("metadata-backup-staging")
            .join(format!(
                "backup-{:032x}.msbackup",
                u128::from_be_bytes(backup_id.as_bytes())
            ));
        let original = fs::read(&staging)?;
        if !original.starts_with(b"MSBACKUP") {
            return Err("original backup container missing".into());
        }

        // Remove only this fixture's exact encrypted staging object. Its durable journal and
        // admitted provider copy remain, as they would after losing local staging bytes.
        fs::remove_file(&staging)?;
        wait_for_restored_source(&staging, &original).await?;
        add_second_copy(&root, &client, &authorization).await?;
        let protected = offline_backup::protected_backup(&root, &client, &authorization).await?;
        if protected != id {
            return Err("recovery replaced the admitted backup identity".into());
        }
        phase = "export the completed generation before restart";
        let (exported, _) =
            backup_history::encrypted_export(root.address, &client, &authorization, &id).await?;
        if exported != original {
            return Err("completed backup changed its original encrypted bytes".into());
        }
        stop_processes(processes);
        processes.push(root.start()?);
        wait_for_status(root.address, &client, "configured").await?;
        phase = "export the completed generation after restart";
        let (reopened, _) =
            backup_history::encrypted_export(root.address, &client, &authorization, &id).await?;
        if reopened != original {
            return Err("completed recovery did not survive daemon restart".into());
        }
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    stop_processes(processes);
    let proof = proof.map_err(|error| -> Box<dyn Error> {
        format!("backup recovery phase {phase}: {error}").into()
    });
    retain_failure_state(proof, [root.temporary])
}

async fn require_two_copies(
    root: &ProcessFixture,
    client: &ClientConfig,
    authorization: &str,
) -> Result<(), Box<dyn Error>> {
    let response = request_with_headers(
        root.address,
        client,
        "GET",
        "/api/latest/admin/backups/schedule",
        None,
        &[("Authorization", authorization)],
    )
    .await?;
    require_status(&response, "200 OK", "read backup schedule")?;
    let schedule: BackupScheduleResponse = serde_json::from_str(response_body(&response)?)?;
    let schedule = schedule.schedule.ok_or("default backup schedule absent")?;
    let body = serde_json::to_vec(&json!({
        "operation_id": "00000000-0000-4000-8000-000000000091", "expected_sequence": schedule.sequence,
        "policy": {"enabled": true, "interval_seconds": 86400, "retained_generations": 3,
            "minimum_verified_copies": 2, "minimum_independent_copies": 0}
    }))?;
    let response = request_with_headers(
        root.address,
        client,
        "PUT",
        "/api/latest/admin/backups/schedule",
        Some(&body),
        &[("Authorization", authorization)],
    )
    .await?;
    require_status(&response, "200 OK", "require a second backup copy")
}

async fn wait_for_recorded(
    root: &ProcessFixture,
    client: &ClientConfig,
    authorization: &str,
) -> Result<String, Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let response = tokio::time::timeout_at(
            deadline.into(),
            request_with_headers(
                root.address,
                client,
                "GET",
                "/api/latest/admin/backups/runs?limit=1",
                None,
                &[("Authorization", authorization)],
            ),
        )
        .await??;
        require_status(&response, "200 OK", "read pending two-copy backup")?;
        let page: ListBackupRunsResponse = serde_json::from_str(response_body(&response)?)?;
        if let Some(run) = page.runs.first()
            && run.minimum_verified_copies == 2
            && run.state == BackupRunStatus::Recorded
        {
            return Ok(run.backup_id.clone());
        }
        if Instant::now() >= deadline {
            return Err(format!("backup did not await its second copy: {:?}", page.runs).into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn wait_for_restored_source(staging: &Path, original: &[u8]) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        match fs::read(staging) {
            Ok(bytes) if bytes == original => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err(
                "worker did not recover its exact staged source from the admitted copy".into(),
            );
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn add_second_copy(
    root: &ProcessFixture,
    client: &ClientConfig,
    authorization: &str,
) -> Result<(), Box<dyn Error>> {
    let response = request_with_headers(
        root.address,
        client,
        "GET",
        "/api/latest/admin/storage-folders?limit=1",
        None,
        &[("Authorization", authorization)],
    )
    .await?;
    require_status(&response, "200 OK", "choose local backup target")?;
    let inventory: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    let folder = inventory["folders"]
        .as_array()
        .and_then(|folders| folders.first())
        .ok_or("storage folder absent")?;
    // Two copies on one host prove copy-count completion, not independent-machine protection.
    stage10::configure(root.address, client, authorization, &json!({
        "operation_id": "00000000-0000-4000-8000-000000000092", "destination_id": "00000000-0000-4000-8000-000000000093",
        "expected_revision": 0, "name": "Second recovery copy", "provider": {"kind":"registered_target", "target_id": folder["target_id"]},
        "provider_generation": folder["generation"], "enabled": true
    })).await?;
    Ok(())
}
