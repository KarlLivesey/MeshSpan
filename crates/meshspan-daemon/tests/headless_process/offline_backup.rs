// SPDX-License-Identifier: GPL-2.0-only

//! A real export remains verifiable with every daemon stopped and no online key available.

use super::{Error, ProcessFixture, WAIT_LIMIT};
use sha2::Digest as _;
use std::fmt::Write as _;
use std::{fs, path::Path, process::Output};

#[tokio::test]
async fn exported_backup_verifies_offline_and_rejects_changed_bytes_without_live_state_writes()
-> Result<(), Box<dyn Error>> {
    recover_backup(super::recovery_live_file::Clients::Https).await
}

#[tokio::test]
#[ignore = "requires the local pinned smbclient container image"]
async fn original_file_recovers_through_https_and_real_smb_after_storage_restart()
-> Result<(), Box<dyn Error>> {
    recover_backup(super::recovery_live_file::Clients::HttpsAndSmb).await
}

async fn recover_backup(clients: super::recovery_live_file::Clients) -> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let mut processes = vec![root.start()?];
    let proof = async {
        let claim = super::wait_for_claim(&root.claim_path).await?;
        let client = super::wait_for_client(&root.identity_path).await?;
        super::wait_for_status(root.address, &client, "claim_required").await?;
        let created = super::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("bootstrap key missing")?;
        super::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        super::wait_for_storage_folder_visibility(&root, &client, key).await?;
        let administrator = super::bootstrap_administrator_id(&claim, &root.identity_path)?;
        super::recovery_history::populate(&root, &client, key, &administrator, clients).await?;
        let authorization = format!("Bearer {key}");
        let id = protected_backup(&root, &client, &authorization).await?;
        let (bytes, digest) =
            super::backup_history::encrypted_export(root.address, &client, &authorization, &id)
                .await?;
        let backup = root.temporary.path().join("export.msb");
        fs::write(&backup, &bytes)?;
        super::stop_processes(&mut processes);
        let live = root.state_path.join("root-authority.sqlite3");
        let expected = {
            let repository = meshspan_metadata::AuthoritativeRepository::new(
                meshspan_metadata::PartitionDatabase::open_existing(
                    &live,
                    meshspan_domain::UnixMicros::new(1),
                )?,
            );
            repository
                .metadata_backup(meshspan_domain::BackupId::parse(&id.replace('-', ""))?)?
                .ok_or("exported backup missing from authoritative catalogue")?
        };
        let before = fs::read(&live)?;
        let work = root.temporary.path().join("offline-check");
        let result = verify(&root, &backup, &digest, &work).await?;
        if !result.status.success() {
            return Err(format!(
                "offline verification failed: {}",
                String::from_utf8_lossy(&result.stderr)
            )
            .into());
        }
        let report: serde_json::Value = serde_json::from_slice(&result.stdout)?;
        assert_eq!(report["verified"], true);
        assert_eq!(report["service_started"], false);
        assert_eq!(report["verification"], "offline_recovery_bundle");
        assert!(
            report["retained_secret_generations_verified"]
                .as_str()
                .ok_or("verified secret count missing")?
                .parse::<u64>()?
                > 0
        );
        assert_eq!(report["backup_id"], id);
        assert_eq!(report["mesh_id"], created["mesh_id"]);
        assert_eq!(
            report["source_log_index"],
            expected.last_log_index.to_string()
        );
        assert_eq!(
            report["source_log_term"],
            expected.last_log_term.to_string()
        );
        assert_eq!(
            report["state_revision"],
            expected.state_revision.get().to_string()
        );
        assert_eq!(report["schema_version"], expected.schema_version);
        assert_eq!(
            report["restored_schema_version"],
            meshspan_metadata::PartitionDatabase::supported_schema_version()
        );
        assert_eq!(
            report["sha256"],
            digest
                .strip_prefix("sha256:")
                .ok_or("digest prefix absent")?
        );
        assert!(!work.exists());
        super::recovery_keys::install_from_export(&root, &backup, &digest).await?;
        reject_damaged_backups(&root, &backup, &digest, &bytes, &work).await?;
        assert_eq!(fs::read(live)?, before);
        assert_eq!(fs::read(backup)?, bytes);
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    super::stop_processes(&mut processes);
    super::retain_failure_state(proof, [root.temporary])
}

async fn reject_damaged_backups(
    root: &ProcessFixture,
    backup: &Path,
    digest: &str,
    bytes: &[u8],
    work: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut damaged = bytes.to_vec();
    *damaged.last_mut().ok_or("empty export")? ^= 1;
    fs::write(backup, &damaged)?;
    assert_rejected(&verify(root, backup, digest, work).await?);
    assert!(!work.exists());
    // Even a newly calculated outer hash cannot authenticate corrupted encrypted chunks.
    let mut changed_digest = String::new();
    for byte in sha2::Sha256::digest(&damaged) {
        write!(&mut changed_digest, "{byte:02x}")?;
    }
    assert_rejected(&verify(root, backup, &changed_digest, work).await?);
    assert!(!work.exists());
    fs::write(backup, bytes)?;
    let original_code = fs::read(&root.saved_recovery_code_path)?;
    let mut wrong_code = original_code.clone();
    let last = wrong_code.last_mut().ok_or("empty recovery code")?;
    *last = if *last == b'0' { b'1' } else { b'0' };
    fs::write(&root.saved_recovery_code_path, wrong_code)?;
    let wrong_key = verify(root, backup, digest, work).await?;
    fs::write(&root.saved_recovery_code_path, original_code)?;
    assert_rejected(&wrong_key);
    assert!(!work.exists());
    fs::create_dir(work)?;
    fs::write(work.join("keep.txt"), b"not a restore destination")?;
    assert_rejected(&verify(root, backup, digest, work).await?);
    assert_eq!(
        fs::read(work.join("keep.txt"))?,
        b"not a restore destination"
    );
    Ok(())
}

pub(super) async fn protected_backup(
    root: &ProcessFixture,
    client: &rustls::ClientConfig,
    authorization: &str,
) -> Result<String, Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + WAIT_LIMIT;
    loop {
        let response = super::request_with_headers(
            root.address,
            client,
            "GET",
            "/api/latest/admin/backups/runs?limit=1",
            None,
            &[("Authorization", authorization)],
        )
        .await?;
        super::require_status(&response, "200 OK", "read backup for offline proof")?;
        let page: meshspan_api_contract::ListBackupRunsResponse =
            serde_json::from_str(super::response_body(&response)?)?;
        if let Some(run) = page.runs.first()
            && run.state == meshspan_api_contract::BackupRunStatus::Protected
        {
            return Ok(run.backup_id.clone());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(
                "automatic backup did not become protected for offline verification".into(),
            );
        }
        tokio::time::sleep(super::RETRY_INTERVAL).await;
    }
}

async fn verify(
    root: &ProcessFixture,
    backup: &Path,
    digest: &str,
    work: &Path,
) -> Result<Output, Box<dyn Error>> {
    let mut command = std::process::Command::new(&root.daemon_binary);
    command
        .arg("verify-backup")
        .arg(backup)
        .arg(digest)
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(work);
    run_command(command).await
}

pub(super) async fn run_command(
    mut command: std::process::Command,
) -> Result<Output, Box<dyn Error>> {
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut process = VerificationProcess(vec![command.spawn()?]);
    let deadline = tokio::time::Instant::now() + WAIT_LIMIT;
    while process.0[0].try_wait()?.is_none() {
        if tokio::time::Instant::now() >= deadline {
            return Err("offline verification command exceeded its deadline".into());
        }
        tokio::time::sleep(super::RETRY_INTERVAL).await;
    }
    Ok(process
        .0
        .pop()
        .ok_or("verification child missing")?
        .wait_with_output()?)
}

pub(super) struct VerificationProcess(pub(super) Vec<std::process::Child>);

impl Drop for VerificationProcess {
    fn drop(&mut self) {
        super::stop_processes(&mut self.0);
    }
}

fn assert_rejected(result: &Output) {
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!result.stderr.is_empty());
}
