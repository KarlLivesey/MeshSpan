// SPDX-License-Identifier: GPL-2.0-only

//! Slow public SMB proof: an idle open must outlive its original one-minute lease.

use std::error::Error;

#[tokio::test]
#[ignore = "65-second lease proof using an optional locally compiled Samba client"]
async fn real_smb_idle_open_survives_original_lease() -> Result<(), Box<dyn Error>> {
    let helper = std::path::PathBuf::from(
        std::env::var_os("MESHSPAN_SMB_LEASE_CLIENT")
            .ok_or("set MESHSPAN_SMB_LEASE_CLIENT to the optional local helper binary")?,
    );
    if !helper.is_absolute() || !helper.is_file() {
        return Err("SMB lease helper must be an existing absolute path".into());
    }
    let root = crate::ProcessFixture::new()?;
    let mut processes = vec![root.start()?];
    let proof = async {
        let claim = crate::wait_for_claim(&root.claim_path).await?;
        let client = crate::wait_for_client(&root.identity_path).await?;
        let administrator = crate::bootstrap_administrator_id(&claim, &root.identity_path)?;
        crate::wait_for_status(root.address, &client, "claim_required").await?;
        let created = crate::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("missing bootstrap key")?;
        crate::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        crate::wait_for_storage_folder_visibility(&root, &client, key).await?;
        let volume =
            crate::create_volume_details(root.address, &client, key, &administrator).await?;
        crate::publish_smb_export(root.address, &client, key, &volume).await?;
        crate::wait_for_smb_listener(root.smb_address).await?;
        let url = format!(
            "smb://127.0.0.1:{}/process-files/idle-lease.txt",
            root.smb_address.port()
        );
        let key = key.to_owned();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new("timeout")
                .args(["100"])
                .arg(helper)
                .arg(url)
                .env("MESHSPAN_SMB_PASSWORD", key)
                .output()
        })
        .await??;
        crate::require_smb_client_success(&output)?;
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("RETAINED_HANDLE_READ_WRITE_CLOSE_VERIFIED")
        );
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    crate::stop_processes(&mut processes);
    crate::retain_failure_state(proof, [root.temporary])
}
