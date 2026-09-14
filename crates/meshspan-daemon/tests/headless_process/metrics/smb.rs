// SPDX-License-Identifier: GPL-2.0-only

//! Real SMB credential rejection is measured independently of successful logins and restarts.

use super::{Error, json};
use crate::{ClientConfig, ProcessFixture};

#[tokio::test]
#[ignore = "requires the local pinned smbclient container image"]
async fn real_smb_authentication_rejection_is_counted_once_and_resets_after_restart()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
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
        let authorization = format!("Bearer {key}");
        super::configure(
            root.address,
            &client,
            &authorization,
            &json!({
                "operation_id": "00000000-0000-4000-8000-000000000090", "expected_sequence": 0,
                "policy": {"enabled": true, "allowed_principals": [administrator]}
            }),
        )
        .await?;
        assert_eq!(count(&root, &client, key).await?, 0);
        reject_login(root.smb_address.port()).await?;
        assert_eq!(count(&root, &client, key).await?, 1);
        crate::run_real_smb_command(
            root.smb_address.port(),
            key.to_owned(),
            root.temporary.path(),
            "pwd",
        )
        .await?;
        assert_eq!(
            count(&root, &client, key).await?,
            1,
            "successful login counted as rejection"
        );
        crate::stop_processes(&mut processes);
        processes[0] = root.start()?;
        crate::wait_for_status(root.address, &client, "configured").await?;
        assert_eq!(count(&root, &client, key).await?, 0);
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    crate::stop_processes(&mut processes);
    crate::retain_failure_state(proof, [root.temporary])
}

async fn reject_login(port: u16) -> Result<(), Box<dyn Error>> {
    let result = tokio::task::spawn_blocking(move || {
        let mut client = crate::smb_client_process(
            port,
            "deliberately-invalid-key".to_owned(),
            None,
            crate::real_smb_command_script(),
        )?;
        client.env("MESHSPAN_SMB_COMMAND", "ls").output()
    })
    .await??;
    assert!(
        !result.status.success(),
        "invalid SMB credential was accepted"
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("NT_STATUS_LOGON_FAILURE")
            || String::from_utf8_lossy(&result.stderr).contains("NT_STATUS_LOGON_FAILURE"),
        "SMB failed before producing the expected authentication rejection"
    );
    Ok(())
}

async fn count(
    root: &ProcessFixture,
    client: &ClientConfig,
    key: &str,
) -> Result<u64, Box<dyn Error>> {
    let response = crate::request_with_headers(
        root.address,
        client,
        "GET",
        super::SCRAPE,
        None,
        &[("Authorization", &format!("Bearer {key}"))],
    )
    .await?;
    crate::require_status(
        &response,
        "200 OK",
        "scrape SMB authentication observations",
    )?;
    Ok(crate::response_body(&response)?
        .lines()
        .find_map(|line| line.strip_prefix("meshspan_v1_smb_authentication_rejections_total "))
        .ok_or("SMB authentication metric missing")?
        .parse()?)
}
