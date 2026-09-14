// SPDX-License-Identifier: GPL-2.0-only

//! Restart an admitted successor incarnation through normal HTTPS and QUIC startup.
//! The fixture supplies the admitted projection; it does not prove disaster-recovery admission.

use super::*;

#[tokio::test]
async fn successor_incarnation_restarts_serves_files_and_accepts_a_new_peer()
-> Result<(), Box<dyn Error>> {
    successor_workflow(false).await
}

#[tokio::test]
#[ignore = "requires the local pinned smbclient container image"]
async fn successor_incarnation_serves_real_smb_reads_writes_and_deletes()
-> Result<(), Box<dyn Error>> {
    successor_workflow(true).await
}

async fn successor_workflow(smb: bool) -> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let peer = ProcessFixture::new()?;
    let mut cleanup = ProcessCleanup(vec![root.start()?]);
    let proof = async {
        let claim = wait_for_claim(&root.claim_path).await?;
        let client = wait_for_client(&root.identity_path).await?;
        wait_for_status(root.address, &client, "claim_required").await?;
        let created = create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("missing initial key")?;
        save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        wait_for_storage_folder_visibility(&root, &client, key).await?;
        stop_processes(&mut cleanup.0);
        let connection =
            rusqlite::Connection::open(root.state_path.join("root-authority.sqlite3"))?;
        // Only a stopped, isolated test fixture: no production incarnation mutation or
        // recovery barrier is bypassed by the implementation being exercised.
        assert_eq!(
            connection.execute("UPDATE nodes SET current_incarnation = 2", [])?,
            1
        );
        drop(connection);
        cleanup.0[0] = root.start()?;
        wait_for_status(root.address, &client, "configured").await?;
        let administrator = bootstrap_administrator_id(&claim, &root.identity_path)?;
        let details = create_volume_details(root.address, &client, key, &administrator).await?;
        let volume = &details.volume_id;
        let content = b"A successor incarnation must serve the same namespace";
        upload_file(root.address, &client, key, volume, content).await?;
        assert_file_surfaces(root.address, &client, key, volume, content).await?;
        if smb {
            verify_smb(&root, &client, key, &details).await?;
        }
        let join = issue_join_code(&root, &client, key).await?;
        cleanup.0.push(peer.start_join(&join)?);
        let peer_client = wait_for_client(&peer.identity_path).await?;
        wait_for_status(peer.address, &peer_client, "configured").await?;
        wait_for_file_surfaces(peer.address, &peer_client, key, volume, content).await?;
        Ok(())
    }
    .await;
    stop_processes(&mut cleanup.0);
    retain_failure_state(proof, [root.temporary, peer.temporary])
}

async fn verify_smb(
    root: &ProcessFixture,
    client: &ClientConfig,
    key: &str,
    volume: &CreatedVolume,
) -> Result<(), Box<dyn Error>> {
    publish_smb_export(root.address, client, key, volume).await?;
    wait_for_smb_listener(root.smb_address).await?;
    let expected = b"SMB uses the successor's live incarnation for every file operation";
    fs::write(root.temporary.path().join("smb-upload.bin"), expected)?;
    run_real_smb_command(root.smb_address.port(), key.to_owned(), root.temporary.path(),
        "put /proof/smb-upload.bin successor.bin; get successor.bin /proof/smb-download.bin; del successor.bin"
    ).await?;
    assert_eq!(
        fs::read(root.temporary.path().join("smb-download.bin"))?,
        expected
    );
    wait_for_named_file_listing_state(
        root.address,
        client,
        key,
        &volume.volume_id,
        "successor.bin",
        false,
    )
    .await?;
    Ok(())
}
