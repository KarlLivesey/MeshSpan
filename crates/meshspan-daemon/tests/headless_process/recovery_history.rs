// SPDX-License-Identifier: GPL-2.0-only

//! A non-empty real backup retains authenticated filesystem journals and decryptable file content.

use super::{Error, ProcessFixture, offline_backup::run_command};
use std::{fs, path::Path, process::Command};

pub(super) async fn populate(
    root: &ProcessFixture,
    client: &rustls::ClientConfig,
    key: &str,
    administrator: &str,
    clients: super::recovery_live_file::Clients,
) -> Result<(), Box<dyn Error>> {
    let details = super::create_volume_details(root.address, client, key, administrator).await?;
    if clients.includes_smb() {
        super::publish_smb_export(root.address, client, key, &details).await?;
    }
    let volume = details.volume_id;
    super::assign_single_node_strong_acknowledgement(root.address, client, key, &volume).await?;
    super::upload_file(
        root.address,
        client,
        key,
        &volume,
        b"Recovery must retain this file's history and content-key envelope",
    )
    .await?;
    super::recovery_live_file::remember(root, key, &volume, clients)?;
    Ok(())
}

pub(super) async fn stage(
    root: &ProcessFixture,
    coordinator: &Path,
    backup: &Path,
) -> Result<(), Box<dyn Error>> {
    let source = root.state_path.join("filesystem");
    let names = ["filesystem-branch.sqlite3", "filesystem-content.sqlite3"];
    let before = names
        .iter()
        .map(|name| fs::read(source.join(name)))
        .collect::<Result<Vec<_>, _>>()?;
    let destination = coordinator.join("history-candidate");
    let unavailable = root.temporary.path().join("unavailable-original-journals");
    fs::rename(&source, &unavailable)?;
    assert!(!source.exists());
    let result = run_command(command(root, coordinator, backup, &destination)).await?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(report["staged"], true);
    assert_eq!(report["history_source"], "authenticated_backup");
    assert_eq!(report["retained_roots_checked"], "1");
    assert_eq!(report["manifest_references_checked"], "1");
    assert_eq!(report["shards_verified"], false);
    assert_eq!(report["admission_ready"], false);
    assert_eq!(report["service_started"], false);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(destination.join("history.json"))?)?,
        report
    );
    for (name, bytes) in names.iter().zip(before) {
        assert_eq!(fs::read(unavailable.join(name))?, bytes);
    }
    assert!(!source.exists());
    let rejected = run_command(command(root, coordinator, backup, &destination)).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());

    super::recovery_content::verify(root, coordinator, backup).await?;

    // Corrupt only the staged donor copy, never the original daemon's journals.
    let content = rusqlite::Connection::open(destination.join("filesystem-content.sqlite3"))?;
    content.execute(
        "UPDATE content_publications SET key_ciphertext = zeroblob(48)",
        [],
    )?;
    drop(content);
    let failed_work = coordinator.join("bad-history-candidate");
    let rejected = run_command(command(root, coordinator, &destination, &failed_work)).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!failed_work.join("history.json").exists());
    Ok(())
}

fn command(
    root: &ProcessFixture,
    coordinator: &Path,
    source: &Path,
    destination: &Path,
) -> Command {
    let mut command = Command::new(&root.daemon_binary);
    command
        .arg("stage-recovery-history")
        .arg(coordinator.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(source)
        .arg(destination);
    command
}
