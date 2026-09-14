// SPDX-License-Identifier: GPL-2.0-only

//! Real encrypted export and source packs verify file bytes with the original daemon stopped.

use super::{Error, ProcessFixture, offline_backup::run_command};
use meshspan_metadata::{AuthoritativeRepository, PageLimit, PartitionDatabase};
use sha2::Digest as _;
use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

pub(super) async fn verify(
    root: &ProcessFixture,
    coordinator: &Path,
    backup: &Path,
) -> Result<(), Box<dyn Error>> {
    let selection = write_selection(root, coordinator)?;
    fs::rename(
        root.state_path.join("storage-targets"),
        coordinator.join("unavailable-target-journals"),
    )?;
    let original_pack = root
        .storage_path
        .join(".meshspan/packs/0000000000000001.sqlite3");
    let original_bytes = fs::read(&original_pack)?;
    let work = coordinator.join("content-candidate");
    let result = run_command(command(root, coordinator, backup, &selection, &work)).await?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(report["content_verified"], true);
    assert_eq!(report["retained_roots_checked"], "1");
    assert_eq!(report["manifest_references_checked"], "1");
    assert_eq!(
        report["logical_bytes_checked"],
        b"Recovery must retain this file's history and content-key envelope"
            .len()
            .to_string()
    );
    assert_eq!(report["chunks_checked"], "1");
    assert_eq!(report["target_inventory_verified"], true);
    let prepared: serde_json::Value =
        serde_json::from_slice(&fs::read(coordinator.join("coordinator/prepared.json"))?)?;
    assert_eq!(
        report["target_inventory_sha256"],
        prepared["target_inventory_sha256"]
    );
    assert_eq!(report["admission_ready"], false);
    assert_eq!(report["service_started"], false);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(work.join("content.json"))?)?,
        report
    );
    assert!(!root.state_path.join("filesystem").exists());
    assert!(!root.state_path.join("storage-targets").exists());
    assert_eq!(fs::read(original_pack)?, original_bytes);
    assert_eq!(
        fs::read(root.storage_path.join("operator-file.txt"))?,
        b"untouched"
    );
    reject_changed_inputs(root, coordinator, backup, &selection).await?;
    Ok(())
}

fn write_selection(
    _root: &ProcessFixture,
    coordinator: &Path,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let selection = coordinator.join("storage-selection.json");
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(coordinator.join("selection.json"))?)?;
    fs::write(&selection, serde_json::to_vec(&original["storage"])?)?;
    fs::set_permissions(&selection, fs::Permissions::from_mode(0o600))?;
    Ok(selection)
}

pub(super) fn source_selection(root: &ProcessFixture) -> Result<serde_json::Value, Box<dyn Error>> {
    let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &root.state_path.join("root-authority.sqlite3"),
        meshspan_domain::UnixMicros::new(1),
    )?);
    let page = repository.topology_targets(None, PageLimit::new(2)?)?;
    assert_eq!(page.items.len(), 1);
    let target = &page.items[0];
    let value = serde_json::json!({"maximum_copied_bytes": "16777216", "targets": [{
        "target_id": target.target_id.to_string(), "generation": target.generation.to_string(),
        "storage_path": root.storage_path.to_str().ok_or("non-UTF fixture path")?
    }]});
    // Domain Display is compact hex; the operator boundary deliberately uses canonical UUIDs.
    let compact = target.target_id.to_string();
    let canonical = format!(
        "{}-{}-{}-{}-{}",
        &compact[..8],
        &compact[8..12],
        &compact[12..16],
        &compact[16..20],
        &compact[20..]
    );
    let mut value = value;
    value["targets"][0]["target_id"] = serde_json::json!(canonical);
    Ok(value)
}

async fn reject_changed_inputs(
    root: &ProcessFixture,
    coordinator: &Path,
    backup: &Path,
    selection: &Path,
) -> Result<(), Box<dyn Error>> {
    let original = fs::read(selection)?;
    let mut changed: serde_json::Value = serde_json::from_slice(&original)?;
    changed["targets"][0]["generation"] = serde_json::json!("2");
    fs::write(selection, serde_json::to_vec(&changed)?)?;
    let missing = coordinator.join("unknown-generation");
    let result = run_command(command(root, coordinator, backup, selection, &missing)).await?;
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!missing.join("content.json").exists());
    fs::write(selection, &original)?;
    let nested = root.storage_path.join("must-not-create");
    let result = run_command(command(root, coordinator, backup, selection, &nested)).await?;
    assert!(!result.status.success());
    assert!(!nested.exists());
    let pack = root
        .storage_path
        .join(".meshspan/packs/0000000000000001.sqlite3");
    let before = fs::read(&pack)?;
    // The stopped daemon can leave committed pages in WAL. Opening a writer below may
    // checkpoint and remove it; restoring only the old main file would lose those pages.
    let sidecars = ["-wal", "-shm", "-journal"].map(|suffix| {
        let file = pack.with_file_name(format!("0000000000000001.sqlite3{suffix}"));
        let bytes = match fs::read(&file) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        };
        (file, bytes)
    });
    let sidecars = sidecars
        .into_iter()
        .map(|(file, bytes)| Ok((file, bytes?)))
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    let connection = rusqlite::Connection::open(&pack)?;
    connection.execute(
        "UPDATE shards SET stored_bytes = zeroblob(stored_length)",
        [],
    )?;
    drop(connection);
    let damaged = coordinator.join("damaged-content");
    let result = run_command(command(root, coordinator, backup, selection, &damaged)).await?;
    reject_unverified_preparation(root, coordinator, backup).await?;
    fs::write(&pack, &before)?;
    for (file, bytes) in sidecars {
        match bytes {
            Some(bytes) => fs::write(file, bytes)?,
            None => match fs::remove_file(file) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            },
        }
    }
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!damaged.join("content.json").exists());
    assert_eq!(fs::read(&pack)?, before);
    Ok(())
}

/// File verification must precede signing, not merely reject activation after keys were exported.
async fn reject_unverified_preparation(
    root: &ProcessFixture,
    coordinator: &Path,
    backup: &Path,
) -> Result<(), Box<dyn Error>> {
    let failed = coordinator.join("unverified-preparation");
    fs::create_dir(&failed)?;
    fs::copy(
        coordinator.join("selection.json"),
        failed.join("selection.json"),
    )?;
    let digest = super::recovery_keys::hex(&sha2::Sha256::digest(fs::read(backup)?))?;
    let result = run_command(super::recovery_keys::preparation_command(
        root, backup, &digest, &failed,
    ))
    .await?;
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    for name in [
        "prepared.sqlite3",
        "prepared.json",
        "root.der",
        "abababab-abab-8bab-abab-abababababab.bundle",
    ] {
        assert!(!failed.join("coordinator").join(name).exists(), "{name}");
    }
    assert!(!failed.join("coordinator/build").exists());
    Ok(())
}

fn command(
    root: &ProcessFixture,
    coordinator: &Path,
    source: &Path,
    selection: &Path,
    work: &Path,
) -> Command {
    let mut command = Command::new(&root.daemon_binary);
    command
        .arg("verify-recovery-content")
        .arg(coordinator.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(source)
        .arg(selection)
        .arg(work);
    command
}
