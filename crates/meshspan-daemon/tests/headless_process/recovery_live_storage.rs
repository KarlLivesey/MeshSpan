// SPDX-License-Identifier: GPL-2.0-only

//! Compose existing offline commands into physical recovery on the storage-only replacement.

use super::{Error, ProcessFixture, recovery_state_set::accepted};
use std::{fs, io::Write as _, os::unix::fs::OpenOptionsExt as _, path::Path, process::Command};

const STORAGE: &str = "bcbcbcbc-bcbc-8cbc-bcbc-bcbcbcbcbcbc";

pub(super) async fn prepare(
    root: &ProcessFixture,
    directory: &Path,
    backup: &Path,
) -> Result<(), Box<dyn Error>> {
    let package = directory.join("storage-seed-package");
    let mut export = Command::new(&root.daemon_binary);
    export
        .arg("export-recovery-state")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(backup)
        .arg(STORAGE)
        .arg(&package);
    assert_eq!(accepted(export).await?["exported"], true);
    let folder = directory.join("live-restored-storage");
    fs::create_dir(&folder)?;
    fs::write(folder.join("keep.txt"), b"ordinary sibling stays untouched")?;
    let request = directory.join("live-target-request.json");
    write_request(
        &request,
        &serde_json::json!({
            "operation_id": "cececece-cece-4ece-8ece-cececececece", "path": folder,
            "usage_limit": {"kind": "percent", "percent": 95}
        }),
    )?;
    let mut prepare = Command::new(&root.daemon_binary);
    prepare
        .arg("prepare-recovery-target")
        .arg(&package)
        .arg(directory.join("root.der"))
        .arg(directory.join("storage.pk8"))
        .arg(directory.join("storage.x25519"))
        .arg(request)
        .arg(directory.join("live-target-work"));
    assert_eq!(accepted(prepare).await?["outcome"], "prepared");
    let mut collect = Command::new(&root.daemon_binary);
    collect
        .arg("collect-recovery-target")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(directory.join("live-target-work/target.report"));
    assert_eq!(accepted(collect).await?["outcome"], "recorded");
    restore_and_collect(root, directory, backup).await?;
    assert_eq!(
        fs::read(folder.join("keep.txt"))?,
        b"ordinary sibling stays untouched"
    );
    Ok(())
}

async fn restore_and_collect(
    root: &ProcessFixture,
    directory: &Path,
    backup: &Path,
) -> Result<(), Box<dyn Error>> {
    let selection: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("selection.json"))?)?;
    let source = &selection["storage"]["targets"][0];
    let request = directory.join("live-restore-request.json");
    write_request(
        &request,
        &serde_json::json!({
            "path": directory.join("live-restored-storage"),
            "inventory_directory": directory.join("coordinator/inventory"),
            "source_target_id": source["target_id"], "source_generation": source["generation"]
        }),
    )?;
    let mut restore = Command::new(&root.daemon_binary);
    restore
        .arg("restore-recovery-target")
        .arg(directory.join("storage-seed-package"))
        .arg(directory.join("root.der"))
        .arg(directory.join("storage.pk8"))
        .arg(directory.join("storage.x25519"))
        .arg(directory.join("live-target-work"))
        .arg(request);
    let report = accepted(restore).await?;
    assert_eq!(report["restored"], true);
    assert_eq!(report["receipt_count"], "1");
    let receipts = directory.join("live-target-work").join(format!(
        "restore-{}-{}",
        source["target_id"]
            .as_str()
            .ok_or("source target missing")?,
        source["generation"]
            .as_str()
            .ok_or("source generation missing")?
    ));
    let mut collect = Command::new(&root.daemon_binary);
    collect
        .arg("collect-recovery-restoration")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(backup)
        .arg(receipts)
        .arg(directory.join("live-restoration-collection"));
    assert_eq!(accepted(collect).await?["archive_matched"], true);
    Ok(())
}

fn write_request(destination: &Path, value: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?
        .write_all(&serde_json::to_vec(value)?)?;
    Ok(())
}
