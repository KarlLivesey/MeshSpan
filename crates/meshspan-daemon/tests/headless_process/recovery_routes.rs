// SPDX-License-Identifier: GPL-2.0-only

//! Actual encrypted route-candidate export and replacement-node installation, still fenced.

use super::{Error, ProcessFixture};
use meshspan_contracts::ShardReceipt;
use meshspan_daemon::OperatingSystemClock;
use meshspan_domain::Clock as _;
use meshspan_filesystem::DurableContentCatalog;
use std::{fs, path::Path, process::Command};

pub(super) async fn transfer(
    root: &ProcessFixture,
    directory: &Path,
    backup: &Path,
    expected: ShardReceipt,
    authority: &meshspan_recovery_bundle::RecoveredAuthority,
) -> Result<(), Box<dyn Error>> {
    let package = directory.join("route-state-package");
    let original = directory.join("installed-state/filesystem/filesystem-content.sqlite3");
    let before = fs::read(&original)?;
    let exported =
        super::offline_backup::run_command(export(root, directory, backup, &package)).await?;
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&exported.stdout)?;
    assert_eq!(report["restored_route_references"], "1");
    assert_eq!(report["admission_ready"], false);
    assert!(!package.join("staging").exists());
    let destination = directory.join("installed-route-state");
    let mut install = Command::new(&root.daemon_binary);
    install
        .arg("install-recovery-state")
        .arg(&package)
        .arg(directory.join("root.der"))
        .arg("abababab-abab-8bab-abab-abababababab")
        .arg(directory.join("identity.pk8"))
        .arg(directory.join("wrapping.x25519"))
        .arg(&destination);
    let installed = super::offline_backup::run_command(install).await?;
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    super::recovery_state::verify_installed(directory, &destination)?;
    verify_routes(&destination, expected)?;
    assert_eq!(fs::read(original)?, before);
    assert!(!root.storage_path.exists());
    rejects_corrupt_collection(root, directory, backup).await?;
    super::recovery_state_collection::collect(root, directory, authority).await?;
    super::recovery_providers::transfer(root, directory, backup, expected).await?;
    Ok(())
}

async fn rejects_corrupt_collection(
    root: &ProcessFixture,
    directory: &Path,
    backup: &Path,
) -> Result<(), Box<dyn Error>> {
    let sql = rusqlite::Connection::open(directory.join("coordinator/prepared.sqlite3"))?;
    let original: Vec<u8> = sql.query_row(
        "SELECT receipt FROM partition_recovery_shards WHERE ordinal = 0",
        [],
        |row| row.get(0),
    )?;
    let guard: String = sql.query_row("SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = 'partition_recovery_shards_immutable'", [], |row| row.get(0))?;
    sql.execute_batch("DROP TRIGGER partition_recovery_shards_immutable; UPDATE partition_recovery_shards SET receipt = zeroblob(126) WHERE ordinal = 0;")?;
    let work = directory.join("corrupt-route-package");
    let result = super::offline_backup::run_command(export(root, directory, backup, &work)).await;
    sql.execute(
        "UPDATE partition_recovery_shards SET receipt = ?1 WHERE ordinal = 0",
        [original],
    )?;
    sql.execute_batch(&guard)?;
    let rejected = result?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!work.join("state.auth").exists());
    assert!(!work.join("state.msb").exists());
    Ok(())
}

fn export(root: &ProcessFixture, directory: &Path, backup: &Path, package: &Path) -> Command {
    let mut command = Command::new(&root.daemon_binary);
    command
        .arg("export-recovery-state")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(backup)
        .arg("abababab-abab-8bab-abab-abababababab")
        .arg(package);
    command
}

fn verify_routes(directory: &Path, expected: ShardReceipt) -> Result<(), Box<dyn Error>> {
    let catalog =
        DurableContentCatalog::open(&directory.join("filesystem"), OperatingSystemClock.now())?;
    let candidate = catalog
        .shard_repair_candidate(
            expected.target_id,
            expected.target_generation,
            expected.shard,
        )?
        .ok_or("replacement route missing")?;
    assert_eq!(candidate.source_receipt, expected);
    assert_eq!(candidate.source_layout_generation, 2);
    let content = catalog
        .committed_content_by_manifest(candidate.manifest_id)?
        .ok_or("replacement content missing")?;
    let stripe = catalog.committed_protected_stripe(content, expected.shard.stripe_index)?;
    assert_eq!(stripe.receipts.as_slice(), &[expected]);
    Ok(())
}
