// SPDX-License-Identifier: GPL-2.0-only

//! Restart proofs use the actual operator command and its durable filesystem boundaries.

use super::{
    Error, ProcessFixture, WAIT_LIMIT,
    offline_backup::{VerificationProcess, run_command},
    recovery_keys::preparation_command,
};
use meshspan_daemon::OperatingSystemClock;
use meshspan_domain::{Clock as _, NodeId};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use meshspan_recovery_bundle::RecoveredAuthority;
use std::{
    fs,
    os::unix::{fs::DirBuilderExt as _, process::ExitStatusExt as _},
    path::Path,
    process::Stdio,
};

pub(super) async fn interrupt(
    root: &ProcessFixture,
    backup: &Path,
    digest: &str,
    directory: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut command = preparation_command(root, backup, digest, directory);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process = VerificationProcess(vec![command.spawn()?]);
    let deadline = tokio::time::Instant::now() + WAIT_LIMIT;
    let checkpoint = directory.join("coordinator/build/restored.sqlite3");
    while !checkpoint.exists() {
        if process.0[0].try_wait()?.is_some() || tokio::time::Instant::now() >= deadline {
            return Err("preparation did not reach the unpublished restore checkpoint".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    process.0[0].kill()?;
    let output = process
        .0
        .pop()
        .ok_or("preparation child missing")?
        .wait_with_output()?;
    assert_eq!(output.status.signal(), Some(9));
    assert!(output.stdout.is_empty());
    assert!(!directory.join("coordinator/prepared.sqlite3").exists());
    assert!(directory.join("coordinator/intent").exists());
    Ok(())
}

pub(super) async fn exports_and_conflicts(
    root: &ProcessFixture,
    backup: &Path,
    digest: &str,
    directory: &Path,
) -> Result<(), Box<dyn Error>> {
    let work = directory.join("coordinator");
    let bundle_name = "abababab-abab-8bab-abab-abababababab.bundle";
    let bundle = fs::read(work.join(bundle_name))?;
    let report = fs::read(work.join("prepared.json"))?;
    // Simulate interruption between publishing the database and completing its outputs.
    fs::rename(work.join(bundle_name), directory.join("saved.bundle"))?;
    fs::rename(
        work.join("prepared.json"),
        directory.join("saved-report.json"),
    )?;
    fs::write(
        work.join(format!(".{bundle_name}.meshspan-0.tmp")),
        b"partial export",
    )?;
    let resumed = run_command(preparation_command(root, backup, digest, directory)).await?;
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(fs::read(work.join(bundle_name))?, bundle);
    assert_eq!(fs::read(work.join("prepared.json"))?, report);
    assert!(!work.join("build").exists());
    assert!(!work.join(format!(".{bundle_name}.meshspan-0.tmp")).exists());
    let selection = fs::read(directory.join("selection.json"))?;
    let mut changed: serde_json::Value = serde_json::from_slice(&selection)?;
    changed["storage"]["maximum_copied_bytes"] = serde_json::json!("33554432");
    fs::write(
        directory.join("selection.json"),
        serde_json::to_vec(&changed)?,
    )?;
    let rejected = run_command(preparation_command(root, backup, digest, directory)).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert_eq!(fs::read(work.join(bundle_name))?, bundle);
    fs::write(directory.join("selection.json"), selection)?;
    let mut corrupted = bundle.clone();
    *corrupted.last_mut().ok_or("empty transfer")? ^= 1;
    fs::write(work.join(bundle_name), &corrupted)?;
    let rejected = run_command(preparation_command(root, backup, digest, directory)).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert_eq!(fs::read(work.join(bundle_name))?, corrupted);
    fs::write(work.join(bundle_name), bundle)?;
    Ok(())
}

pub(super) async fn preserves_receipt(
    root: &ProcessFixture,
    backup: &Path,
    digest: &str,
    directory: &Path,
    authority: &RecoveredAuthority,
) -> Result<(), Box<dyn Error>> {
    let database = directory.join("coordinator/prepared.sqlite3");
    let node = NodeId::from_bytes(meshspan_domain::uuid_v8([171; 16]))?;
    let repo = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &database,
        OperatingSystemClock.now(),
    )?);
    let before = repo
        .recovery_key_installation(authority, node)?
        .ok_or("receipt missing")?;
    drop(repo);
    let resumed = run_command(preparation_command(root, backup, digest, directory)).await?;
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let repo = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &database,
        OperatingSystemClock.now(),
    )?);
    assert_eq!(
        repo.recovery_key_installation(authority, node)?,
        Some(before)
    );
    assert!(matches!(
        repo.load_consensus_state(2),
        Err(meshspan_metadata::ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    Ok(())
}

pub(super) async fn retained_inventory(
    root: &ProcessFixture,
    backup: &Path,
    digest: &str,
    directory: &Path,
) -> Result<(), Box<dyn Error>> {
    let work = directory.join("coordinator");
    let report = fs::read(work.join("prepared.json"))?;
    let prepared = fs::read(work.join("prepared.sqlite3"))?;
    let unavailable = directory.join("unavailable-original-media");
    fs::rename(&root.storage_path, &unavailable)?;
    let resumed = run_command(preparation_command(root, backup, digest, directory)).await?;
    fs::rename(&unavailable, &root.storage_path)?;
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&resumed.stdout)?,
        serde_json::from_slice::<serde_json::Value>(&report)?
    );
    let pack = work.join("inventory/pack-0000000000000001/pack.sqlite3");
    let before = fs::read(&pack)?;
    let mut changed = before.clone();
    *changed.last_mut().ok_or("empty retained pack")? ^= 1;
    fs::write(&pack, changed)?;
    let rejected = run_command(preparation_command(root, backup, digest, directory)).await?;
    fs::write(&pack, &before)?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let missing = directory.join("unavailable-retained-pack");
    fs::rename(&pack, &missing)?;
    let rejected = run_command(preparation_command(root, backup, digest, directory)).await?;
    fs::rename(&missing, &pack)?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert_eq!(fs::read(work.join("prepared.json"))?, report);
    assert_eq!(fs::read(work.join("prepared.sqlite3"))?, prepared);
    Ok(())
}

pub(super) async fn workspace_input_is_not_cleanup_authority(
    root: &ProcessFixture,
    backup: &Path,
    digest: &str,
    directory: &Path,
) -> Result<(), Box<dyn Error>> {
    let build = directory.join("coordinator/build");
    fs::DirBuilder::new().mode(0o700).create(&build)?;
    let supplied = build.join("plaintext.sqlite3");
    fs::copy(backup, &supplied)?;
    let before = fs::read(&supplied)?;
    let result = run_command(preparation_command(root, &supplied, digest, directory)).await?;
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(fs::read(&supplied)?, before);
    fs::rename(&supplied, directory.join("preserved-input-backup.msb"))?;
    fs::remove_dir(build)?;
    Ok(())
}
