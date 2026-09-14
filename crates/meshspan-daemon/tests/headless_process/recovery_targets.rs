// SPDX-License-Identifier: GPL-2.0-only

//! Actual replacement folder preparation and coordinator collection without service admission.

use super::{Error, ProcessFixture};
use meshspan_daemon::{LocalNodeIdentity, OperatingSystemClock};
use meshspan_domain::{Clock as _, NodeId};
use meshspan_metadata::{
    AuthoritativeRepository, ConsensusStoreError, PageLimit, PartitionDatabase,
    PreparedRecoveryTarget, StorageUsageLimit,
};
use meshspan_recovery_bundle::RecoveredAuthority;
use meshspan_storage::{MarkerFingerprint, RecoveryFolder};
use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

pub(super) async fn prepare_and_collect(
    root: &ProcessFixture,
    directory: &Path,
    authority: &RecoveredAuthority,
    backup: &Path,
) -> Result<(), Box<dyn Error>> {
    let folder = directory.join("replacement-storage");
    fs::create_dir(&folder)?;
    fs::write(
        folder.join("keep.txt"),
        b"ordinary sibling must stay untouched",
    )?;
    let request = serde_json::json!({
        "operation_id": "cbcbcbcb-cbcb-4bcb-8bcb-cbcbcbcbcbcb", "path": folder,
        "usage_limit": {"kind": "percent", "percent": 95}
    });
    let request_file = directory.join("storage-request.json");
    fs::write(&request_file, serde_json::to_vec(&request)?)?;
    fs::set_permissions(&request_file, fs::Permissions::from_mode(0o600))?;
    let output = super::offline_backup::run_command(prepare(root, directory)).await?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let prepared = assert_report(&output.stdout, "prepared")?;
    let encoded = fs::read(directory.join("target-work/target.report"))?;
    let (target, signature) =
        PreparedRecoveryTarget::decode_report(authority.root_certificate_der(), &encoded)?;
    assert_eq!(
        target.node_id,
        NodeId::from_bytes(meshspan_domain::uuid_v8([171; 16]))?
    );
    assert_eq!(target.generation, 1);
    assert_eq!(target.usage_limit, StorageUsageLimit::Percent(95));
    let identity = LocalNodeIdentity::open(&directory.join("identity.pk8"), "replacement.invalid")?;
    meshspan_certificates::NodePublicIdentity::from_sec1(identity.public_key_sec1())?
        .verify_enrolment_transcript(&target.installation_message()?, &signature)?;
    let media = RecoveryFolder::open(
        &folder,
        MarkerFingerprint::from_bytes(target.marker_fingerprint),
    )?;
    assert_eq!(media.marker().target_id(), target.target_id);
    drop(media);
    assert!(read_targets(directory, authority)?.is_empty());
    let output = super::offline_backup::run_command(collect(root, directory)).await?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let collected = assert_report(&output.stdout, "recorded")?;
    assert_eq!(read_targets(directory, authority)?, vec![target.clone()]);
    let retry = super::offline_backup::run_command(prepare(root, directory)).await?;
    assert!(
        retry.status.success(),
        "{}",
        String::from_utf8_lossy(&retry.stderr)
    );
    assert_eq!(assert_report(&retry.stdout, "prepared")?, prepared);
    assert_eq!(
        fs::read(directory.join("target-work/target.report"))?,
        encoded
    );
    let retry = super::offline_backup::run_command(collect(root, directory)).await?;
    assert!(retry.status.success());
    assert_eq!(assert_report(&retry.stdout, "recorded")?, collected);
    reject_changes(root, directory, authority, &target, request).await?;
    super::recovery_restoration::restore(root, directory, &target, authority, backup).await?;
    assert_eq!(
        fs::read(folder.join("keep.txt"))?,
        b"ordinary sibling must stay untouched"
    );
    Ok(())
}

async fn reject_changes(
    root: &ProcessFixture,
    directory: &Path,
    authority: &RecoveredAuthority,
    target: &PreparedRecoveryTarget,
    mut request: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let report_file = directory.join("target-work/target.report");
    let original = fs::read(&report_file)?;
    request["usage_limit"]["percent"] = 80.into();
    fs::write(
        directory.join("storage-request.json"),
        serde_json::to_vec(&request)?,
    )?;
    let rejected = super::offline_backup::run_command(prepare(root, directory)).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert_eq!(fs::read(&report_file)?, original);
    let mut corrupt = original.clone();
    *corrupt.last_mut().ok_or("empty target report")? ^= 1;
    fs::write(&report_file, corrupt)?;
    let rejected = super::offline_backup::run_command(collect(root, directory)).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert_eq!(read_targets(directory, authority)?, vec![target.clone()]);
    fs::write(&report_file, original)?;
    Ok(())
}

fn read_targets(
    directory: &Path,
    authority: &RecoveredAuthority,
) -> Result<Vec<PreparedRecoveryTarget>, Box<dyn Error>> {
    let database = PartitionDatabase::open_existing(
        &directory.join("coordinator/prepared.sqlite3"),
        OperatingSystemClock.now(),
    )?;
    database.check_integrity()?;
    let repository = AuthoritativeRepository::new(database);
    assert!(matches!(
        repository.load_consensus_state(2),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    let targets = repository.recovery_targets(
        authority,
        NodeId::from_bytes(meshspan_domain::uuid_v8([171; 16]))?,
        None,
        PageLimit::new(10)?,
    )?;
    for target in &targets {
        assert_eq!(
            repository.recovery_storage_target_marker(target.target_id, 1)?,
            None
        );
    }
    Ok(targets)
}

fn assert_report(bytes: &[u8], outcome: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let report: serde_json::Value = serde_json::from_slice(bytes)?;
    assert_eq!(report["outcome"], outcome);
    assert_eq!(report["service_started"], false);
    assert_eq!(report["admission_ready"], false);
    Ok(report)
}

fn prepare(root: &ProcessFixture, directory: &Path) -> Command {
    let mut command = Command::new(&root.daemon_binary);
    command
        .arg("prepare-recovery-target")
        .arg(directory.join("state-package"))
        .arg(directory.join("root.der"))
        .arg(directory.join("identity.pk8"))
        .arg(directory.join("wrapping.x25519"))
        .arg(directory.join("storage-request.json"))
        .arg(directory.join("target-work"));
    command
}

fn collect(root: &ProcessFixture, directory: &Path) -> Command {
    let mut command = Command::new(&root.daemon_binary);
    command
        .arg("collect-recovery-target")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(directory.join("target-work/target.report"));
    command
}
