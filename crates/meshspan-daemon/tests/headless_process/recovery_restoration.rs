// SPDX-License-Identifier: GPL-2.0-only

//! Real node-side restoration into a freshly prepared provider, with exact durable retry.

use super::{Error, ProcessFixture};
use meshspan_contracts::ShardReceipt;
use meshspan_daemon::LocalNodeIdentity;
use meshspan_metadata::PreparedRecoveryTarget;
use meshspan_storage::{MarkerFingerprint, RecoveryFolder, RecoveryInventory};
use sha2::{Digest as _, Sha256};
use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

pub(super) async fn restore(
    root: &ProcessFixture,
    directory: &Path,
    target: &PreparedRecoveryTarget,
    authority: &meshspan_recovery_bundle::RecoveredAuthority,
    backup: &Path,
) -> Result<(), Box<dyn Error>> {
    let unavailable_source = directory.join("unavailable-original-storage");
    fs::rename(&root.storage_path, &unavailable_source)?;
    let selection: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("selection.json"))?)?;
    let source = &selection["storage"]["targets"][0];
    let request = serde_json::json!({"path": directory.join("replacement-storage"),
        "inventory_directory": directory.join("coordinator/inventory"),
        "source_target_id": source["target_id"], "source_generation": source["generation"]});
    let request_file = directory.join("restore-target.json");
    fs::write(&request_file, serde_json::to_vec(&request)?)?;
    fs::set_permissions(&request_file, fs::Permissions::from_mode(0o600))?;
    let work = directory.join("target-work").join(format!(
        "restore-{}-{}",
        source["target_id"].as_str().ok_or("source missing")?,
        source["generation"].as_str().ok_or("generation missing")?
    ));
    // A live folder owner blocks this separate process before it can store or report success.
    let guard = RecoveryFolder::open(
        &directory.join("replacement-storage"),
        MarkerFingerprint::from_bytes(target.marker_fingerprint),
    )?;
    let rejected = super::offline_backup::run_command(command(root, directory)).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!work.join("restored.json").exists());
    drop(guard);
    let output = super::offline_backup::run_command(command(root, directory)).await?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["restored"], true);
    assert_eq!(report["service_started"], false);
    assert_eq!(report["admission_ready"], false);
    assert_eq!(report["receipt_count"], "1");
    assert!(!work.join("build").exists());
    let encoded = fs::read(work.join("receipts.bin"))?;
    let receipts = decode_receipts(&encoded)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(report["receipts_sha256"], hex(&Sha256::digest(&encoded))?);
    assert_eq!(receipts[0].target_id, target.target_id);
    assert_eq!(receipts[0].target_generation, target.generation);
    verify_signature(directory, target, source, &report)?;
    verify_bytes(directory, target, receipts[0])?;
    // Simulate loss of the coordinator-facing report after provider writes were durable.
    fs::remove_file(work.join("restored.json"))?;
    fs::remove_file(work.join("receipts.bin"))?;
    let retried = super::offline_backup::run_command(command(root, directory)).await?;
    assert!(
        retried.status.success(),
        "{}",
        String::from_utf8_lossy(&retried.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&retried.stdout)?,
        report
    );
    assert_eq!(fs::read(work.join("receipts.bin"))?, encoded);
    verify_bytes(directory, target, receipts[0])?;
    super::recovery_restoration_collection::collect(root, directory, authority, backup, &work)
        .await?;
    super::recovery_routes::transfer(root, directory, backup, receipts[0], authority).await?;
    fs::rename(unavailable_source, &root.storage_path)?;
    Ok(())
}

fn verify_bytes(
    directory: &Path,
    target: &PreparedRecoveryTarget,
    receipt: ShardReceipt,
) -> Result<(), Box<dyn Error>> {
    let source = RecoveryInventory::open(
        &directory.join("coordinator/inventory"),
        target.authorization.claims().backup_digest,
    )?;
    let expected = source
        .read_exact(receipt.shard, receipt.length, receipt.digest)?
        .ok_or("source bytes missing")?;
    drop(source);
    let media = RecoveryFolder::open(
        &directory.join("replacement-storage"),
        MarkerFingerprint::from_bytes(target.marker_fingerprint),
    )?;
    let pack = media.open_pack(1, &directory.join("restored-pack-check"), 16 * 1024 * 1024)?;
    assert_eq!(pack.inventory_page(0, 10)?.records.len(), 1);
    assert_eq!(
        pack.read_exact(receipt.shard, receipt.length, receipt.digest)?,
        expected
    );
    pack.finish()?;
    Ok(())
}

fn verify_signature(
    directory: &Path,
    target: &PreparedRecoveryTarget,
    source: &serde_json::Value,
    report: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let mut expected = b"MeshSpan recovery target restoration v1\0".to_vec();
    expected.extend_from_slice(&target.installation_message()?);
    expected.extend_from_slice(&unhex(
        &source["target_id"]
            .as_str()
            .ok_or("source missing")?
            .replace('-', ""),
    )?);
    expected.extend_from_slice(
        &source["generation"]
            .as_str()
            .ok_or("generation missing")?
            .parse::<u64>()?
            .to_be_bytes(),
    );
    expected.extend_from_slice(&unhex(
        report["receipts_sha256"].as_str().ok_or("digest missing")?,
    )?);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(
        &report["encrypted_bytes"]
            .as_str()
            .ok_or("size missing")?
            .parse::<u64>()?
            .to_be_bytes(),
    );
    assert_eq!(report["installation_message"], hex(&expected)?);
    let identity = LocalNodeIdentity::open(&directory.join("identity.pk8"), "replacement.invalid")?;
    meshspan_certificates::NodePublicIdentity::from_sec1(identity.public_key_sec1())?
        .verify_enrolment_transcript(
            &expected,
            &unhex(
                report["installation_signature"]
                    .as_str()
                    .ok_or("signature missing")?,
            )?,
        )?;
    Ok(())
}

fn decode_receipts(bytes: &[u8]) -> Result<Vec<ShardReceipt>, Box<dyn Error>> {
    let mut remaining = bytes
        .strip_prefix(b"MSRRCPT\x01")
        .ok_or("bad receipts version")?;
    let mut receipts = Vec::new();
    while !remaining.is_empty() {
        let (length, rest) = remaining.split_at_checked(2).ok_or("truncated length")?;
        let size = usize::from(u16::from_be_bytes(length.try_into()?));
        assert_eq!(size, 126);
        let (receipt, rest) = rest.split_at_checked(size).ok_or("truncated receipt")?;
        receipts.push(meshspan_data_plane::decode_shard_receipt(receipt)?);
        remaining = rest;
    }
    Ok(receipts)
}

fn command(root: &ProcessFixture, directory: &Path) -> Command {
    let mut command = Command::new(&root.daemon_binary);
    command
        .arg("restore-recovery-target")
        .arg(directory.join("state-package"))
        .arg(directory.join("root.der"))
        .arg(directory.join("identity.pk8"))
        .arg(directory.join("wrapping.x25519"))
        .arg(directory.join("target-work"))
        .arg(directory.join("restore-target.json"));
    command
}

pub(super) fn hex(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    use std::fmt::Write as _;
    let mut encoded = String::new();
    for byte in bytes {
        write!(encoded, "{byte:02x}")?;
    }
    Ok(encoded)
}

fn unhex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}
