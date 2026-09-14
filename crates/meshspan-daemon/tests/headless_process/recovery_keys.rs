// SPDX-License-Identifier: GPL-2.0-only

//! Actual daemon command installs keys exported from the selected encrypted metadata backup.

use super::{Error, ProcessFixture};
use meshspan_daemon::{LocalNodeIdentity, LocalWrappingKey, OperatingSystemClock};
use meshspan_domain::{Clock as _, NodeId};
use meshspan_metadata::AuthoritativeRepository;
use meshspan_recovery_bundle::{RecoveredAuthority, RecoveryBundle, RecoveryBundleCode};
use std::{
    fs,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

pub(super) async fn install_from_export(
    root: &ProcessFixture,
    backup: &Path,
    digest: &str,
) -> Result<(), Box<dyn Error>> {
    let directory = root.temporary.path().join("replacement-key-installation");
    fs::create_dir(&directory)?;
    let identity_path = directory.join("identity.pk8");
    let identity = LocalNodeIdentity::create(&identity_path, "replacement.invalid")?;
    let wrapping_path = directory.join("wrapping.x25519");
    let wrapping = LocalWrappingKey::open_or_create(&wrapping_path)?;
    let saved_bundle = fs::read_to_string(&root.saved_recovery_bundle_path)?;
    let authority = RecoveryBundle::decode(&decode_hex(
        saved_bundle
            .trim_end()
            .strip_prefix("meshspan-recovery-file-v1.")
            .ok_or("recovery download prefix missing")?,
    )?)?
    .open(&RecoveryBundleCode::parse(
        fs::read_to_string(&root.saved_recovery_code_path)?.trim(),
    )?)?;
    let trusted_root = directory.join("root.der");
    protected_write(&trusted_root, authority.root_certificate_der())?;
    let bundle = directory.join("keys.bundle");
    let generations =
        prepare_bundle(root, backup, digest, &directory, &identity, &wrapping).await?;
    fs::copy(
        directory.join("coordinator/abababab-abab-8bab-abab-abababababab.bundle"),
        &bundle,
    )?;
    fs::set_permissions(&bundle, fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        fs::read(directory.join("coordinator/root.der"))?,
        authority.root_certificate_der()
    );
    let destination = directory.join("installed.bundle");
    let command = install_command(root, &directory, &destination);
    let report = super::offline_backup::run_command(command).await?;
    assert!(
        report.status.success(),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&report.stdout)?;
    assert_eq!(report["installed"], true);
    assert_eq!(report["service_started"], false);
    assert_eq!(report["node_certificate_generation"], "1");
    assert_eq!(
        report["verified_secret_generations"],
        generations.to_string()
    );
    assert_eq!(fs::read(&destination)?, fs::read(&bundle)?);
    assert_eq!(
        fs::metadata(&destination)?.permissions().mode() & 0o777,
        0o600
    );
    meshspan_certificates::NodePublicIdentity::from_sec1(identity.public_key_sec1())?
        .verify_enrolment_transcript(
            &decode_hex(
                report["installation_message"]
                    .as_str()
                    .ok_or("message missing")?,
            )?,
            &decode_hex(
                report["installation_signature"]
                    .as_str()
                    .ok_or("signature missing")?,
            )?,
        )?;
    collect_installation(root, &directory, &authority, &report).await?;
    super::recovery_resume::preserves_receipt(root, backup, digest, &directory, &authority).await?;
    super::recovery_history::stage(root, &directory, backup).await?;
    super::recovery_state::transfer(root, &directory, backup, &authority).await?;
    super::recovery_state_set::prove(root, backup, digest, &directory, &authority).await?;
    super::recovery_certificate_transport::prove(&directory).await?;
    let retry = install_command(root, &directory, &destination);
    let retry = super::offline_backup::run_command(retry).await?;
    assert!(retry.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&retry.stdout)?,
        report
    );
    let original = fs::read(&destination)?;
    let mut damaged = original.clone();
    *damaged.last_mut().ok_or("empty bundle")? ^= 1;
    fs::write(&bundle, damaged)?;
    let rejected = install_command(root, &directory, &directory.join("rejected.bundle"));
    let rejected = super::offline_backup::run_command(rejected).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!directory.join("rejected.bundle").exists());
    assert_eq!(fs::read(destination)?, original);
    Ok(())
}

async fn collect_installation(
    root: &ProcessFixture,
    directory: &Path,
    authority: &RecoveredAuthority,
    report: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let prepared = directory.join("coordinator/prepared.sqlite3");
    let repo = AuthoritativeRepository::new(meshspan_metadata::PartitionDatabase::open_existing(
        &prepared,
        OperatingSystemClock.now(),
    )?);
    let node = NodeId::from_bytes(meshspan_domain::uuid_v8([171; 16]))?;
    assert_eq!(repo.recovery_key_installation(authority, node)?, None);
    drop(repo);
    let report_file = directory.join("installation.json");
    let mut invalid = report.clone();
    invalid["installation_signature"] = serde_json::Value::String("00".repeat(64));
    protected_write(&report_file, &serde_json::to_vec(&invalid)?)?;
    let rejected = super::offline_backup::run_command(collection_command(root, directory)).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let repo = AuthoritativeRepository::new(meshspan_metadata::PartitionDatabase::open_existing(
        &prepared,
        OperatingSystemClock.now(),
    )?);
    assert_eq!(repo.recovery_key_installation(authority, node)?, None);
    drop(repo);
    fs::write(&report_file, serde_json::to_vec(report)?)?;
    let output = super::offline_backup::run_command(collection_command(root, directory)).await?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let collected: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(collected["recorded"], true);
    assert_eq!(collected["node_id"], "abababab-abab-8bab-abab-abababababab");
    assert_eq!(collected["sha256"], report["sha256"]);
    assert_eq!(collected["service_started"], false);
    assert_eq!(collected["admission_ready"], false);
    let repo = AuthoritativeRepository::new(meshspan_metadata::PartitionDatabase::open_existing(
        &prepared,
        OperatingSystemClock.now(),
    )?);
    let receipt = repo
        .recovery_key_installation(authority, node)?
        .ok_or("receipt missing")?;
    assert_eq!(
        collected["recorded_at_unix_micros"],
        receipt.recorded_at.get().to_string()
    );
    assert!(matches!(
        repo.load_consensus_state(2),
        Err(meshspan_metadata::ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    drop(repo);
    let retry = super::offline_backup::run_command(collection_command(root, directory)).await?;
    assert!(retry.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&retry.stdout)?,
        collected
    );
    Ok(())
}

fn collection_command(root: &ProcessFixture, directory: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(&root.daemon_binary);
    command
        .arg("collect-recovery-installation")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg("abababab-abab-8bab-abab-abababababab")
        .arg(directory.join("installation.json"));
    command
}

fn install_command(
    root: &ProcessFixture,
    directory: &Path,
    destination: &Path,
) -> std::process::Command {
    let mut command = std::process::Command::new(&root.daemon_binary);
    command
        .arg("install-recovery-keys")
        .arg(directory.join("keys.bundle"))
        .arg(directory.join("root.der"))
        .arg("abababab-abab-8bab-abab-abababababab")
        .arg(directory.join("identity.pk8"))
        .arg(directory.join("wrapping.x25519"))
        .arg(destination);
    command
}

async fn prepare_bundle(
    root: &ProcessFixture,
    backup: &Path,
    digest: &str,
    directory: &Path,
    identity: &LocalNodeIdentity,
    wrapping: &LocalWrappingKey,
) -> Result<u64, Box<dyn Error>> {
    let selection = serde_json::json!({
        "recovery_id": "aeaeaeae-aeae-8eae-aeae-aeaeaeaeaeae",
        "storage": super::recovery_content::source_selection(root)?,
        "nodes": [{
            "node_id": "abababab-abab-8bab-abab-abababababab",
            "host_id": "acacacac-acac-acac-acac-acacacacacac",
            "host_name": "Replacement host", "node_name": "Replacement node",
            "incarnation": "1", "roles": ["storage", "gateway", "metadata"],
            "identity_public_key": hex(identity.public_key_sec1())?,
            "wrapping_public_key": hex(&wrapping.public_key().as_bytes())?,
            "private_endpoint": "127.0.0.1:10000"
        }]
    });
    protected_write(
        &directory.join("selection.json"),
        &serde_json::to_vec(&selection)?,
    )?;
    let bad_digest = preparation_command(root, backup, &"00".repeat(32), directory);
    let rejected = super::offline_backup::run_command(bad_digest).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(!directory.join("coordinator").exists());
    super::recovery_resume::interrupt(root, backup, digest, directory).await?;
    let command = preparation_command(root, backup, digest, directory);
    let output = super::offline_backup::run_command(command).await?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["prepared"], true);
    assert_eq!(report["service_started"], false);
    assert_eq!(report["admission_ready"], false);
    assert_eq!(report["target_inventory_verified"], true);
    assert_eq!(
        report["target_inventory_sha256"]
            .as_str()
            .ok_or("inventory digest missing")?
            .len(),
        64
    );
    assert_eq!(report["recovery_id"], selection["recovery_id"]);
    assert_eq!(
        report["bundles"]
            .as_array()
            .ok_or("bundle list missing")?
            .len(),
        1
    );
    let saved = fs::read(directory.join("coordinator/prepared.json"))?;
    assert_eq!(
        fs::metadata(directory.join("coordinator/prepared.sqlite3"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&saved)?, report);
    assert!(
        !directory
            .join("coordinator/aeaeaeae-aeae-8eae-aeae-aeaeaeaeaeae")
            .exists()
    );
    let repeat =
        super::offline_backup::run_command(preparation_command(root, backup, digest, directory))
            .await?;
    assert!(
        repeat.status.success(),
        "{}",
        String::from_utf8_lossy(&repeat.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&repeat.stdout)?,
        report
    );
    assert_eq!(
        fs::read(directory.join("coordinator/prepared.json"))?,
        saved
    );
    super::recovery_resume::exports_and_conflicts(root, backup, digest, directory).await?;
    super::recovery_resume::retained_inventory(root, backup, digest, directory).await?;
    super::recovery_resume::workspace_input_is_not_cleanup_authority(
        root, backup, digest, directory,
    )
    .await?;
    Ok(report["retained_secret_generations"]
        .as_str()
        .ok_or("generation count missing")?
        .parse::<u64>()?
        + 2)
}

pub(super) fn preparation_command(
    root: &ProcessFixture,
    backup: &Path,
    digest: &str,
    directory: &Path,
) -> std::process::Command {
    let mut command = std::process::Command::new(&root.daemon_binary);
    command
        .arg("prepare-recovery")
        .arg(backup)
        .arg(digest)
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(directory.join("selection.json"))
        .arg(directory.join("coordinator"));
    command
}

pub(super) fn hex(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    use std::fmt::Write as _;
    let mut encoded = String::new();
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(encoded)
}

fn protected_write(destination: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(destination)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !value.is_ascii() || !value.len().is_multiple_of(2) {
        return Err("invalid hex".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}
