// SPDX-License-Identifier: GPL-2.0-only

//! Actual coordinator export and node installation without copying the private recovery root.

use super::{Error, ProcessFixture};
use meshspan_daemon::{LocalNodeIdentity, OperatingSystemClock};
use meshspan_domain::Clock as _;
use meshspan_metadata::{AuthoritativeRepository, ConsensusStoreError, PartitionDatabase};
use meshspan_recovery_bundle::{RecoveredAuthority, RecoveryStateTransfer};
use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

pub(super) async fn transfer(
    root: &ProcessFixture,
    directory: &Path,
    backup: &Path,
    authority: &RecoveredAuthority,
) -> Result<(), Box<dyn Error>> {
    let package = directory.join("state-package");
    let mut export = Command::new(&root.daemon_binary);
    export
        .arg("export-recovery-state")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(backup)
        .arg("abababab-abab-8bab-abab-abababababab")
        .arg(&package);
    let exported = super::offline_backup::run_command(export).await?;
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&exported.stdout)?;
    assert_eq!(report["exported"], true);
    assert_eq!(fs::read_dir(&package)?.count(), 3);
    assert!(!package.join("staging").exists());
    assert!(!fs::read(package.join("state.msb"))?.starts_with(b"SQLite format 3"));
    let destination = directory.join("installed-state");
    let installed =
        super::offline_backup::run_command(install(root, directory, &destination)).await?;
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&installed.stdout)?;
    assert_eq!(report["installed"], true);
    assert_eq!(report["admission_ready"], false);
    assert_eq!(report["service_started"], false);
    assert_eq!(
        report,
        serde_json::from_slice::<serde_json::Value>(&fs::read(
            destination.join("installed.json")
        )?)?
    );
    verify_installed(directory, &destination)?;
    let original = fs::read(destination.join("root-authority.sqlite3"))?;
    let rejected =
        super::offline_backup::run_command(install(root, directory, &destination)).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert_eq!(
        fs::read(destination.join("root-authority.sqlite3"))?,
        original
    );
    super::recovery_targets::prepare_and_collect(root, directory, authority, backup).await?;
    for name in ["state.msb", "keys.bundle", "state.auth"] {
        let original = fs::read(package.join(name))?;
        let mut damaged = original.clone();
        *damaged.last_mut().ok_or("empty export")? ^= 1;
        fs::write(package.join(name), damaged)?;
        let bad = directory.join(format!("rejected-{name}"));
        let rejected = super::offline_backup::run_command(install(root, directory, &bad)).await?;
        assert!(!rejected.status.success(), "accepted corrupt {name}");
        assert!(rejected.stdout.is_empty());
        assert!(!bad.join("installed.json").exists());
        assert!(!bad.join("root-authority.sqlite3").exists());
        fs::write(package.join(name), original)?;
    }
    Ok(())
}

pub(super) fn verify_installed(directory: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    let root = fs::read(directory.join("root.der"))?;
    let transfer =
        RecoveryStateTransfer::decode(&root, &fs::read(destination.join("state.auth"))?)?;
    let database = PartitionDatabase::open_existing(
        &destination.join("root-authority.sqlite3"),
        OperatingSystemClock.now(),
    )?;
    database.check_integrity()?;
    let repository = AuthoritativeRepository::new(database);
    assert_eq!(
        repository.verify_recovery_preparation(&root)?,
        transfer.claims().authorization
    );
    assert!(matches!(
        repository.load_consensus_state(2),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    for name in [
        "root-authority.sqlite3",
        "filesystem/filesystem-branch.sqlite3",
        "filesystem/filesystem-content.sqlite3",
        "keys.bundle",
        "installed.json",
    ] {
        assert_eq!(
            fs::metadata(destination.join(name))?.permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(!destination.join("filesystem-branch.sqlite3").exists());
    assert!(!destination.join("filesystem-content.sqlite3").exists());
    assert_eq!(
        fs::metadata(destination.join("filesystem"))?
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(destination)?.permissions().mode() & 0o777,
        0o700
    );
    let identity = LocalNodeIdentity::open(&directory.join("identity.pk8"), "replacement.invalid")?;
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(destination.join("installed.json"))?)?;
    let encoded = report["installation_signature"]
        .as_str()
        .ok_or("missing signature")?;
    let signature: Vec<u8> = encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok::<_, Box<dyn Error>>(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect::<Result<_, _>>()?;
    meshspan_certificates::NodePublicIdentity::from_sec1(identity.public_key_sec1())?
        .verify_enrolment_transcript(&transfer.installation_message()?, &signature)?;
    Ok(())
}

fn install(root: &ProcessFixture, directory: &Path, destination: &Path) -> Command {
    let mut command = Command::new(&root.daemon_binary);
    command
        .arg("install-recovery-state")
        .arg(directory.join("state-package"))
        .arg(directory.join("root.der"))
        .arg("abababab-abab-8bab-abab-abababababab")
        .arg(directory.join("identity.pk8"))
        .arg(directory.join("wrapping.x25519"))
        .arg(destination);
    command
}
