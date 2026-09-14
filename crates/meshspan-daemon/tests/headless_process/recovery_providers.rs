// SPDX-License-Identifier: GPL-2.0-only

//! Actual state-set delivery of restored provider identities; still no service admission.

use super::{Error, ProcessFixture, recovery_state_set::accepted};
use meshspan_contracts::ShardReceipt;
use meshspan_daemon::OperatingSystemClock;
use meshspan_domain::Clock as _;
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase, StorageUsageLimit};
use meshspan_storage::{FolderRegistration, MarkerFingerprint, RegisteredFolder, UsageLimit};
use std::{fs, path::Path, process::Command};

const NODE: &str = "abababab-abab-8bab-abab-abababababab";

pub(super) async fn transfer(
    root: &ProcessFixture,
    directory: &Path,
    backup: &Path,
    expected: ShardReceipt,
) -> Result<(), Box<dyn Error>> {
    let packages = directory.join("provider-state-set");
    let mut export = Command::new(&root.daemon_binary);
    export
        .arg("export-recovery-state-set")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(backup)
        .arg(&packages);
    let exported = accepted(export).await?;
    assert_eq!(exported["exported"], true);
    assert_eq!(exported["admission_ready"], false);
    assert!(!packages.join("staging").exists());
    let destination = directory.join("installed-provider-state");
    let mut install = Command::new(&root.daemon_binary);
    install
        .arg("install-recovery-state")
        .arg(packages.join(NODE))
        .arg(directory.join("root.der"))
        .arg(NODE)
        .arg(directory.join("identity.pk8"))
        .arg(directory.join("wrapping.x25519"))
        .arg(&destination)
        .arg("--storage-target")
        .arg(directory.join("target-work"))
        .arg(directory.join("replacement-storage"));
    assert_eq!(accepted(install).await?["installed"], true);
    super::recovery_state::verify_installed(directory, &destination)?;
    verify_provider(directory, &destination, expected)?;
    verify_original_journal(directory, &destination, expected)?;
    verify_runtime_material(directory, &destination)?;
    reject_unadmitted_startup(root, &destination, &directory.join("replacement-storage")).await?;
    reject_missing_journal(root, directory, &packages).await?;
    assert!(!root.storage_path.exists());
    Ok(())
}

fn verify_original_journal(
    directory: &Path,
    destination: &Path,
    expected: ShardReceipt,
) -> Result<(), Box<dyn Error>> {
    use meshspan_contracts::StoragePermitMacKey;
    use meshspan_storage::{CapacityPolicy, FolderShardStore, StoragePermitVerifier};
    use std::os::unix::ffi::OsStrExt as _;
    let local = meshspan_metadata::LocalDatabase::open_existing(
        &destination.join("local.sqlite3"),
        OperatingSystemClock.now(),
    )?;
    let records = local.local_recovered_targets()?;
    assert_eq!(records.len(), 1);
    assert!(local.local_targets()?.is_empty());
    let record = records.first().ok_or("missing recovered mount")?;
    let folder_path = fs::canonicalize(directory.join("replacement-storage"))?;
    let journal = fs::canonicalize(directory.join("target-work"))?;
    assert_eq!(record.canonical_path, folder_path.as_os_str().as_bytes());
    assert_eq!(record.journal_directory, journal.as_os_str().as_bytes());
    assert_eq!(record.target_id, expected.target_id);
    assert!(!destination.join("storage-targets").exists());
    let target = meshspan_metadata::PreparedRecoveryTarget::decode_report(
        &fs::read(directory.join("root.der"))?,
        &fs::read(journal.join("target.report"))?,
    )?
    .0;
    let claims = target.authorization.claims();
    let folder = RegisteredFolder::reopen(
        &folder_path,
        FolderRegistration {
            mesh_id: record.mesh_id,
            target_id: record.target_id,
            generation: record.generation,
            usage_limit: UsageLimit::Percent(95),
        },
        MarkerFingerprint::from_bytes(record.marker_fingerprint),
    )?;
    let mut provider = FolderShardStore::reopen(
        folder,
        &journal,
        CapacityPolicy {
            usage_limit: UsageLimit::Percent(95),
            repair_reserve_bytes: 0,
            revision: claims.source_revision,
        },
        StoragePermitVerifier::new(
            record.mesh_id,
            claims.recovery_epoch,
            claims.source_revision,
            StoragePermitMacKey::from_bytes([17; 32])?,
        )?,
        OperatingSystemClock.now(),
        &mut meshspan_daemon::OperatingSystemRandom,
    )?;
    let entry = provider
        .inventory_exact(expected.shard)?
        .ok_or("restored journal entry absent")?;
    assert_eq!(entry.shard, expected.shard);
    assert_eq!(entry.length, expected.length);
    assert_eq!(entry.digest, expected.digest);
    assert_eq!(
        provider
            .scrub_exact(entry, OperatingSystemClock.now())?
            .outcome,
        meshspan_contracts::ScrubOutcome::Healthy
    );
    local.check_integrity()?;
    Ok(())
}

async fn reject_missing_journal(
    root: &ProcessFixture,
    directory: &Path,
    packages: &Path,
) -> Result<(), Box<dyn Error>> {
    let journals = directory.join("target-work/storage-targets");
    let saved = directory.join("temporarily-unavailable-target-journals");
    fs::rename(&journals, &saved)?;
    let destination = directory.join("rejected-missing-target-journal");
    let mut install = Command::new(&root.daemon_binary);
    install
        .arg("install-recovery-state")
        .arg(packages.join(NODE))
        .arg(directory.join("root.der"))
        .arg(NODE)
        .arg(directory.join("identity.pk8"))
        .arg(directory.join("wrapping.x25519"))
        .arg(&destination)
        .arg("--storage-target")
        .arg(directory.join("target-work"))
        .arg(directory.join("replacement-storage"));
    let output = super::offline_backup::run_command(install).await?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!destination.join("installed.json").exists());
    assert!(!journals.exists());
    fs::rename(saved, journals)?;
    Ok(())
}

fn verify_provider(
    directory: &Path,
    destination: &Path,
    expected: ShardReceipt,
) -> Result<(), Box<dyn Error>> {
    let database = PartitionDatabase::open_existing(
        &destination.join("root-authority.sqlite3"),
        OperatingSystemClock.now(),
    )?;
    let repository = AuthoritativeRepository::new(database);
    let context = repository
        .storage_target_provider_context_by_target(expected.target_id)?
        .ok_or("restored provider absent")?;
    assert_eq!(context.generation, expected.target_generation);
    assert_eq!(context.policy_revision, context.catalogue_revision.next()?);
    let marker = repository
        .recovery_storage_target_marker(expected.target_id, expected.target_generation)?
        .ok_or("restored marker absent")?;
    let folder = RegisteredFolder::reopen(
        &directory.join("replacement-storage"),
        FolderRegistration {
            mesh_id: context.mesh_id,
            target_id: context.target_id,
            generation: context.generation,
            usage_limit: match context.usage_limit {
                StorageUsageLimit::Percent(value) => UsageLimit::percent(value)?,
                StorageUsageLimit::Bytes(value) => UsageLimit::bytes(value)?,
            },
        },
        MarkerFingerprint::from_bytes(marker),
    )?;
    assert_eq!(folder.marker().target_id(), expected.target_id);
    assert_eq!(folder.marker().fingerprint().as_bytes(), marker);
    drop(folder);
    repository.into_database().check_integrity()?;
    let coordinator = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &directory.join("coordinator/prepared.sqlite3"),
        OperatingSystemClock.now(),
    )?);
    assert!(
        coordinator
            .storage_target_provider_context_by_target(expected.target_id)?
            .is_none()
    );
    assert!(
        coordinator
            .recovery_storage_target_marker(expected.target_id, expected.target_generation)?
            .is_none()
    );
    let sql = rusqlite::Connection::open_with_flags(
        destination.join("root-authority.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (old_targets, origin): (i64, bool) = sql.query_row("SELECT
        (SELECT COUNT(*) FROM storage_targets WHERE target_id != ?1 AND (state != 5 OR retired_at IS NULL)),
        EXISTS(SELECT 1 FROM storage_targets t JOIN component_instances c ON c.instance_id = t.provider_instance_id
            JOIN partition_recovery_preparation p ON p.singleton = c.recovery_preparation
            WHERE t.target_id = ?1 AND c.created_by IS NULL)", [expected.target_id.as_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?;
    assert_eq!(old_targets, 0);
    assert!(origin);
    assert_eq!(
        fs::read(directory.join("replacement-storage/keep.txt"))?,
        b"ordinary sibling must stay untouched"
    );
    Ok(())
}

fn verify_runtime_material(directory: &Path, destination: &Path) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt as _;
    let files = [
        ("identity.pk8", "secrets/node-identity.pk8"),
        ("wrapping.x25519", "secrets/node-wrapping-key.x25519"),
        ("root.der", "recovery-root.der"),
    ];
    for (source, installed) in files {
        // A failed assertion must not print either private-key byte string.
        let same_protected_bytes =
            fs::read(directory.join(source))? == fs::read(destination.join(installed))?;
        assert!(
            same_protected_bytes,
            "installed identity differs from its source"
        );
        assert_eq!(
            fs::metadata(destination.join(installed))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    meshspan_daemon::LocalNodeIdentity::open(
        &destination.join("secrets/node-identity.pk8"),
        "replacement.invalid",
    )?;
    meshspan_daemon::LocalWrappingKey::open(&destination.join("secrets/node-wrapping-key.x25519"))?;
    for file in [
        "secrets/totp-ceremony.key",
        "secrets/passkey-ceremony.key",
        "local.sqlite3",
    ] {
        assert_eq!(
            fs::metadata(destination.join(file))?.permissions().mode() & 0o777,
            0o600
        );
    }
    let local = meshspan_metadata::LocalDatabase::open_existing(
        &destination.join("local.sqlite3"),
        OperatingSystemClock.now(),
    )?;
    assert!(local.active_local_claim()?.is_none());
    assert!(local.local_setup()?.is_none());
    assert!(!destination.join("first-boot.claim").exists());
    assert!(!destination.join("prepared.sqlite3").exists());
    Ok(())
}

async fn reject_unadmitted_startup(
    root: &ProcessFixture,
    destination: &Path,
    storage: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut start = Command::new(&root.daemon_binary);
    start
        .arg("--daemon-state-dir")
        .arg(destination)
        .arg("--storage-path")
        .arg(storage)
        .arg("--https-listen")
        .arg("127.0.0.1:0");
    let output = super::offline_backup::run_command(start).await?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr)?;
    if !error.contains("RecoveryAdmissionRequired") {
        return Err(format!("unexpected startup failure: {error}").into());
    }
    assert!(!destination.join("first-boot.claim").exists());
    Ok(())
}
