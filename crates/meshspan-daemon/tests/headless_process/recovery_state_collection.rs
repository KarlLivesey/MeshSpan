// SPDX-License-Identifier: GPL-2.0-only

//! A key-only or old-state acknowledgement never satisfies an explicitly newer package set.

use super::{Error, ProcessFixture, recovery_restoration::hex};
use meshspan_daemon::OperatingSystemClock;
use meshspan_domain::Clock as _;
use meshspan_metadata::{AuthoritativeRepository, ConsensusStoreError, PartitionDatabase};
use meshspan_recovery_bundle::{RecoveredAuthority, RecoveryStateTransfer};
use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

pub(super) async fn collect(
    root: &ProcessFixture,
    directory: &Path,
    authority: &RecoveredAuthority,
) -> Result<(), Box<dyn Error>> {
    let old = transfer(directory, authority, "state-package")?;
    let current = transfer(directory, authority, "route-state-package")?;
    assert_ne!(old.claims().state_digest, current.claims().state_digest);
    let repository = open(directory)?;
    assert!(
        repository
            .require_recovery_state_installations(authority, std::slice::from_ref(&old))
            .is_err()
    );
    assert!(
        repository
            .require_recovery_state_installations(authority, &[])
            .is_err()
    );
    drop(repository);
    let first = accepted(
        root,
        directory,
        "state-package",
        "installed-state/installed.json",
    )
    .await?;
    assert_eq!(
        accepted(
            root,
            directory,
            "state-package",
            "installed-state/installed.json"
        )
        .await?,
        first
    );
    let repository = open(directory)?;
    repository.require_recovery_state_installations(authority, std::slice::from_ref(&old))?;
    assert!(
        repository
            .require_recovery_state_installations(authority, std::slice::from_ref(&current))
            .is_err()
    );
    assert!(
        repository
            .require_recovery_state_installations(authority, &[old.clone(), old.clone()])
            .is_err()
    );
    drop(repository);
    rejects_substitution(root, directory, &current).await?;
    rejects_failed_insert(root, directory, authority, &current).await?;
    let saved = accepted(
        root,
        directory,
        "route-state-package",
        "installed-route-state/installed.json",
    )
    .await?;
    assert_eq!(saved["state_sha256"], hex(&current.claims().state_digest)?);
    assert_eq!(
        accepted(
            root,
            directory,
            "route-state-package",
            "installed-route-state/installed.json"
        )
        .await?,
        saved
    );
    let repository = open(directory)?;
    repository.require_recovery_state_installations(authority, std::slice::from_ref(&current))?;
    repository.require_recovery_state_installations(authority, std::slice::from_ref(&old))?;
    assert!(matches!(
        repository.load_consensus_state(2),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    assert_eq!(
        repository.current_revision()?,
        current.claims().authorization.claims().source_revision
    );
    Ok(())
}

async fn rejects_substitution(
    root: &ProcessFixture,
    directory: &Path,
    current: &RecoveryStateTransfer,
) -> Result<(), Box<dyn Error>> {
    let rejected = super::offline_backup::run_command(command(
        root,
        directory,
        "route-state-package",
        "installed-state/installed.json",
    ))
    .await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let mut report: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("installed-state/installed.json"))?)?;
    report["state_sha256"] = hex(&current.claims().state_digest)?.into();
    report["installation_message"] = hex(&current.installation_message()?)?.into();
    // Correct displayed fields still carry the old package's valid node signature.
    let file = directory.join("substituted-state-report.json");
    fs::write(&file, serde_json::to_vec(&report)?)?;
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
    let rejected = super::offline_backup::run_command(command(
        root,
        directory,
        "route-state-package",
        "substituted-state-report.json",
    ))
    .await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    Ok(())
}

async fn rejects_failed_insert(
    root: &ProcessFixture,
    directory: &Path,
    authority: &RecoveredAuthority,
    current: &RecoveryStateTransfer,
) -> Result<(), Box<dyn Error>> {
    let sql = rusqlite::Connection::open(directory.join("coordinator/prepared.sqlite3"))?;
    sql.execute_batch("CREATE TRIGGER injected_state_receipt BEFORE INSERT ON partition_recovery_state_installations BEGIN SELECT RAISE(ABORT, 'injected'); END;")?;
    let result = super::offline_backup::run_command(command(
        root,
        directory,
        "route-state-package",
        "installed-route-state/installed.json",
    ))
    .await;
    sql.execute_batch("DROP TRIGGER injected_state_receipt;")?;
    let rejected = result?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert!(
        open(directory)?
            .require_recovery_state_installations(authority, std::slice::from_ref(current))
            .is_err()
    );
    assert_eq!(
        sql.query_row(
            "SELECT COUNT(*) FROM partition_recovery_state_installations",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    Ok(())
}

async fn accepted(
    root: &ProcessFixture,
    directory: &Path,
    package: &str,
    report: &str,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let output =
        super::offline_backup::run_command(command(root, directory, package, report)).await?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result["recorded"], true);
    assert_eq!(result["service_started"], false);
    assert_eq!(result["admission_ready"], false);
    Ok(result)
}

fn transfer(
    directory: &Path,
    authority: &RecoveredAuthority,
    package: &str,
) -> Result<RecoveryStateTransfer, Box<dyn Error>> {
    Ok(RecoveryStateTransfer::decode(
        authority.root_certificate_der(),
        &fs::read(directory.join(package).join("state.auth"))?,
    )?)
}

fn open(directory: &Path) -> Result<AuthoritativeRepository, Box<dyn Error>> {
    let database = PartitionDatabase::open_existing(
        &directory.join("coordinator/prepared.sqlite3"),
        OperatingSystemClock.now(),
    )?;
    database.check_integrity()?;
    Ok(AuthoritativeRepository::new(database))
}

fn command(root: &ProcessFixture, directory: &Path, package: &str, report: &str) -> Command {
    let mut command = Command::new(&root.daemon_binary);
    command
        .arg("collect-recovery-state")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(directory.join(package).join("state.auth"))
        .arg(directory.join(report));
    command
}
