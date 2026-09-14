// SPDX-License-Identifier: GPL-2.0-only

//! Real coordinator commands issue exact consensus permission only after every installation.

use super::{Error, ProcessFixture};
use meshspan_recovery_bundle::{
    RecoveredAuthority, RecoveryConsensusAdmission, RecoveryStateTransfer,
};
use std::{fs, os::unix::fs::PermissionsExt as _, path::Path, process::Command};

pub(super) async fn reject_incomplete(
    root: &ProcessFixture,
    directory: &Path,
) -> Result<(), Box<dyn Error>> {
    let output = directory.join("consensus.permission");
    let result = super::offline_backup::run_command(command(root, directory, &output)).await?;
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!output.exists());
    Ok(())
}

pub(super) async fn issue(
    root: &ProcessFixture,
    directory: &Path,
    authority: &RecoveredAuthority,
    expected: &[RecoveryStateTransfer; 2],
    reservations: [std::net::UdpSocket; 2],
) -> Result<(), Box<dyn Error>> {
    let output = directory.join("consensus.permission");
    let failed_output = directory.join("absent-parent/permission");
    let failure =
        super::offline_backup::run_command(command(root, directory, &failed_output)).await?;
    assert!(!failure.status.success());
    assert!(failure.stdout.is_empty());
    assert!(!failed_output.exists());
    let report = super::recovery_state_set::accepted(command(root, directory, &output)).await?;
    assert_eq!(report["consensus_authorized"], true);
    assert_eq!(report["node_count"], 2);
    let bytes = fs::read(&output)?;
    let permission = RecoveryConsensusAdmission::decode(authority.root_certificate_der(), &bytes)?;
    assert_eq!(
        permission.claims().authorization,
        expected[0].claims().authorization
    );
    assert_eq!(
        permission.claims().state_digest,
        expected[0].claims().state_digest
    );
    assert_eq!(
        permission.claims().state_length,
        expected[0].claims().state_length
    );
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o600);
    super::recovery_state_set::accepted(command(root, directory, &output)).await?;
    assert_eq!(fs::read(&output)?, bytes);
    let second = directory.join("consensus-copy.permission");
    super::recovery_state_set::accepted(command(root, directory, &second)).await?;
    assert_eq!(fs::read(&second)?, bytes);
    fs::write(&second, b"do not overwrite")?;
    let rejected = super::offline_backup::run_command(command(root, directory, &second)).await?;
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert_eq!(fs::read(&second)?, b"do not overwrite");
    for label in ["gateway", "storage"] {
        // An offline permission cannot mutate any installed node or silently start services.
        let installed = directory.join(format!("installed-{label}"));
        assert!(installed.join("state.auth").exists());
        assert!(!installed.join("first-boot.claim").exists());
        assert!(!installed.join("consensus.permission").exists());
    }
    super::recovery_runtime::admit_and_start(root, directory, &output, reservations).await?;
    Ok(())
}

fn command(root: &ProcessFixture, directory: &Path, output: &Path) -> Command {
    let mut command = Command::new(&root.daemon_binary);
    command
        .arg("authorize-recovery-consensus")
        .arg(directory.join("coordinator/prepared.sqlite3"))
        .arg(&root.saved_recovery_bundle_path)
        .arg(&root.saved_recovery_code_path)
        .arg(directory.join("packages"))
        .arg(output);
    command
}
