// SPDX-License-Identifier: GPL-2.0-only

//! Node-side installation. No private offline authority and no running-state overwrite.

use super::{AUTHORIZATION, CONTENT, Error, KEYS, METADATA, NAMESPACE, STATE};
use crate::protected_file::{self, PublishMode};
use meshspan_domain::Clock as _;
use meshspan_metadata::{RecoveryKeyRecipient, verify_recovery_key_bundle};
use meshspan_recovery_bundle::RecoveryStateTransfer;
use std::{ffi::OsString, io, path::Path};

pub(in super::super) fn install_command(arguments: &[OsString]) -> Result<(), Error> {
    super::print_report(&install(arguments, InstallationKind::Daemon)?)
}

pub(in super::super) fn install_into(arguments: &[OsString]) -> Result<serde_json::Value, Error> {
    install(arguments, InstallationKind::RecoveryWorkspace)
}

#[derive(Clone, Copy)]
enum InstallationKind {
    RecoveryWorkspace,
    Daemon,
}

impl InstallationKind {
    const fn metadata_file(self) -> &'static str {
        match self {
            Self::RecoveryWorkspace => METADATA,
            Self::Daemon => crate::daemon_local_state::ROOT_AUTHORITY_DATABASE,
        }
    }

    fn history_directory(self, work: &Path) -> std::path::PathBuf {
        match self {
            Self::RecoveryWorkspace => work.to_path_buf(),
            Self::Daemon => work.join("filesystem"),
        }
    }

    fn sync_databases(self, work: &Path) -> Result<(), Error> {
        let history = self.history_directory(work);
        for file in [
            work.join(self.metadata_file()),
            history.join(NAMESPACE),
            history.join(CONTENT),
        ] {
            super::sync_private(&file)?;
        }
        Ok(())
    }
}

fn install(arguments: &[OsString], kind: InstallationKind) -> Result<serde_json::Value, Error> {
    let [package, root, node, identity, wrapping, work, targets @ ..] = arguments else {
        return Err(Error::StateInstallArguments);
    };
    super::local_targets::validate_arguments(targets)?;
    let root_file = Path::new(root);
    let root = protected_file::read_bounded(Path::new(root), 1, 8192).map_err(|_| Error::Input)?;
    let encoded = protected_file::read_bounded(&Path::new(package).join(AUTHORIZATION), 1, 512)
        .map_err(|_| Error::Input)?;
    let transfer = RecoveryStateTransfer::decode(&root, &encoded).map_err(|_| Error::Authority)?;
    let recipient = transfer.claims();
    if recipient.node_id != super::node_id(node)? {
        return Err(Error::Authority);
    }
    let identity = crate::LocalNodeIdentity::open(Path::new(identity), "meshspan-recovery.invalid")
        .map_err(|_| Error::Input)?;
    let wrapping = crate::LocalWrappingKey::open(Path::new(wrapping)).map_err(|_| Error::Input)?;
    let work = Path::new(work);
    super::private_directory(work)?;
    // The earliest durable file fences even an interrupted installation from first-boot setup.
    protected_file::publish(&work.join(AUTHORIZATION), &encoded, PublishMode::Create)
        .map_err(|_| Error::Workspace)?;
    copy_exact(
        &Path::new(package).join(KEYS),
        &work.join(KEYS),
        (recipient.key_bundle_digest, recipient.key_bundle_length),
    )?;
    let mut bundle = protected_file::open_read(&work.join(KEYS)).map_err(|_| Error::Input)?;
    let verification = verify_recovery_key_bundle(
        &mut bundle,
        &root,
        RecoveryKeyRecipient {
            node_id: recipient.node_id,
            identity_public_key: identity
                .public_key_sec1()
                .try_into()
                .map_err(|_| Error::Input)?,
            wrapping_public_key: wrapping.public_key(),
        },
        |secret, envelope| wrapping.decrypt_secret(secret, envelope),
    )
    .map_err(|_| Error::Authority)?;
    if !verification.matches_state_transfer(&transfer) {
        return Err(Error::Authority);
    }
    copy_exact(
        &Path::new(package).join(STATE),
        &work.join(STATE),
        (recipient.state_digest, recipient.state_length),
    )?;
    let repository = restore_candidate(work, &transfer, &wrapping, &root, kind)?;
    super::local_targets::install(
        &super::local_targets::Installation {
            repository: &repository,
            transfer: &transfer,
            identity: &identity,
            root_certificate: root_file,
            destination: work,
        },
        targets,
    )?;
    drop(repository);
    if matches!(kind, InstallationKind::Daemon) {
        crate::DaemonLocalState::install_recovery_material(
            work,
            recipient.node_id,
            &identity,
            &wrapping,
            crate::OperatingSystemClock.now(),
        )
        .map_err(|_| Error::Material)?;
        super::sync_private(&work.join("local.sqlite3"))?;
        protected_file::publish(&work.join("recovery-root.der"), &root, PublishMode::Create)
            .map_err(|_| Error::Workspace)?;
    }
    kind.sync_databases(work)?;
    // Only verified, fsynced state can receive a node-signed installation acknowledgement.
    let message = transfer
        .installation_message()
        .map_err(|_| Error::Material)?;
    let signature = identity
        .sign_enrolment_transcript(&message)
        .map_err(|_| Error::Worker)?;
    let report = serde_json::json!({
        "installed": true, "admission_ready": false, "service_started": false,
        "node_id": crate::create_mesh_setup::format_uuid(recipient.node_id.as_bytes()),
        "state_sha256": crate::update_candidate::hex(&recipient.state_digest),
        "installation_message": crate::update_candidate::hex(&message),
        "installation_signature": crate::update_candidate::hex(&signature),
        "scope": "Verified private metadata/history and encrypted node keys; not restored protection or service admission"
    });
    protected_file::publish(
        &work.join("installed.json"),
        &serde_json::to_vec(&report).map_err(|_| Error::Worker)?,
        PublishMode::Create,
    )
    .map_err(|_| Error::Workspace)?;
    Ok(report)
}

/// Decrypt and verify the database set as one candidate before attaching any node-local mounts.
fn restore_candidate(
    work: &Path,
    transfer: &RecoveryStateTransfer,
    wrapping: &crate::LocalWrappingKey,
    root: &[u8],
    kind: InstallationKind,
) -> Result<meshspan_metadata::AuthoritativeRepository, Error> {
    let metadata_file = kind.metadata_file();
    let history = kind.history_directory(work);
    if matches!(kind, InstallationKind::Daemon) {
        super::private_directory(&history)?;
    }
    let recipient = transfer.claims();
    let evidence = meshspan_backup::read_backup_evidence(&work.join(STATE), recipient.state_digest)
        .map_err(|_| Error::Material)?;
    wrapping
        .restore_backup_files(
            &work.join(STATE),
            meshspan_backup::BackupFiles {
                metadata: &work.join(metadata_file),
                history: Some(meshspan_backup::BackupHistoryFiles {
                    namespace: &history.join(NAMESPACE),
                    content: &history.join(CONTENT),
                }),
            },
            evidence,
        )
        .map_err(|_| Error::Material)?
        .ok_or(Error::History)?;
    kind.sync_databases(work)?;
    let repository = super::open_repository(&work.join(metadata_file))?;
    if repository.verify_recovery_preparation(root)? != recipient.authorization {
        return Err(Error::Authority);
    }
    super::check_history(&repository, &history)?;
    Ok(repository)
}

fn copy_exact(source: &Path, destination: &Path, expected: ([u8; 32], u64)) -> Result<(), Error> {
    use std::io::Read as _;
    let mut input = protected_file::open_read(source).map_err(|_| Error::Input)?;
    if input.metadata().map_err(|_| Error::Input)?.len() != expected.1 {
        return Err(Error::Material);
    }
    protected_file::publish_checked(destination, PublishMode::Create, |output| {
        let copied = io::copy(&mut (&mut input).take(expected.1.saturating_add(1)), output)
            .map_err(|_| protected_file::ProtectedFileError::Invalid)?;
        if copied != expected.1 {
            return Err(protected_file::ProtectedFileError::Invalid);
        }
        Ok(())
    })
    .map_err(|_| Error::Workspace)?;
    if super::file_digest(destination)? != expected {
        return Err(Error::Material);
    }
    Ok(())
}
