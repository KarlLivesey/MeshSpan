// SPDX-License-Identifier: GPL-2.0-only

//! Node-local, durable encrypted recovery-key installation without the offline private root.

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use meshspan_domain::NodeId;
use meshspan_metadata::{
    RecoveryKeyBundleVerification, RecoveryKeyRecipient, verify_recovery_key_bundle,
};

use crate::protected_file::{self, ProtectedFileError, PublishMode};
use crate::{LocalNodeIdentity, LocalWrappingKey};

pub(crate) fn install_command(arguments: &[OsString]) -> Result<(), RecoveryKeyInstallationError> {
    let [bundle, root, node_id, identity, wrapping, destination] = arguments else {
        return Err(RecoveryKeyInstallationError::Arguments);
    };
    let root = protected_file::read_bounded(Path::new(root), 1, 8192)
        .map_err(|_| RecoveryKeyInstallationError::Input)?;
    let node_id = node_id
        .to_str()
        .and_then(|value| crate::create_mesh_setup::parse_uuid(value).ok())
        .and_then(|bytes| NodeId::from_bytes(bytes).ok())
        .ok_or(RecoveryKeyInstallationError::Arguments)?;
    let identity = LocalNodeIdentity::open(Path::new(identity), "meshspan-recovery.invalid")
        .map_err(|_| RecoveryKeyInstallationError::Input)?;
    let wrapping = LocalWrappingKey::open(Path::new(wrapping))
        .map_err(|_| RecoveryKeyInstallationError::Input)?;
    let recipient = RecoveryKeyRecipient {
        node_id,
        identity_public_key: identity
            .public_key_sec1()
            .try_into()
            .map_err(|_| RecoveryKeyInstallationError::Input)?,
        wrapping_public_key: wrapping.public_key(),
    };
    let verification = install_bundle(
        Path::new(bundle),
        Path::new(destination),
        &root,
        recipient,
        &wrapping,
    )?;
    // Publication has completed and fsynced before any installation attestation is signed.
    let message = verification.installation_message();
    let signature = identity
        .sign_enrolment_transcript(&message)
        .map_err(|_| RecoveryKeyInstallationError::Worker)?;
    let report = installation_report(&verification, &signature);
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &report)
        .map_err(|_| RecoveryKeyInstallationError::Worker)?;
    output
        .write_all(b"\n")
        .map_err(|_| RecoveryKeyInstallationError::Worker)
}

fn installation_report(
    verified: &RecoveryKeyBundleVerification,
    signature: &[u8],
) -> meshspan_api_contract::RecoveryInstallationReport {
    meshspan_api_contract::RecoveryInstallationReport {
        installed: true,
        service_started: false,
        scope: "Encrypted recovery keys and node certificate; not metadata, target readiness or service admission".into(),
        node_certificate_generation: verified.node_certificate().generation().to_string(),
        node_certificate_not_after_unix_seconds: verified.node_certificate().not_after().to_string(),
        sha256: crate::update_candidate::hex(&verified.bundle_digest()),
        verified_secret_generations: verified.verified_generations().to_string(),
        installation_message: crate::update_candidate::hex(&verified.installation_message()),
        installation_signature: crate::update_candidate::hex(signature),
    }
}

fn install_bundle(
    source: &Path,
    destination: &Path,
    root: &[u8],
    recipient: RecoveryKeyRecipient,
    wrapping: &LocalWrappingKey,
) -> Result<RecoveryKeyBundleVerification, RecoveryKeyInstallationError> {
    match protected_file::open_read(destination) {
        Ok(mut installed) => {
            let saved =
                verify_recovery_key_bundle(&mut installed, root, recipient, |secret, envelope| {
                    wrapping.decrypt_secret(secret, envelope)
                })
                .map_err(|_| RecoveryKeyInstallationError::Verification)?;
            let mut input = protected_file::open_read(source)
                .map_err(|_| RecoveryKeyInstallationError::Input)?;
            let requested =
                verify_recovery_key_bundle(&mut input, root, recipient, |secret, envelope| {
                    wrapping.decrypt_secret(secret, envelope)
                })
                .map_err(|_| RecoveryKeyInstallationError::Verification)?;
            if saved.bundle_digest() != requested.bundle_digest() {
                return Err(RecoveryKeyInstallationError::Conflict);
            }
            installed
                .sync_all()
                .map_err(|_| RecoveryKeyInstallationError::Publication)?;
            protected_file::sync_parent(destination)
                .map_err(|_| RecoveryKeyInstallationError::Publication)?;
            Ok(saved)
        }
        Err(ProtectedFileError::Missing) => {
            install_new_bundle(source, destination, root, recipient, wrapping)
        }
        Err(_) => Err(RecoveryKeyInstallationError::Publication),
    }
}

fn install_new_bundle(
    source: &Path,
    destination: &Path,
    root: &[u8],
    recipient: RecoveryKeyRecipient,
    wrapping: &LocalWrappingKey,
) -> Result<RecoveryKeyBundleVerification, RecoveryKeyInstallationError> {
    let mut input =
        protected_file::open_read(source).map_err(|_| RecoveryKeyInstallationError::Input)?;
    let mut verification = None;
    protected_file::publish_checked(destination, PublishMode::Create, |output| {
        let mut copied = CopyingReader {
            input: &mut input,
            output,
        };
        verification = Some(
            verify_recovery_key_bundle(&mut copied, root, recipient, |secret, envelope| {
                wrapping.decrypt_secret(secret, envelope)
            })
            .map_err(|_| ProtectedFileError::Invalid)?,
        );
        Ok(())
    })
    .map_err(|error| match error {
        ProtectedFileError::Invalid => RecoveryKeyInstallationError::Verification,
        ProtectedFileError::Exists => RecoveryKeyInstallationError::Conflict,
        _ => RecoveryKeyInstallationError::Publication,
    })?;
    verification.ok_or(RecoveryKeyInstallationError::Verification)
}

struct CopyingReader<'a> {
    input: &'a mut File,
    output: &'a mut File,
}
impl Read for CopyingReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let read = self.input.read(bytes)?;
        self.output.write_all(&bytes[..read])?;
        Ok(read)
    }
}

/// Closed, redacted node-side installation failure.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryKeyInstallationError {
    /// No secret is accepted in the process argument list.
    #[error(
        "usage: install-recovery-keys BUNDLE ROOT_CERTIFICATE NODE_UUID IDENTITY_KEY_FILE WRAPPING_KEY_FILE NEW_DESTINATION"
    )]
    Arguments,
    /// Existing protected local identity/root inputs are missing or unsafe.
    #[error("recovery installation input is missing, malformed or unsafe")]
    Input,
    /// Signatures, selected keys, ciphertext or complete inventory did not verify.
    #[error("recovery key installation verification failed")]
    Verification,
    /// Never overwrite a different or concurrently published installation.
    #[error("recovery key installation conflicts with the existing destination")]
    Conflict,
    /// Atomic file publication or its durability acknowledgement failed.
    #[error("recovery key installation publication failed")]
    Publication,
    /// Worker, signing or report output failed; safe replay remains available.
    #[error("recovery key installation worker or report failed")]
    Worker,
}
