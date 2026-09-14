// SPDX-License-Identifier: GPL-2.0-only

//! Non-destructive offline verification using an independently saved export receipt and authority.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::Path;

use meshspan_backup::BackupFileEvidence;
use meshspan_domain::{Clock as _, OperationId, RandomSource as _, Revision, uuid_v8};
use meshspan_metadata::{
    AuthoritativeRepository, EncryptedPartitionBackupManifest, EncryptedRestorePaths, LogPosition,
    PartitionBackupManifest, restore_encrypted_partition_backup,
};
use meshspan_recovery_bundle::{RecoveredAuthority, RecoveryBundle, RecoveryBundleCode};
use meshspan_secret_envelope::WrappingPrivateKey;
use zeroize::Zeroizing;

use crate::backup_readiness_workspace::ReadinessWorkspace;

/// Offline checks never return paths, decrypted material or service-admission authority.
#[derive(Debug, thiserror::Error)]
pub enum OfflineBackupError {
    /// Invalid command shape; the code itself must never be supplied in the argument list.
    #[error(
        "usage: verify-backup BACKUP SHA256 RECOVERY_BUNDLE RECOVERY_CODE_FILE NEW_WORK_DIRECTORY"
    )]
    Arguments,
    /// The selected input could not be safely read or decoded.
    #[error("offline backup input is unreadable, malformed or exceeds its bound")]
    Input,
    /// The independent recovery material did not authenticate this backup's authority.
    #[error("offline recovery bundle, code or stored mesh authority did not match")]
    Authority,
    /// The container or isolated SQLite restore failed verification.
    #[error("backup digest, authenticated content or exact database state did not verify")]
    Verification,
    /// A retained secret cannot be recovered with the independently supplied bundle.
    #[error(
        "a retained secret generation has no valid offline recovery envelope or cannot be decrypted"
    )]
    Secrets,
    /// Workspaces must be new and are never reused as an active daemon state directory.
    #[error("offline verification requires a new, private work directory")]
    Workspace,
    /// Failure to remove disposable plaintext is not a successful verification.
    #[error(
        "offline verification workspace cleanup failed; plaintext may remain in the requested work directory"
    )]
    Cleanup,
    /// Worker failure or inability to write the final report.
    #[error("offline backup verification worker or report failed")]
    Worker,
}

pub(crate) fn verify_command(arguments: &[OsString]) -> Result<(), OfflineBackupError> {
    let [backup, digest, bundle, code, work] = arguments else {
        return Err(OfflineBackupError::Arguments);
    };
    let expected = parse_digest(digest)?;
    let bundle = read_bundle(Path::new(bundle))?;
    let code = crate::protected_file::read_bounded(Path::new(code), 1, 128)
        .map_err(|_| OfflineBackupError::Input)?;
    let code = RecoveryBundleCode::parse(
        std::str::from_utf8(&code)
            .map_err(|_| OfflineBackupError::Input)?
            .trim_end_matches(['\r', '\n']),
    )
    .map_err(|_| OfflineBackupError::Authority)?;
    let authority = bundle
        .open(&code)
        .map_err(|_| OfflineBackupError::Authority)?;
    let evidence = meshspan_backup::read_backup_evidence(Path::new(backup), expected)
        .map_err(|_| OfflineBackupError::Verification)?;
    if evidence.source.mesh_id != bundle.mesh_id() {
        return Err(OfflineBackupError::Authority);
    }
    let verified_secrets = verify_in_workspace(
        Path::new(backup),
        Path::new(work),
        evidence,
        &bundle,
        &authority,
    )?;
    let source = evidence.source;
    let report = serde_json::json!({
        "verified": true, "verification": "offline_recovery_bundle",
        "backup_id": crate::create_mesh_setup::format_uuid(source.backup_id.as_bytes()),
        "mesh_id": crate::create_mesh_setup::format_uuid(source.mesh_id.as_bytes()),
        "partition_id": crate::create_mesh_setup::format_uuid(source.partition_id.as_bytes()),
        "source_log_index": source.last_log_index.to_string(),
        "source_log_term": source.last_log_term.to_string(),
        "state_revision": source.state_revision.to_string(), "schema_version": source.schema_version,
        "restored_schema_version": meshspan_metadata::PartitionDatabase::supported_schema_version(),
        "sha256": crate::update_candidate::hex(&expected),
        "retained_secret_generations_verified": verified_secrets.to_string(),
        "scope": "Exact exported metadata backup only; not latest-state, file-shard or live-service recovery",
        "service_started": false,
    });
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &report).map_err(|_| OfflineBackupError::Worker)?;
    output
        .write_all(b"\n")
        .map_err(|_| OfflineBackupError::Worker)
}

fn verify_in_workspace(
    backup: &Path,
    work: &Path,
    evidence: BackupFileEvidence,
    bundle: &RecoveryBundle,
    authority: &RecoveredAuthority,
) -> Result<u64, OfflineBackupError> {
    let mut bytes = [0; 16];
    crate::OperatingSystemRandom
        .fill_bytes(&mut bytes)
        .map_err(|_| OfflineBackupError::Worker)?;
    let operation =
        OperationId::from_bytes(uuid_v8(bytes)).map_err(|_| OfflineBackupError::Worker)?;
    let work = std::env::current_dir()
        .map_err(|_| OfflineBackupError::Workspace)?
        .join(work);
    DirBuilder::new()
        .mode(0o700)
        .create(&work)
        .map_err(|_| OfflineBackupError::Workspace)?;
    let workspace =
        ReadinessWorkspace::create(&work, operation).map_err(|_| OfflineBackupError::Workspace)?;
    let checked = verify_database(backup, evidence, bundle, authority, &workspace);
    workspace
        .cleanup()
        .map_err(|_| OfflineBackupError::Cleanup)?;
    fs::remove_dir(work).map_err(|_| OfflineBackupError::Cleanup)?;
    checked
}

fn verify_database(
    backup: &Path,
    evidence: BackupFileEvidence,
    bundle: &RecoveryBundle,
    authority: &RecoveredAuthority,
    workspace: &ReadinessWorkspace,
) -> Result<u64, OfflineBackupError> {
    let restored = restore_encrypted_partition_backup(
        EncryptedRestorePaths {
            encrypted_source: backup,
            plaintext_staging: &workspace.file("plaintext.sqlite3"),
            restored_destination: &workspace.file("restored.sqlite3"),
        },
        partition_manifest(evidence),
        authority.wrapping_key(),
        crate::OperatingSystemClock.now(),
    )
    .map_err(|_| OfflineBackupError::Verification)?;
    let repository = AuthoritativeRepository::new(restored);
    let stored = repository
        .mesh_recovery_authority(bundle.mesh_id())
        .map_err(|_| OfflineBackupError::Verification)?
        .ok_or(OfflineBackupError::Authority)?;
    if stored.public_wrapping_key != authority.public_wrapping_key()
        || stored.root_certificate_der != authority.root_certificate_der()
        || stored.bundle_digest != bundle.digest()
    {
        return Err(OfflineBackupError::Authority);
    }
    verify_retained_secrets(&repository, authority.wrapping_key())
}

pub(crate) fn partition_manifest(evidence: BackupFileEvidence) -> EncryptedPartitionBackupManifest {
    let source = evidence.source;
    EncryptedPartitionBackupManifest {
        encrypted: evidence,
        partition: PartitionBackupManifest {
            backup_id: source.backup_id,
            partition_id: source.partition_id,
            mesh_id: source.mesh_id,
            applied_position: LogPosition {
                index: source.last_log_index,
                term: source.last_log_term,
            },
            state_revision: Revision::new(source.state_revision),
            schema_version: source.schema_version,
            byte_length: source.byte_length,
            digest: source.digest,
            created_at: source.created_at,
        },
    }
}

fn verify_retained_secrets(
    repository: &AuthoritativeRepository,
    key: &WrappingPrivateKey,
) -> Result<u64, OfflineBackupError> {
    let limit = meshspan_metadata::PageLimit::new(128).map_err(|_| OfflineBackupError::Worker)?;
    let mut after = None;
    let mut verified = 0_u64;
    loop {
        let page = repository
            .secret_generation_contexts(after, limit)
            .map_err(|_| OfflineBackupError::Secrets)?;
        for context in page.items {
            let record = repository
                .secret_generation(context)
                .map_err(|_| OfflineBackupError::Secrets)?
                .ok_or(OfflineBackupError::Secrets)?;
            verify_secret(&record, key)?;
            verified = verified.checked_add(1).ok_or(OfflineBackupError::Secrets)?;
        }
        match page.next {
            Some(next) => after = Some(next),
            None => return Ok(verified),
        }
    }
}

fn verify_secret(
    record: &meshspan_metadata::SecretGenerationRecord,
    key: &WrappingPrivateKey,
) -> Result<(), OfflineBackupError> {
    let mut selected = None;
    for recipient in &record.recipients {
        let public = recipient
            .recipient_public_key()
            .map_err(|_| OfflineBackupError::Secrets)?;
        if public != key.public_key() {
            continue;
        }
        if recipient.context() != record.secret.context() || selected.replace(recipient).is_some() {
            return Err(OfflineBackupError::Secrets);
        }
    }
    let recipient = selected.ok_or(OfflineBackupError::Secrets)?;
    let data_key = recipient
        .open(key)
        .map_err(|_| OfflineBackupError::Secrets)?;
    // Successful authenticated decryption is the evidence; plaintext is immediately zeroised.
    drop(
        record
            .secret
            .decrypt(&data_key)
            .map_err(|_| OfflineBackupError::Secrets)?,
    );
    Ok(())
}

pub(crate) fn read_bundle(source: &Path) -> Result<RecoveryBundle, OfflineBackupError> {
    if !fs::symlink_metadata(source)
        .map_err(|_| OfflineBackupError::Input)?
        .is_file()
    {
        return Err(OfflineBackupError::Input);
    }
    let maximum = crate::pending_recovery_bundle::MAXIMUM_RECOVERY_DOWNLOAD_BYTES;
    let mut bytes = Zeroizing::new(Vec::new());
    File::open(source)
        .map_err(|_| OfflineBackupError::Input)?
        .take(u64::try_from(maximum + 1).map_err(|_| OfflineBackupError::Input)?)
        .read_to_end(&mut bytes)
        .map_err(|_| OfflineBackupError::Input)?;
    if bytes.len() > maximum {
        return Err(OfflineBackupError::Input);
    }
    // Accept the binary container and the exact existing setup/panel download format.
    if let Ok(bundle) = RecoveryBundle::decode(&bytes) {
        return Ok(bundle);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| OfflineBackupError::Input)?;
    crate::pending_recovery_bundle::decode_download_text(text)
        .map_err(|_| OfflineBackupError::Input)
}

pub(crate) fn parse_digest(value: &OsString) -> Result<[u8; 32], OfflineBackupError> {
    let value = value.to_str().ok_or(OfflineBackupError::Arguments)?;
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OfflineBackupError::Arguments);
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| OfflineBackupError::Arguments)?;
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::{OfflineBackupError, verify_secret};
    use meshspan_domain::Revision;
    use meshspan_metadata::SecretGenerationRecord;
    use meshspan_secret_envelope::{SecretContext, WrappingPrivateKey, encrypt_secret};

    #[test]
    fn retained_secrets_require_the_exact_recovery_recipient_and_ciphertext()
    -> Result<(), Box<dyn std::error::Error>> {
        let recovery = WrappingPrivateKey::from_bytes([7; 32])?;
        let gateway = WrappingPrivateKey::from_bytes([8; 32])?;
        let context = SecretContext::new(1, [9; 16], 1)?;
        let (secret, recipients) = encrypt_secret(
            context,
            b"recover this historical key",
            &[recovery.public_key(), gateway.public_key()],
            &mut crate::OperatingSystemRandom,
        )?;
        let mut record = SecretGenerationRecord {
            secret,
            recipients,
            revision: Revision::new(1),
        };
        verify_secret(&record, &recovery)?;
        verify_secret(&record, &gateway)?;
        let wrong = WrappingPrivateKey::from_bytes([10; 32])?;
        assert!(matches!(
            verify_secret(&record, &wrong),
            Err(OfflineBackupError::Secrets)
        ));

        // Even another well-formed ciphertext for this same identity must fail with the old key.
        let (substituted, _) = encrypt_secret(
            context,
            b"not the same secret",
            &[recovery.public_key()],
            &mut crate::OperatingSystemRandom,
        )?;
        record.secret = substituted;
        assert!(matches!(
            verify_secret(&record, &recovery),
            Err(OfflineBackupError::Secrets)
        ));
        Ok(())
    }
}
