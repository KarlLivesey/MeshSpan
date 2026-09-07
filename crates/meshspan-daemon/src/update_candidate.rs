// SPDX-License-Identifier: GPL-2.0-only

//! Read-only candidate admission. No database, process replacement or publication occurs here.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::Path;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Closed failures for the read-only candidate verifier; no input or private paths are returned.
#[derive(Debug, Error)]
pub enum UpdateCandidateError {
    /// The command accepts exactly manifest, signature, trusted SEC1 key, executable and target.
    #[error("usage: verify-update MANIFEST SIGNATURE TRUSTED_SEC1_KEY EXECUTABLE TARGET")]
    Arguments,
    /// An input was not a readable bounded regular file.
    #[error("update candidate file could not be read within its bound")]
    Input,
    /// The independently pinned key did not authenticate this exact manifest.
    #[error("update candidate signature was not verified")]
    Signature,
    /// The manifest did not conform to the exact current format.
    #[error("invalid or non-canonical update manifest")]
    Manifest,
    /// The selected target was absent or its executable failed length/hash verification.
    #[error("update executable does not match the selected signed artifact")]
    Artifact,
    /// The local verification worker or its report failed.
    #[error("update verification worker or output failed")]
    Worker,
}

pub(crate) fn verify_command(arguments: &[std::ffi::OsString]) -> Result<(), UpdateCandidateError> {
    let [manifest, signature, trusted_key, executable, target] = arguments else {
        return Err(UpdateCandidateError::Arguments);
    };
    let target = target.to_str().ok_or(UpdateCandidateError::Arguments)?;
    let manifest = read_bounded(Path::new(manifest), 16 * 1_024)?;
    let signature = read_bounded(Path::new(signature), 72)?;
    let trusted_key = read_bounded(Path::new(trusted_key), 65)?;
    let parsed =
        meshspan_metadata::authenticate_update_manifest(&manifest, &signature, &trusted_key)
            .map_err(|error| match error {
                meshspan_metadata::UpdateManifestError::Signature => {
                    UpdateCandidateError::Signature
                }
                meshspan_metadata::UpdateManifestError::Manifest => UpdateCandidateError::Manifest,
                meshspan_metadata::UpdateManifestError::Artifact => UpdateCandidateError::Artifact,
            })?;
    let artifact = parsed
        .artifact(target)
        .map_err(|_| UpdateCandidateError::Artifact)?;
    verify_executable(Path::new(executable), &artifact)?;
    let report = serde_json::json!({
        "verified": true,
        "version": parsed.version().map_err(|_| UpdateCandidateError::Manifest)?,
        "source_commit": parsed.source_commit().map_err(|_| UpdateCandidateError::Manifest)?,
        "target": target,
        "sha256": artifact.sha256,
        "manifest_sha256": hex(&Sha256::digest(&manifest)),
        "scope": "signature and executable only; not compatibility, installation or release acceptance",
        "publication": "prohibited"
    });
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &report).map_err(|_| UpdateCandidateError::Worker)?;
    output
        .write_all(b"\n")
        .map_err(|_| UpdateCandidateError::Worker)
}

fn verify_executable(
    file_path: &Path,
    artifact: &meshspan_metadata::UpdateArtifact,
) -> Result<(), UpdateCandidateError> {
    let expected = artifact.size;
    let mut file = File::open(file_path).map_err(|_| UpdateCandidateError::Input)?;
    let metadata = file.metadata().map_err(|_| UpdateCandidateError::Input)?;
    if !metadata.is_file() || metadata.len() != expected {
        return Err(UpdateCandidateError::Artifact);
    }
    let mut hash = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = vec![0; 64 * 1_024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| UpdateCandidateError::Input)?;
        if count == 0 {
            break;
        }
        length += u64::try_from(count).map_err(|_| UpdateCandidateError::Artifact)?;
        if length > expected {
            return Err(UpdateCandidateError::Artifact);
        }
        hash.update(&buffer[..count]);
    }
    if length != expected || hex(&hash.finalize()) != artifact.sha256 {
        return Err(UpdateCandidateError::Artifact);
    }
    Ok(())
}

fn read_bounded(file_path: &Path, maximum: u64) -> Result<Vec<u8>, UpdateCandidateError> {
    let file = File::open(file_path).map_err(|_| UpdateCandidateError::Input)?;
    let metadata = file.metadata().map_err(|_| UpdateCandidateError::Input)?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(UpdateCandidateError::Input);
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| UpdateCandidateError::Input)?;
    if u64::try_from(bytes.len()).map_err(|_| UpdateCandidateError::Input)? > maximum {
        return Err(UpdateCandidateError::Input);
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}
