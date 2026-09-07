// SPDX-License-Identifier: GPL-2.0-only

//! Read-only candidate admission. No database, process replacement or publication occurs here.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::Path;

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAXIMUM_BINARY_BYTES: u64 = 8 * 1_024 * 1_024 * 1_024;
const TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-musl",
];

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
    let parsed = authenticate(&manifest, &signature, &trusted_key)?;
    let artifact = select_artifact(&parsed, target)?;
    verify_executable(Path::new(executable), artifact)?;
    let report = serde_json::json!({
        "verified": true,
        "version": parsed["version"],
        "source_commit": parsed["source_commit"],
        "target": target,
        "sha256": artifact["sha256"],
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

pub(crate) fn authenticate(
    manifest: &[u8],
    signature: &[u8],
    trusted_key: &[u8],
) -> Result<Value, UpdateCandidateError> {
    meshspan_certificates::verify_update_signature(trusted_key, manifest, signature)
        .map_err(|_| UpdateCandidateError::Signature)?;
    let value: Value =
        serde_json::from_slice(manifest).map_err(|_| UpdateCandidateError::Manifest)?;
    // The canonical comparison also rejects duplicate fields, whitespace and alternative number
    // spellings. Only ASCII strings occur in this version, avoiding cross-runtime Unicode rules.
    if serde_json::to_vec(&value).map_err(|_| UpdateCandidateError::Manifest)? != manifest {
        return Err(UpdateCandidateError::Manifest);
    }
    validate_manifest(&value)?;
    Ok(value)
}

fn validate_manifest(value: &Value) -> Result<(), UpdateCandidateError> {
    fields(
        value,
        &[
            "format",
            "version",
            "licence",
            "source_commit",
            "api_sha256",
            "artifacts",
            "compatibility",
        ],
    )?;
    if value["format"].as_u64() != Some(1)
        || value["licence"].as_str() != Some("GPL-2.0-only")
        || !valid_version(text(value, "version")?)
        || !valid_hex(text(value, "source_commit")?, 40)
        || !valid_hex(text(value, "api_sha256")?, 64)
    {
        return Err(UpdateCandidateError::Manifest);
    }
    validate_compatibility(&value["compatibility"])?;
    let artifacts = value["artifacts"]
        .as_array()
        .ok_or(UpdateCandidateError::Manifest)?;
    if !(1..=4).contains(&artifacts.len()) {
        return Err(UpdateCandidateError::Manifest);
    }
    let mut targets = BTreeSet::new();
    for artifact in artifacts {
        fields(artifact, &["target", "size", "sha256"])?;
        let target = text(artifact, "target")?;
        if !TARGETS.contains(&target)
            || !targets.insert(target)
            || !valid_hex(text(artifact, "sha256")?, 64)
        {
            return Err(UpdateCandidateError::Manifest);
        }
        artifact_size(artifact)?;
    }
    Ok(())
}

fn validate_compatibility(value: &Value) -> Result<(), UpdateCandidateError> {
    fields(
        value,
        &[
            "private_protocol_major",
            "partition_schema_min",
            "partition_schema_max",
            "partition_schema_target",
            "rollback_supported",
        ],
    )?;
    let integer = |key: &str| -> Result<u64, UpdateCandidateError> {
        let number = value[key].as_u64().ok_or(UpdateCandidateError::Manifest)?;
        if (1..=u64::from(u32::MAX)).contains(&number) {
            Ok(number)
        } else {
            Err(UpdateCandidateError::Manifest)
        }
    };
    integer("private_protocol_major")?;
    let minimum = integer("partition_schema_min")?;
    let maximum = integer("partition_schema_max")?;
    let target = integer("partition_schema_target")?;
    if minimum > maximum || target < maximum || value["rollback_supported"].as_bool() != Some(false)
    {
        return Err(UpdateCandidateError::Manifest);
    }
    Ok(())
}

fn fields(value: &Value, expected: &[&str]) -> Result<(), UpdateCandidateError> {
    let object = value.as_object().ok_or(UpdateCandidateError::Manifest)?;
    if object.len() != expected.len() || object.keys().any(|key| !expected.contains(&key.as_str()))
    {
        return Err(UpdateCandidateError::Manifest);
    }
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, UpdateCandidateError> {
    value[key].as_str().ok_or(UpdateCandidateError::Manifest)
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_version(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            (1..=9).contains(&part.len())
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))
        })
}

fn artifact_size(value: &Value) -> Result<u64, UpdateCandidateError> {
    let encoded = text(value, "size")?;
    let size = encoded
        .parse::<u64>()
        .map_err(|_| UpdateCandidateError::Manifest)?;
    if size == 0 || size > MAXIMUM_BINARY_BYTES || size.to_string() != encoded {
        return Err(UpdateCandidateError::Manifest);
    }
    Ok(size)
}

fn select_artifact<'a>(
    manifest: &'a Value,
    target: &str,
) -> Result<&'a Value, UpdateCandidateError> {
    manifest["artifacts"]
        .as_array()
        .ok_or(UpdateCandidateError::Manifest)?
        .iter()
        .find(|artifact| artifact["target"].as_str() == Some(target))
        .ok_or(UpdateCandidateError::Artifact)
}

fn verify_executable(file_path: &Path, artifact: &Value) -> Result<(), UpdateCandidateError> {
    let expected = artifact_size(artifact)?;
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
    if length != expected || hex(&hash.finalize()) != text(artifact, "sha256")? {
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
