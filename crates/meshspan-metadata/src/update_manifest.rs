// SPDX-License-Identifier: GPL-2.0-only

//! Shared bounded signed-manifest validation for CLI inspection and replicated update admission.

use serde_json::Value;
use std::collections::BTreeSet;
use thiserror::Error;

const MAXIMUM_BINARY_BYTES: u64 = 8 * 1_024 * 1_024 * 1_024;
const TARGETS: [&str; 4] = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-musl",
];

/// Failure at the signed update manifest boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum UpdateManifestError {
    /// The independently trusted key did not authenticate the exact bytes.
    #[error("update candidate signature was not verified")]
    Signature,
    /// The canonical manifest shape or one of its fields is invalid.
    #[error("invalid or non-canonical update manifest")]
    Manifest,
    /// No artifact matches the requested platform.
    #[error("update candidate does not include this platform")]
    Artifact,
}

/// An authenticated and structurally validated manifest, not installation authority.
#[derive(Clone, Debug, PartialEq)]
pub struct UpdateManifest {
    value: Value,
}

impl UpdateManifest {
    /// Signed platform entries in manifest order, bounded to four by admission.
    ///
    /// # Errors
    /// Rejects malformed internal representation.
    pub fn artifacts(&self) -> Result<Vec<(String, UpdateArtifact)>, UpdateManifestError> {
        self.value["artifacts"]
            .as_array()
            .ok_or(UpdateManifestError::Manifest)?
            .iter()
            .map(|value| {
                let target = text(value, "target")?;
                Ok((target.to_owned(), self.artifact(target)?))
            })
            .collect()
    }
    /// Authenticated candidate version.
    ///
    /// # Errors
    /// Rejects a malformed internal representation.
    pub fn version(&self) -> Result<&str, UpdateManifestError> {
        text(&self.value, "version")
    }
    /// Exact source commit recorded by the signer.
    ///
    /// # Errors
    /// Rejects a malformed internal representation.
    pub fn source_commit(&self) -> Result<&str, UpdateManifestError> {
        text(&self.value, "source_commit")
    }
    /// Selects the signed executable identity without consulting local files.
    ///
    /// # Errors
    /// Rejects an absent platform or malformed stored representation.
    pub fn artifact(&self, target: &str) -> Result<UpdateArtifact, UpdateManifestError> {
        let artifact = select_artifact(&self.value, target)?;
        Ok(UpdateArtifact {
            size: artifact_size(artifact)?,
            sha256: text(artifact, "sha256")?.to_owned(),
        })
    }
    /// Checks the signed partition-schema input range and private protocol major.
    /// Other database families and runtime capability probes remain separate obligations.
    #[must_use]
    pub fn accepts_partition(&self, schema: u32, protocol_major: u32) -> bool {
        let compatibility = &self.value["compatibility"];
        compatibility["partition_schema_min"]
            .as_u64()
            .is_some_and(|minimum| minimum <= u64::from(schema))
            && compatibility["partition_schema_max"]
                .as_u64()
                .is_some_and(|maximum| maximum >= u64::from(schema))
            && compatibility["private_protocol_major"].as_u64() == Some(u64::from(protocol_major))
    }
}

/// Exact immutable executable identity from an authenticated manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateArtifact {
    /// Expected bytes; capped at eight GiB.
    pub size: u64,
    /// Lowercase SHA-256, exactly 64 characters.
    pub sha256: String,
}

/// Authenticates an exact canonical manifest with an independently pinned key.
///
/// # Errors
/// Rejects signature failures, ambiguous JSON, unknown fields, unsupported targets or bounds.
pub fn authenticate_update_manifest(
    manifest: &[u8],
    signature: &[u8],
    trusted_key: &[u8],
) -> Result<UpdateManifest, UpdateManifestError> {
    meshspan_certificates::verify_update_signature(trusted_key, manifest, signature)
        .map_err(|_| UpdateManifestError::Signature)?;
    let value: Value =
        serde_json::from_slice(manifest).map_err(|_| UpdateManifestError::Manifest)?;
    // The canonical comparison also rejects duplicate fields, whitespace and alternative number
    // spellings. Only ASCII strings occur in this version, avoiding cross-runtime Unicode rules.
    if serde_json::to_vec(&value).map_err(|_| UpdateManifestError::Manifest)? != manifest {
        return Err(UpdateManifestError::Manifest);
    }
    validate_manifest(&value)?;
    Ok(UpdateManifest { value })
}

fn validate_manifest(value: &Value) -> Result<(), UpdateManifestError> {
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
        return Err(UpdateManifestError::Manifest);
    }
    validate_compatibility(&value["compatibility"])?;
    let artifacts = value["artifacts"]
        .as_array()
        .ok_or(UpdateManifestError::Manifest)?;
    if !(1..=4).contains(&artifacts.len()) {
        return Err(UpdateManifestError::Manifest);
    }
    let mut targets = BTreeSet::new();
    for artifact in artifacts {
        fields(artifact, &["target", "size", "sha256"])?;
        let target = text(artifact, "target")?;
        if !TARGETS.contains(&target)
            || !targets.insert(target)
            || !valid_hex(text(artifact, "sha256")?, 64)
        {
            return Err(UpdateManifestError::Manifest);
        }
        artifact_size(artifact)?;
    }
    Ok(())
}

fn validate_compatibility(value: &Value) -> Result<(), UpdateManifestError> {
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
    let integer = |key: &str| -> Result<u64, UpdateManifestError> {
        let number = value[key].as_u64().ok_or(UpdateManifestError::Manifest)?;
        if (1..=u64::from(u32::MAX)).contains(&number) {
            Ok(number)
        } else {
            Err(UpdateManifestError::Manifest)
        }
    };
    integer("private_protocol_major")?;
    let minimum = integer("partition_schema_min")?;
    let maximum = integer("partition_schema_max")?;
    let target = integer("partition_schema_target")?;
    if minimum > maximum || target < maximum || value["rollback_supported"].as_bool() != Some(false)
    {
        return Err(UpdateManifestError::Manifest);
    }
    Ok(())
}

fn fields(value: &Value, expected: &[&str]) -> Result<(), UpdateManifestError> {
    let object = value.as_object().ok_or(UpdateManifestError::Manifest)?;
    if object.len() != expected.len() || object.keys().any(|key| !expected.contains(&key.as_str()))
    {
        return Err(UpdateManifestError::Manifest);
    }
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, UpdateManifestError> {
    value[key].as_str().ok_or(UpdateManifestError::Manifest)
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

fn artifact_size(value: &Value) -> Result<u64, UpdateManifestError> {
    let encoded = text(value, "size")?;
    let size = encoded
        .parse::<u64>()
        .map_err(|_| UpdateManifestError::Manifest)?;
    if size == 0 || size > MAXIMUM_BINARY_BYTES || size.to_string() != encoded {
        return Err(UpdateManifestError::Manifest);
    }
    Ok(size)
}

fn select_artifact<'a>(
    manifest: &'a Value,
    target: &str,
) -> Result<&'a Value, UpdateManifestError> {
    manifest["artifacts"]
        .as_array()
        .ok_or(UpdateManifestError::Manifest)?
        .iter()
        .find(|artifact| artifact["target"].as_str() == Some(target))
        .ok_or(UpdateManifestError::Artifact)
}
