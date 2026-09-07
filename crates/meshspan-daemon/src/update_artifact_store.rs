// SPDX-License-Identifier: GPL-2.0-only

//! Owner-only executable cache. Byte transfer is separate from consensus and never proves installation.

use crate::protected_file::{self, ProtectedFileError, PublishMode};
use meshspan_metadata::{UpdateArtifact, UpdateManifest};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) const TRANSFER_FRAME_BYTES: usize = 64 * 1024;

/// File IO must be called from an owned blocking worker, never an async executor.
pub(crate) struct UpdateArtifactStore {
    directory: PathBuf,
}

impl UpdateArtifactStore {
    /// The caller owns the daemon-state lock and has already validated its directory.
    pub(crate) fn open(state_directory: &Path) -> Result<Self, ArtifactStoreError> {
        let directory = crate::daemon_local_state::ensure_private_directory(
            &state_directory.join("update-artifacts"),
        )
        .map_err(|_| ArtifactStoreError::Unsafe)?;
        Ok(Self { directory })
    }

    /// Stream exact signed bytes, verify before publishing, and fsync before acknowledging.
    /// Existing content is reverified; it is never overwritten merely because a path matches.
    pub(crate) fn stage(
        &self,
        manifest: &UpdateManifest,
        target: &str,
        input: &mut impl Read,
    ) -> Result<UpdateArtifact, ArtifactStoreError> {
        let artifact = manifest
            .artifact(target)
            .map_err(|_| ArtifactStoreError::Invalid)?;
        let destination = self.directory.join(&artifact.sha256);
        let result = protected_file::publish_checked(&destination, PublishMode::Create, |file| {
            transfer(input, file, &artifact).map_err(|error| match error {
                ArtifactStoreError::Io(error) => ProtectedFileError::Io(error),
                ArtifactStoreError::Unsafe | ArtifactStoreError::Invalid => {
                    ProtectedFileError::Invalid
                }
            })
        });
        match result {
            Ok(()) => Ok(artifact),
            Err(ProtectedFileError::Exists) => {
                self.open_verified(manifest, target)?;
                Ok(artifact)
            }
            Err(ProtectedFileError::Io(error)) => Err(ArtifactStoreError::Io(error)),
            Err(
                ProtectedFileError::Missing
                | ProtectedFileError::Unsafe
                | ProtectedFileError::Changed
                | ProtectedFileError::Invalid,
            ) => Err(ArtifactStoreError::Invalid),
        }
    }

    /// Return a freshly verified file handle, not an unchecked path. Callers still check trust.
    pub(crate) fn open_verified(
        &self,
        manifest: &UpdateManifest,
        target: &str,
    ) -> Result<File, ArtifactStoreError> {
        let artifact = manifest
            .artifact(target)
            .map_err(|_| ArtifactStoreError::Invalid)?;
        let path = self.directory.join(&artifact.sha256);
        let before = fs::symlink_metadata(&path)?;
        if !before.is_file()
            || before.permissions().mode() & 0o077 != 0
            || before.len() != artifact.size
        {
            return Err(ArtifactStoreError::Unsafe);
        }
        let mut file = File::open(path)?;
        let opened = file.metadata()?;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(ArtifactStoreError::Unsafe);
        }
        transfer(&mut file, &mut std::io::sink(), &artifact)?;
        std::io::Seek::rewind(&mut file)?;
        Ok(file)
    }
}

fn transfer(
    input: &mut impl Read,
    output: &mut impl Write,
    artifact: &UpdateArtifact,
) -> Result<(), ArtifactStoreError> {
    let mut buffer = vec![0; TRANSFER_FRAME_BYTES];
    let mut digest = Sha256::new();
    let mut length = 0_u64;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(count).map_err(|_| ArtifactStoreError::Invalid)?)
            .ok_or(ArtifactStoreError::Invalid)?;
        if length > artifact.size {
            return Err(ArtifactStoreError::Invalid);
        }
        digest.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    if length != artifact.size || hex(&digest.finalize()) != artifact.sha256 {
        return Err(ArtifactStoreError::Invalid);
    }
    Ok(())
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

#[derive(Debug, thiserror::Error)]
pub(crate) enum ArtifactStoreError {
    #[error("update artifact does not match its signed declaration")]
    Invalid,
    #[error("update artifact location is unsafe")]
    Unsafe,
    #[error("update artifact IO failed")]
    Io(#[from] std::io::Error),
}
