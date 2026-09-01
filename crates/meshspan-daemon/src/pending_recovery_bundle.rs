// SPDX-License-Identifier: GPL-2.0-only

//! Protected restart-stable delivery file for first-mesh offline authority.

use std::path::Path;

use meshspan_domain::{MeshId, RandomSource};
use meshspan_recovery_bundle::{
    MAXIMUM_RECOVERY_BUNDLE_BYTES, OfflineRecoveryIdentity, RecoveryBundle, RecoveryBundleCode,
    RecoveryBundleError, create_recovery_bundle_with_code,
};
use thiserror::Error;

use crate::protected_file::{self, ProtectedFileError, PublishMode};

const MINIMUM_RECOVERY_BUNDLE_BYTES: usize = 256;
const DOWNLOAD_PREFIX: &str = "meshspan-recovery-file-v1.";

/// One validated encrypted bundle retained only until the administrator verifies a saved copy.
pub struct PendingRecoveryBundle {
    bundle: RecoveryBundle,
}

/// Idempotent protected-file cleanup after authoritative save verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingRecoveryBundleRemoval {
    /// The exact pending file was removed durably.
    Applied,
    /// The file was already absent after the authoritative transition.
    Replayed,
}

impl PendingRecoveryBundle {
    /// Opens the exact pending bundle or atomically creates it when absent.
    ///
    /// # Errors
    ///
    /// Rejects unsafe files, another mesh, a wrong derived code, corruption, unavailable entropy
    /// or publication failure. Existing evidence is never replaced.
    pub fn open_or_create(
        path: &Path,
        mesh_id: MeshId,
        code: &RecoveryBundleCode,
        random: &mut impl RandomSource,
    ) -> Result<Self, PendingRecoveryBundleError> {
        match protected_file::read_bounded(
            path,
            MINIMUM_RECOVERY_BUNDLE_BYTES,
            MAXIMUM_RECOVERY_BUNDLE_BYTES,
        ) {
            Ok(bytes) => Self::from_bytes(&bytes, mesh_id, code),
            Err(ProtectedFileError::Missing) => Self::create(path, mesh_id, code, random),
            Err(error) => Err(error.into()),
        }
    }

    /// Returns public identity and bundle commitments safe for consensus metadata.
    ///
    /// # Errors
    ///
    /// Fails only if validated in-memory public-key evidence has been corrupted.
    pub fn public_identity(&self) -> Result<OfflineRecoveryIdentity, PendingRecoveryBundleError> {
        Ok(OfflineRecoveryIdentity::from_bundle(&self.bundle)?)
    }

    /// Returns the short exact save-verification challenge.
    #[must_use]
    pub fn challenge(
        &self,
        code: &RecoveryBundleCode,
    ) -> meshspan_recovery_bundle::RecoveryChallenge {
        self.bundle.challenge(code)
    }

    /// Encodes a canonical text file safe for JSON delivery and direct offline saving.
    ///
    /// # Errors
    ///
    /// Fails closed if the validated bundle cannot enter its bounded canonical file encoding.
    pub fn download_text(&self) -> Result<String, PendingRecoveryBundleError> {
        let bytes = self.bundle.encode()?;
        let mut output = String::with_capacity(DOWNLOAD_PREFIX.len() + (bytes.len() * 2));
        output.push_str(DOWNLOAD_PREFIX);
        append_hex(&mut output, &bytes);
        Ok(output)
    }

    /// Removes only the exact verified mesh and bundle digest.
    ///
    /// # Errors
    ///
    /// Rejects unsafe, corrupt, substituted or changed evidence; absence is an idempotent replay.
    pub fn remove_if_matches(
        path: &Path,
        mesh_id: MeshId,
        bundle_digest: [u8; 32],
    ) -> Result<PendingRecoveryBundleRemoval, PendingRecoveryBundleError> {
        let bytes = match protected_file::read_bounded(
            path,
            MINIMUM_RECOVERY_BUNDLE_BYTES,
            MAXIMUM_RECOVERY_BUNDLE_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(ProtectedFileError::Missing) => {
                return Ok(PendingRecoveryBundleRemoval::Replayed);
            }
            Err(error) => return Err(error.into()),
        };
        let bundle = RecoveryBundle::decode(&bytes)?;
        if bundle.mesh_id() != mesh_id || bundle.digest() != bundle_digest {
            return Err(PendingRecoveryBundleError::Conflict);
        }
        protected_file::remove(path)?;
        Ok(PendingRecoveryBundleRemoval::Applied)
    }

    fn create(
        path: &Path,
        mesh_id: MeshId,
        code: &RecoveryBundleCode,
        random: &mut impl RandomSource,
    ) -> Result<Self, PendingRecoveryBundleError> {
        let (bundle, _) = create_recovery_bundle_with_code(mesh_id, code, random)?;
        let bytes = bundle.encode()?;
        protected_file::publish(path, &bytes, PublishMode::Create)?;
        Self::from_bytes(&bytes, mesh_id, code)
    }

    fn from_bytes(
        bytes: &[u8],
        mesh_id: MeshId,
        code: &RecoveryBundleCode,
    ) -> Result<Self, PendingRecoveryBundleError> {
        let bundle = RecoveryBundle::decode(bytes)?;
        if bundle.mesh_id() != mesh_id {
            return Err(PendingRecoveryBundleError::Conflict);
        }
        let _authority = bundle.open(code)?;
        Ok(Self { bundle })
    }
}

/// Stable pending-bundle failures without file, code or private-key content.
#[derive(Debug, Error)]
pub enum PendingRecoveryBundleError {
    /// Owner-only atomic file handling failed.
    #[error("pending recovery bundle file failed")]
    File,
    /// Existing protected evidence belongs to different setup input.
    #[error("pending recovery bundle conflicts with setup")]
    Conflict,
    /// Recovery authority generation, encoding or authentication failed.
    #[error("pending recovery bundle is invalid or unavailable")]
    Bundle(#[from] RecoveryBundleError),
}

impl From<ProtectedFileError> for PendingRecoveryBundleError {
    fn from(_: ProtectedFileError) -> Self {
        Self::File
    }
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}
