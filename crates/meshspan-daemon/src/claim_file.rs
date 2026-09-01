// SPDX-License-Identifier: GPL-2.0-only

//! Atomic owner-only filesystem presentation for one secret claim bundle.

use std::io;
use std::path::Path;

use meshspan_domain::{ClaimBundle, ClaimId, ENCODED_CLAIM_BUNDLE_LENGTH};
use thiserror::Error;

use crate::protected_file::{self, ProtectedFileError, PublishMode};

/// Owner-only local automation-file operations for one claim bundle.
pub struct ClaimFile;

impl ClaimFile {
    /// Atomically creates a new protected output without replacing any existing path.
    ///
    /// The complete bytes and file metadata are durable before the destination name
    /// becomes visible. The parent directory is synchronised after publication.
    ///
    /// # Errors
    ///
    /// Rejects an existing destination, unsuitable path or any filesystem/durability failure.
    pub fn create(path: &Path, claim: &ClaimBundle) -> Result<(), ClaimFileError> {
        publish(path, claim, PublishMode::Create)
    }

    /// Atomically replaces the exact destination with a new protected claim output.
    ///
    /// # Errors
    ///
    /// Rejects an unsuitable path or any filesystem/durability failure. A failure
    /// before rename leaves the prior destination unchanged.
    pub fn replace(path: &Path, claim: &ClaimBundle) -> Result<(), ClaimFileError> {
        publish(path, claim, PublishMode::Replace)
    }

    /// Opens, bounds and parses one owner-only regular claim file without following
    /// a swapped symbolic link between the metadata check and read.
    ///
    /// # Errors
    ///
    /// Rejects missing, permissive, non-regular, replaced, malformed or unreadable files.
    pub fn read(path: &Path) -> Result<ClaimBundle, ClaimFileError> {
        let bytes = protected_file::read_bounded(
            path,
            ENCODED_CLAIM_BUNDLE_LENGTH,
            ENCODED_CLAIM_BUNDLE_LENGTH,
        )
        .map_err(map_protected_error)?;
        let encoded = std::str::from_utf8(&bytes).map_err(|_| ClaimFileError::Invalid)?;
        ClaimBundle::parse(encoded).map_err(|_| ClaimFileError::Invalid)
    }

    /// Removes the output only when it still names the exact claim and verifier.
    ///
    /// A missing path or different replacement is left untouched and reports `false`.
    ///
    /// # Errors
    ///
    /// Rejects unsafe/malformed files or a filesystem/durability failure.
    pub fn remove_if_matches(
        path: &Path,
        claim_id: ClaimId,
        secret_digest: [u8; 32],
    ) -> Result<bool, ClaimFileError> {
        let claim = match Self::read(path) {
            Ok(claim) => claim,
            Err(ClaimFileError::Missing) => return Ok(false),
            Err(error) => return Err(error),
        };
        if claim.claim_id() != claim_id || !digests_match(claim.secret_digest(), secret_digest) {
            return Ok(false);
        }
        protected_file::remove(path).map_err(map_protected_error)?;
        Ok(true)
    }
}

/// Stable protected-claim-file failure without secret or path contents.
#[derive(Debug, Error)]
pub enum ClaimFileError {
    /// The requested input file does not exist.
    #[error("claim output is missing")]
    Missing,
    /// Create mode refused to overwrite an existing destination.
    #[error("claim output already exists")]
    Exists,
    /// The path is not one stable owner-only regular file.
    #[error("claim output has unsafe file metadata")]
    Unsafe,
    /// The file identity changed while it was being opened.
    #[error("claim output changed during validation")]
    Changed,
    /// Bytes were truncated, excessive, non-UTF-8 or not a canonical claim.
    #[error("claim output contents are invalid")]
    Invalid,
    /// A filesystem or durability operation failed.
    #[error("claim output filesystem operation failed")]
    Io(#[from] io::Error),
}

fn publish(path: &Path, claim: &ClaimBundle, mode: PublishMode) -> Result<(), ClaimFileError> {
    let encoded = claim.expose_encoded();
    protected_file::publish(path, encoded.as_bytes(), mode).map_err(map_protected_error)
}

fn map_protected_error(error: ProtectedFileError) -> ClaimFileError {
    match error {
        ProtectedFileError::Missing => ClaimFileError::Missing,
        ProtectedFileError::Exists => ClaimFileError::Exists,
        ProtectedFileError::Unsafe => ClaimFileError::Unsafe,
        ProtectedFileError::Changed => ClaimFileError::Changed,
        ProtectedFileError::Invalid => ClaimFileError::Invalid,
        ProtectedFileError::Io(error) => ClaimFileError::Io(error),
    }
}

fn digests_match(expected: [u8; 32], presented: [u8; 32]) -> bool {
    expected
        .iter()
        .zip(presented)
        .fold(0_u8, |difference, (expected, presented)| {
            difference | (expected ^ presented)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use meshspan_domain::{ClaimBundle, EntropyError, RandomSource};
    use tempfile::tempdir;

    use super::{ClaimFile, ClaimFileError};

    #[test]
    fn create_is_owner_only_durable_and_never_overwrites() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let path = directory.path().join("claim.txt");
        let first = bundle(1)?;
        let second = bundle(50)?;

        ClaimFile::create(&path, &first)?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            ClaimFile::read(&path)?.secret_digest(),
            first.secret_digest()
        );
        assert!(matches!(
            ClaimFile::create(&path, &second),
            Err(ClaimFileError::Exists)
        ));
        assert_eq!(
            ClaimFile::read(&path)?.secret_digest(),
            first.secret_digest()
        );
        Ok(())
    }

    #[test]
    fn replacement_is_exact_and_matching_removal_does_not_delete_another_claim()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("claim.txt");
        let first = bundle(1)?;
        let second = bundle(50)?;
        ClaimFile::create(&path, &first)?;
        ClaimFile::replace(&path, &second)?;

        assert!(!ClaimFile::remove_if_matches(
            &path,
            first.claim_id(),
            first.secret_digest()
        )?);
        assert!(path.exists());
        assert!(ClaimFile::remove_if_matches(
            &path,
            second.claim_id(),
            second.secret_digest()
        )?);
        assert!(!path.exists());
        assert!(!ClaimFile::remove_if_matches(
            &path,
            second.claim_id(),
            second.secret_digest()
        )?);
        Ok(())
    }

    #[test]
    fn read_rejects_symlinks_permissions_truncation_and_excess()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("claim.txt");
        let link = directory.path().join("claim-link.txt");
        let claim = bundle(1)?;
        ClaimFile::create(&path, &claim)?;
        symlink(&path, &link)?;
        assert!(matches!(
            ClaimFile::read(&link),
            Err(ClaimFileError::Unsafe)
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        assert!(matches!(
            ClaimFile::read(&path),
            Err(ClaimFileError::Unsafe)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        fs::write(&path, b"short")?;
        assert!(matches!(
            ClaimFile::read(&path),
            Err(ClaimFileError::Invalid)
        ));
        fs::write(
            &path,
            vec![b'x'; meshspan_domain::ENCODED_CLAIM_BUNDLE_LENGTH + 1],
        )?;
        assert!(matches!(
            ClaimFile::read(&path),
            Err(ClaimFileError::Invalid)
        ));
        Ok(())
    }

    fn bundle(seed: u8) -> Result<ClaimBundle, meshspan_domain::ClaimBundleError> {
        ClaimBundle::generate(&mut SequentialRandom(seed))
    }

    struct SequentialRandom(u8);

    impl RandomSource for SequentialRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            for byte in destination {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }
}
