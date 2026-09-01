// SPDX-License-Identifier: GPL-2.0-only

//! Bounded headless configuration shared by daemon entry points.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use thiserror::Error;

const MAXIMUM_STORAGE_PATHS: usize = 1_024;
const MAXIMUM_ARGUMENTS: usize = (MAXIMUM_STORAGE_PATHS + 1) * 2;

/// Per-target ceiling for bytes owned by `MeshSpan`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageLimit {
    /// Percentage of the target's measured capacity.
    Percent(u8),
    /// Fixed maximum physical bytes.
    Bytes(u64),
}

impl UsageLimit {
    /// Ordinary appliance default: at most 95% of measured target capacity.
    pub const DEFAULT: Self = Self::Percent(95);

    /// Validates one percentage ceiling.
    ///
    /// # Errors
    ///
    /// Rejects zero and percentages above 100.
    pub const fn percent(value: u8) -> Result<Self, StorageConfigError> {
        if value == 0 || value > 100 {
            Err(StorageConfigError::InvalidUsageLimit)
        } else {
            Ok(Self::Percent(value))
        }
    }

    /// Validates one fixed-byte ceiling.
    ///
    /// # Errors
    ///
    /// Rejects a zero-byte target ceiling.
    pub const fn bytes(value: u64) -> Result<Self, StorageConfigError> {
        if value == 0 {
            Err(StorageConfigError::InvalidUsageLimit)
        } else {
            Ok(Self::Bytes(value))
        }
    }
}

/// Minimal daemon-local paths accepted in headless operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadlessStorageConfig {
    daemon_state_dir: PathBuf,
    storage_paths: Vec<PathBuf>,
}

impl HeadlessStorageConfig {
    /// Validates one state directory and one or more independent storage folders.
    ///
    /// Paths remain operating-system strings; non-UTF paths are not lossy-converted.
    /// Filesystem identity and overlap checks happen when folders are opened because the paths
    /// may not exist while configuration is being assembled.
    ///
    /// # Errors
    ///
    /// Rejects empty paths, duplicate storage paths, an exact state/storage path collision and
    /// inputs beyond the compiled path-count bound.
    pub fn new(
        daemon_state_dir: PathBuf,
        storage_paths: Vec<PathBuf>,
    ) -> Result<Self, StorageConfigError> {
        if daemon_state_dir.as_os_str().is_empty() {
            return Err(StorageConfigError::MissingStateDirectory);
        }
        if storage_paths.is_empty() {
            return Err(StorageConfigError::MissingStoragePath);
        }
        if storage_paths.len() > MAXIMUM_STORAGE_PATHS {
            return Err(StorageConfigError::InvalidArguments);
        }
        let mut unique_paths = BTreeSet::new();
        for folder in &storage_paths {
            if folder.as_os_str().is_empty() {
                return Err(StorageConfigError::InvalidArguments);
            }
            if folder == &daemon_state_dir {
                return Err(StorageConfigError::StateStorageConflict);
            }
            if !unique_paths.insert(folder) {
                return Err(StorageConfigError::DuplicateStoragePath);
            }
        }
        Ok(Self {
            daemon_state_dir,
            storage_paths,
        })
    }

    /// Parses one required `--daemon-state-dir` and repeatable `--storage-path` flags.
    ///
    /// Paths remain operating-system strings; non-UTF paths are not lossy-converted.
    ///
    /// # Errors
    ///
    /// Rejects missing values, unknown/duplicate singleton flags, duplicate or empty paths,
    /// no storage paths, and inputs beyond the compiled path-count bound.
    pub fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, StorageConfigError> {
        let values: Vec<OsString> = arguments.into_iter().take(MAXIMUM_ARGUMENTS + 1).collect();
        if values.is_empty() || values.len() > MAXIMUM_ARGUMENTS || !values.len().is_multiple_of(2)
        {
            return Err(StorageConfigError::InvalidArguments);
        }
        let mut daemon_state_dir = None;
        let mut storage_paths = Vec::new();
        for pair in values.as_chunks::<2>().0 {
            let flag = &pair[0];
            let value = &pair[1];
            if value.is_empty() {
                return Err(StorageConfigError::InvalidArguments);
            }
            if flag == OsStr::new("--daemon-state-dir") {
                if daemon_state_dir.replace(PathBuf::from(value)).is_some() {
                    return Err(StorageConfigError::InvalidArguments);
                }
            } else if flag == OsStr::new("--storage-path") {
                storage_paths.push(PathBuf::from(value));
            } else {
                return Err(StorageConfigError::InvalidArguments);
            }
        }
        Self::new(
            daemon_state_dir.ok_or(StorageConfigError::MissingStateDirectory)?,
            storage_paths,
        )
    }

    /// Returns the daemon-owned state directory, which is never a storage provider folder.
    #[must_use]
    pub fn daemon_state_dir(&self) -> &std::path::Path {
        &self.daemon_state_dir
    }

    /// Returns every configured folder in command-line order.
    #[must_use]
    pub fn storage_paths(&self) -> &[PathBuf] {
        &self.storage_paths
    }
}

/// Stable configuration rejection without echoing attacker-controlled paths.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StorageConfigError {
    /// Flag/value structure or a value is invalid.
    #[error("storage arguments are invalid")]
    InvalidArguments,
    /// Exactly one daemon state directory is required.
    #[error("daemon state directory is required")]
    MissingStateDirectory,
    /// At least one storage path is required.
    #[error("at least one storage path is required")]
    MissingStoragePath,
    /// The same storage path was supplied more than once.
    #[error("storage path is duplicated")]
    DuplicateStoragePath,
    /// The daemon state directory was also supplied as a storage folder.
    #[error("daemon state directory cannot also be a storage path")]
    StateStorageConflict,
    /// A target usage ceiling is zero or outside its valid percentage range.
    #[error("storage usage limit is invalid")]
    InvalidUsageLimit,
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::Path;

    use super::{HeadlessStorageConfig, StorageConfigError, UsageLimit};

    #[test]
    fn repeatable_storage_paths_preserve_order_and_state_is_distinct()
    -> Result<(), StorageConfigError> {
        let config = HeadlessStorageConfig::parse(
            [
                "--storage-path",
                "/data/slow",
                "--daemon-state-dir",
                "/state/instance-a",
                "--storage-path",
                "/data/fast",
            ]
            .map(OsString::from),
        )?;
        assert_eq!(config.daemon_state_dir(), Path::new("/state/instance-a"));
        assert_eq!(config.storage_paths().len(), 2);
        assert_eq!(config.storage_paths()[0], Path::new("/data/slow"));
        assert_eq!(config.storage_paths()[1], Path::new("/data/fast"));
        Ok(())
    }

    #[test]
    fn invalid_flags_missing_values_and_duplicate_paths_fail_closed() {
        for arguments in [
            vec!["--storage-path", "/data"],
            vec!["--daemon-state-dir", "/state"],
            vec!["--daemon-state-dir", "/state", "--storage-path"],
            vec![
                "--daemon-state-dir",
                "/state",
                "--storage-path",
                "/data",
                "--storage-path",
                "/data",
            ],
            vec!["--state", "/state", "--storage-path", "/data"],
            vec!["--daemon-state-dir", "/same", "--storage-path", "/same"],
        ] {
            assert!(
                HeadlessStorageConfig::parse(arguments.into_iter().map(OsString::from)).is_err()
            );
        }
        assert_eq!(
            UsageLimit::percent(0),
            Err(StorageConfigError::InvalidUsageLimit)
        );
        assert_eq!(
            UsageLimit::percent(101),
            Err(StorageConfigError::InvalidUsageLimit)
        );
        assert_eq!(
            UsageLimit::bytes(0),
            Err(StorageConfigError::InvalidUsageLimit)
        );
        assert_eq!(UsageLimit::DEFAULT, UsageLimit::Percent(95));
    }
}
