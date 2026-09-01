// SPDX-License-Identifier: GPL-2.0-only

//! Atomic owner-only local secret-file mechanics shared by typed daemon boundaries.

use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;
use zeroize::Zeroizing;

const OWNER_READ_WRITE: u32 = 0o600;
const TEMPORARY_ATTEMPTS: u8 = 32;

#[derive(Clone, Copy)]
pub(crate) enum PublishMode {
    Create,
    Replace,
}

pub(crate) fn publish(
    path: &Path,
    bytes: &[u8],
    mode: PublishMode,
) -> Result<(), ProtectedFileError> {
    validate_destination(path)?;
    let (temporary_path, mut temporary_file) = create_temporary(path)?;
    let result = (|| {
        temporary_file.write_all(bytes)?;
        temporary_file.sync_all()?;
        validate_metadata(&temporary_file.metadata()?)?;
        drop(temporary_file);
        match mode {
            PublishMode::Create => {
                fs::hard_link(&temporary_path, path).map_err(map_publish_error)?;
            }
            PublishMode::Replace => fs::rename(&temporary_path, path)?,
        }
        sync_parent(path)?;
        if matches!(mode, PublishMode::Create) {
            fs::remove_file(&temporary_path)?;
            sync_parent(path)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ignored = fs::remove_file(&temporary_path);
    }
    result
}

pub(crate) fn read_bounded(
    path: &Path,
    minimum_length: usize,
    maximum_length: usize,
) -> Result<Zeroizing<Vec<u8>>, ProtectedFileError> {
    if minimum_length == 0 || maximum_length < minimum_length {
        return Err(ProtectedFileError::Invalid);
    }
    let before = fs::symlink_metadata(path).map_err(map_read_error)?;
    validate_metadata(&before)?;
    let length = validate_length(&before, minimum_length, maximum_length)?;
    let mut file = OpenOptions::new().read(true).open(path)?;
    let opened = file.metadata()?;
    validate_metadata(&opened)?;
    validate_length(&opened, minimum_length, maximum_length)?;
    if !same_file(&before, &opened) {
        return Err(ProtectedFileError::Changed);
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    file.read_exact(&mut bytes)
        .map_err(map_bounded_read_error)?;
    let mut excess = [0_u8; 1];
    if file.read(&mut excess)? != 0 {
        return Err(ProtectedFileError::Invalid);
    }
    Ok(bytes)
}

pub(crate) fn remove(path: &Path) -> Result<(), ProtectedFileError> {
    fs::remove_file(path)?;
    sync_parent(path)
}

/// Stable protected-file failure without secret or path contents.
#[derive(Debug, Error)]
pub(crate) enum ProtectedFileError {
    #[error("protected file is missing")]
    Missing,
    #[error("protected file already exists")]
    Exists,
    #[error("protected file metadata is unsafe")]
    Unsafe,
    #[error("protected file changed during validation")]
    Changed,
    #[error("protected file contents are invalid")]
    Invalid,
    #[error("protected file filesystem operation failed")]
    Io(#[from] io::Error),
}

fn create_temporary(path: &Path) -> Result<(PathBuf, File), ProtectedFileError> {
    let parent = path.parent().ok_or(ProtectedFileError::Unsafe)?;
    let file_name = path.file_name().ok_or(ProtectedFileError::Unsafe)?;
    for attempt in 0..TEMPORARY_ATTEMPTS {
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".meshspan-{attempt}.tmp"));
        let temporary_path = parent.join(temporary_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(OWNER_READ_WRITE)
            .open(&temporary_path)
        {
            Ok(file) => return Ok((temporary_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(ProtectedFileError::Io(error)),
        }
    }
    Err(ProtectedFileError::Unsafe)
}

fn validate_destination(path: &Path) -> Result<(), ProtectedFileError> {
    let parent = path.parent().ok_or(ProtectedFileError::Unsafe)?;
    let file_name = path.file_name().ok_or(ProtectedFileError::Unsafe)?;
    if file_name.is_empty() || !fs::metadata(parent)?.is_dir() {
        return Err(ProtectedFileError::Unsafe);
    }
    Ok(())
}

fn validate_metadata(metadata: &Metadata) -> Result<(), ProtectedFileError> {
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ProtectedFileError::Unsafe);
    }
    Ok(())
}

fn validate_length(
    metadata: &Metadata,
    minimum_length: usize,
    maximum_length: usize,
) -> Result<usize, ProtectedFileError> {
    let length = usize::try_from(metadata.len()).map_err(|_| ProtectedFileError::Invalid)?;
    if (minimum_length..=maximum_length).contains(&length) {
        Ok(length)
    } else {
        Err(ProtectedFileError::Invalid)
    }
}

fn same_file(before: &Metadata, opened: &Metadata) -> bool {
    before.dev() == opened.dev() && before.ino() == opened.ino()
}

fn sync_parent(path: &Path) -> Result<(), ProtectedFileError> {
    let parent = path.parent().ok_or(ProtectedFileError::Unsafe)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn map_read_error(error: io::Error) -> ProtectedFileError {
    if error.kind() == io::ErrorKind::NotFound {
        ProtectedFileError::Missing
    } else {
        ProtectedFileError::Io(error)
    }
}

fn map_bounded_read_error(error: io::Error) -> ProtectedFileError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        ProtectedFileError::Invalid
    } else {
        ProtectedFileError::Io(error)
    }
}

fn map_publish_error(error: io::Error) -> ProtectedFileError {
    if error.kind() == io::ErrorKind::AlreadyExists {
        ProtectedFileError::Exists
    } else {
        ProtectedFileError::Io(error)
    }
}
