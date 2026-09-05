// SPDX-License-Identifier: GPL-2.0-only

//! Capability-scoped filesystem access for directory backup objects.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use meshspan_contracts::{BackupObjectIdentity, BackupObjectReference};
use meshspan_domain::{BackupDestinationId, OperationId};
use sha2::{Digest, Sha256};

use super::DirectoryBackupProviderError;

const PRIVATE_DIRECTORY: &str = ".meshspan-backups";
const OBJECT_DIRECTORY: &str = "objects";
const CATALOGUE_FILE: &str = "catalogue.sqlite3";
const LOCK_FILE: &str = "provider.lock";
const BUFFER_BYTES: usize = 64 * 1_024;

pub(super) struct ProviderFiles {
    pub(super) objects: Dir,
    pub(super) catalogue_path: PathBuf,
    pub(super) lock: std::fs::File,
}

pub(super) fn open(
    storage_path: &Path,
    destination_id: BackupDestinationId,
) -> Result<ProviderFiles, DirectoryBackupProviderError> {
    let canonical_path = std::fs::canonicalize(storage_path)?;
    let root = Dir::open_ambient_dir(&canonical_path, ambient_authority())?;
    create_directory(&root, PRIVATE_DIRECTORY)?;
    let private = root.open_dir(PRIVATE_DIRECTORY)?;
    let destination_directory = destination_directory(destination_id)?;
    create_directory(&private, &destination_directory)?;
    let destination = private.open_dir(&destination_directory)?;
    let lock = open_lock(&destination)?;
    create_directory(&destination, OBJECT_DIRECTORY)?;
    let objects = destination.open_dir(OBJECT_DIRECTORY)?;
    Ok(ProviderFiles {
        objects,
        catalogue_path: canonical_path
            .join(PRIVATE_DIRECTORY)
            .join(destination_directory)
            .join(CATALOGUE_FILE),
        lock,
    })
}

fn destination_directory(
    destination_id: BackupDestinationId,
) -> Result<String, DirectoryBackupProviderError> {
    let mut value = String::with_capacity(32);
    append_hex(&mut value, &destination_id.as_bytes())?;
    Ok(value)
}

pub(super) fn object_reference(
    object: BackupObjectIdentity,
) -> Result<BackupObjectReference, DirectoryBackupProviderError> {
    let mut value = String::with_capacity(39);
    value.push_str("backup-");
    append_hex(&mut value, &object.backup_id.as_bytes())?;
    value.push_str(".msb");
    BackupObjectReference::new(value).map_err(Into::into)
}

pub(super) fn validate_reference(
    object: BackupObjectIdentity,
    supplied: &BackupObjectReference,
) -> Result<(), DirectoryBackupProviderError> {
    if object_reference(object)?.as_str() == supplied.as_str() {
        Ok(())
    } else {
        Err(DirectoryBackupProviderError::Conflict)
    }
}

pub(super) fn persist_stream(
    objects: &Dir,
    operation_id: OperationId,
    expected: BackupObjectIdentity,
    object_reference: &str,
    source: &mut dyn Read,
) -> Result<(), DirectoryBackupProviderError> {
    discard_unpublished_staging(objects)?;
    if existing_file_matches(objects, object_reference, expected)? {
        return Ok(());
    }
    let pending = pending_reference(operation_id)?;
    remove_if_present(objects, &pending)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = objects.open_with(&pending, &options)?;
    let measurement = copy_and_hash(source, &mut file, Some(expected.byte_length));
    let (length, digest) = match measurement {
        Ok(measurement) => measurement,
        Err(error) => {
            drop(file);
            remove_if_present(objects, &pending)?;
            return Err(error);
        }
    };
    if let Err(error) = verify_measurement(expected, length, digest) {
        drop(file);
        remove_if_present(objects, &pending)?;
        return Err(error);
    }
    file.sync_all()?;
    drop(file);
    match objects.rename(&pending, objects, object_reference) {
        Ok(()) => sync_directory(objects)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            remove_if_present(objects, &pending)?;
            if !existing_file_matches(objects, object_reference, expected)? {
                return Err(DirectoryBackupProviderError::Conflict);
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// The provider holds its exclusive destination lock: no live writer can own these files.
/// Published objects use a different name and are never selected by this recovery pass.
pub(super) fn discard_unpublished_staging(
    objects: &Dir,
) -> Result<(), DirectoryBackupProviderError> {
    for entry in objects.entries()? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(id) = name.strip_prefix("pending-") else {
            continue;
        };
        if id.len() == 32
            && id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            remove_if_present(objects, name)?;
        }
    }
    Ok(())
}

pub(super) fn stream_object(
    objects: &Dir,
    object_reference: &str,
    destination: &mut dyn Write,
) -> Result<(u64, [u8; 32]), DirectoryBackupProviderError> {
    let mut source = objects.open(object_reference).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            DirectoryBackupProviderError::NotFound
        } else {
            error.into()
        }
    })?;
    copy_and_hash(&mut source, destination, None)
}

pub(super) fn verify_measurement(
    expected: BackupObjectIdentity,
    byte_length: u64,
    digest: [u8; 32],
) -> Result<(), DirectoryBackupProviderError> {
    if byte_length == expected.byte_length && digest == expected.digest {
        Ok(())
    } else {
        Err(DirectoryBackupProviderError::Corrupt)
    }
}

pub(super) fn remove_if_present(
    objects: &Dir,
    object_reference: &str,
) -> Result<(), DirectoryBackupProviderError> {
    match objects.remove_file(object_reference) {
        Ok(()) => {
            sync_directory(objects)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Absence is a filesystem fact, not an expired lease. A dangling symlink or
/// non-file entry is still present and must retain its charge for investigation.
pub(super) fn confirm_object_absent(
    objects: &Dir,
    object_reference: &str,
) -> Result<bool, DirectoryBackupProviderError> {
    match objects.symlink_metadata(object_reference) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            sync_directory(objects)?;
            Ok(true)
        }
        Err(error) => Err(error.into()),
    }
}

fn create_directory(parent: &Dir, name: &str) -> Result<(), DirectoryBackupProviderError> {
    match parent.create_dir(name) {
        Ok(()) => sync_directory(parent),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn open_lock(directory: &Dir) -> Result<std::fs::File, DirectoryBackupProviderError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    let lock = directory.open_with(LOCK_FILE, &options)?.into_std();
    lock.try_lock()
        .map_err(|_| DirectoryBackupProviderError::AlreadyOwned)?;
    Ok(lock)
}

fn existing_file_matches(
    objects: &Dir,
    object_reference: &str,
    expected: BackupObjectIdentity,
) -> Result<bool, DirectoryBackupProviderError> {
    let mut file = match objects.open(object_reference) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let (length, digest) = copy_and_hash(&mut file, &mut std::io::sink(), None)?;
    if length == expected.byte_length && digest == expected.digest {
        Ok(true)
    } else {
        Err(DirectoryBackupProviderError::Conflict)
    }
}

fn copy_and_hash(
    source: &mut dyn Read,
    destination: &mut dyn Write,
    maximum: Option<u64>,
) -> Result<(u64, [u8; 32]), DirectoryBackupProviderError> {
    let mut buffer = vec![0_u8; BUFFER_BYTES];
    let mut digest = Sha256::new();
    let mut length = 0_u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(read).map_err(|_| DirectoryBackupProviderError::Corrupt)?)
            .ok_or(DirectoryBackupProviderError::Corrupt)?;
        if maximum.is_some_and(|limit| length > limit) {
            return Err(DirectoryBackupProviderError::InvalidInput);
        }
        destination.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
    }
    Ok((length, digest.finalize().into()))
}

fn pending_reference(operation_id: OperationId) -> Result<String, DirectoryBackupProviderError> {
    let mut value = String::with_capacity(40);
    value.push_str("pending-");
    append_hex(&mut value, &operation_id.as_bytes())?;
    Ok(value)
}

fn append_hex(value: &mut String, bytes: &[u8]) -> Result<(), DirectoryBackupProviderError> {
    for byte in bytes {
        write!(value, "{byte:02x}").map_err(|_| DirectoryBackupProviderError::Corrupt)?;
    }
    Ok(())
}

fn sync_directory(directory: &Dir) -> Result<(), DirectoryBackupProviderError> {
    directory.try_clone()?.into_std_file().sync_all()?;
    Ok(())
}
