// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, private copies of a stable exclusively owned source pack and its crash journals.

use super::RecoveryStorageError as Error;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::{
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

const DATABASE: &str = "pack.sqlite3";
const MEMBERS: [&str; 4] = [
    DATABASE,
    "pack.sqlite3-wal",
    "pack.sqlite3-shm",
    "pack.sqlite3-journal",
];

pub(super) struct Workspace {
    directory: PathBuf,
    copied_bytes: u64,
}

impl Workspace {
    pub(super) fn capture(source: &Path, directory: &Path, maximum: u64) -> Result<Self, Error> {
        if maximum == 0 {
            return Err(Error::InvalidInput);
        }
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(directory)?;
        let mut remaining = maximum;
        for suffix in ["", "-wal", "-journal"] {
            let mut source_name = source.as_os_str().to_os_string();
            source_name.push(suffix);
            let source = Path::new(&source_name);
            match fs::symlink_metadata(source) {
                Ok(metadata) if metadata.is_file() => {}
                Ok(_) => return Err(Error::InvalidInput),
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound && !suffix.is_empty() =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
            let destination = directory.join(format!("{DATABASE}{suffix}"));
            remaining = copy_member(source, &destination, remaining)?;
        }
        Ok(Self {
            directory: directory.to_path_buf(),
            copied_bytes: maximum - remaining,
        })
    }

    pub(super) fn database(&self) -> PathBuf {
        self.directory.join(DATABASE)
    }

    pub(super) const fn copied_bytes(&self) -> u64 {
        self.copied_bytes
    }

    pub(super) fn sync(&self) -> Result<(), Error> {
        for name in MEMBERS {
            match fs::File::open(self.directory.join(name)) {
                Ok(file) => file.sync_all()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && name != DATABASE => {}
                Err(error) => return Err(error.into()),
            }
        }
        #[cfg(unix)]
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    /// Only for an exact pending workspace named by the owning inventory's durable journal.
    pub(super) fn remove_pending(directory: &Path) -> Result<(), Error> {
        match fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.is_dir() => Self {
                directory: directory.to_path_buf(),
                copied_bytes: 0,
            }
            .remove(),
            Ok(_) => Err(Error::InvalidInput),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn remove(self) -> Result<(), Error> {
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file()
                || !MEMBERS.iter().any(|name| entry.file_name() == *name)
            {
                return Err(Error::InvalidInput);
            }
        }
        for name in MEMBERS {
            match fs::remove_file(self.directory.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        fs::remove_dir(self.directory)?;
        Ok(())
    }
}

fn copy_member(source: &Path, destination: &Path, remaining: u64) -> Result<u64, Error> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
    let mut input = options.open(source)?;
    let metadata = input.metadata()?;
    let length = metadata.len();
    if !metadata.is_file() || length > remaining {
        return Err(Error::InvalidInput);
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut output = options.open(destination)?;
    let copied = std::io::copy(&mut (&mut input).take(length), &mut output)?;
    let mut extra = [0];
    if copied != length || input.read(&mut extra)? != 0 {
        return Err(Error::Corrupt);
    }
    output.flush()?;
    Ok(remaining - length)
}
