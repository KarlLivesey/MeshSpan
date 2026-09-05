// SPDX-License-Identifier: GPL-2.0-only

//! Private, disposable restore workspaces; never a live database destination.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MARKER: &[u8] = b"meshspan-backup-readiness-v1\n";
const FILES: &[&str] = &[
    "container.msb",
    "plaintext.sqlite3",
    "plaintext.sqlite3-wal",
    "plaintext.sqlite3-shm",
    "plaintext.sqlite3-journal",
    "restored.sqlite3",
    "restored.sqlite3-wal",
    "restored.sqlite3-shm",
    "restored.sqlite3-journal",
];

pub(crate) struct ReadinessWorkspace {
    directory: PathBuf,
}

impl ReadinessWorkspace {
    // Called once while constructing the daemon's readiness service, before it accepts work.
    // Recovery removes only recognised owned workspaces, never arbitrary sibling content.
    pub(crate) fn prepare_root(state_directory: &Path) -> io::Result<PathBuf> {
        let root = state_directory.join("backup-readiness");
        match DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => File::open(state_directory)?.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        private_directory(&root)?;
        for (index, entry) in fs::read_dir(&root)?.enumerate() {
            if index >= 1024 {
                return Err(io::Error::other("too many restore workspaces"));
            }
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if crate::create_mesh_setup::parse_uuid(name).is_ok() {
                Self {
                    directory: entry.path(),
                }
                .cleanup()?;
            }
        }
        Ok(root)
    }

    pub(crate) fn create(
        root: &Path,
        operation_id: meshspan_domain::OperationId,
    ) -> io::Result<Self> {
        private_directory(root)?;
        let directory = root.join(crate::create_mesh_setup::format_uuid(
            operation_id.as_bytes(),
        ));
        DirBuilder::new().mode(0o700).create(&directory)?;
        let workspace = Self { directory };
        crate::protected_file::publish(
            &workspace.file("owner"),
            MARKER,
            crate::protected_file::PublishMode::Create,
        )
        .map_err(|_| io::Error::other("restore workspace ownership could not be recorded"))?;
        File::open(root)?.sync_all()?;
        Ok(workspace)
    }

    pub(crate) fn file(&self, name: &str) -> PathBuf {
        self.directory.join(name)
    }

    pub(crate) fn encrypted_file(&self) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.file("container.msb"))
    }

    pub(crate) fn cleanup(&self) -> io::Result<()> {
        private_directory(&self.directory)?;
        // Protected-file publication may have been interrupted before its owner-marker
        // hard link. These are its exact reserved temporary names, never arbitrary files.
        for attempt in 0..32 {
            match fs::remove_file(self.file(&format!(".owner.meshspan-{attempt}.tmp"))) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let marker_path = self.file("owner");
        match fs::symlink_metadata(&marker_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                let mut marker = Vec::new();
                File::open(&marker_path)?
                    .take(MARKER.len() as u64 + 1)
                    .read_to_end(&mut marker)?;
                if marker != MARKER {
                    return Err(io::Error::other("unrecognised restore workspace"));
                }
            }
            // An interruption before the marker was durable cannot have created plaintext.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return fs::remove_dir(&self.directory);
            }
            _ => return Err(io::Error::other("unsafe restore workspace marker")),
        }
        for name in FILES {
            match fs::remove_file(self.file(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        // Do not remove the marker if unexpected content prevents safe complete cleanup.
        if fs::read_dir(&self.directory)?.take(2).count() != 1 {
            return Err(io::Error::other(
                "restore workspace contains unexpected content",
            ));
        }
        fs::remove_file(marker_path)?;
        fs::remove_dir(&self.directory)?;
        if let Some(parent) = self.directory.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

impl Drop for ReadinessWorkspace {
    fn drop(&mut self) {
        // Normal completion checks cleanup explicitly. Unwinding/cancellation retries here;
        // any remaining marked workspace is reaped before this service next starts.
        let _cleanup = self.cleanup();
    }
}

fn private_directory(directory: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    let parent = directory
        .parent()
        .ok_or_else(|| io::Error::other("missing workspace parent"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o700
        || metadata.uid() != fs::metadata(parent)?.uid()
    {
        return Err(io::Error::other("unsafe restore workspace directory"));
    }
    Ok(())
}
