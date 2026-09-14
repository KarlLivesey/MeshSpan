// SPDX-License-Identifier: GPL-2.0-only

//! Fixed-file, encrypted recovery delivery. This boundary never grants service admission.

mod collection;
mod consensus_permission;
mod export;
pub(super) use collection::collect_command;
pub(super) use consensus_permission::admit_command;
pub(super) use consensus_permission::authorize_command;
mod install;
mod local_targets;
mod routes;
pub(super) use export::export_command;
pub(super) use export::export_set_command;
pub(super) use install::install_command;
pub(super) use install::install_into;

use super::{RecoveryPreparationError as Error, publication::DigestWriter};
use crate::protected_file;
use meshspan_domain::{Clock as _, NodeId};
use meshspan_filesystem::{DurableContentCatalog, VersionPublicationStore};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use std::{
    ffi::OsStr,
    fs::{self, DirBuilder, File},
    io::{self, Write as _},
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::Path,
};

const STATE: &str = "state.msb";
const AUTHORIZATION: &str = "state.auth";
const KEYS: &str = "keys.bundle";
const METADATA: &str = "prepared.sqlite3";
const NAMESPACE: &str = "filesystem-branch.sqlite3";
const CONTENT: &str = "filesystem-content.sqlite3";

fn node_id(value: &OsStr) -> Result<NodeId, Error> {
    value
        .to_str()
        .and_then(|value| crate::create_mesh_setup::parse_uuid(value).ok())
        .and_then(|bytes| NodeId::from_bytes(bytes).ok())
        .ok_or(Error::Input)
}

fn private_directory(root: &Path) -> Result<(), Error> {
    DirBuilder::new()
        .mode(0o700)
        .create(root)
        .map_err(|_| Error::Workspace)?;
    protected_file::sync_parent(root).map_err(|_| Error::Workspace)
}

fn sync_private(file: &Path) -> Result<(), Error> {
    let input = File::open(file).map_err(|_| Error::Workspace)?;
    input
        .set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|()| input.sync_all())
        .map_err(|_| Error::Workspace)?;
    protected_file::sync_parent(file).map_err(|_| Error::Workspace)
}

fn open_repository(file: &Path) -> Result<AuthoritativeRepository, Error> {
    let _guard = protected_file::open_read(file).map_err(|_| Error::Input)?;
    let database = PartitionDatabase::open_existing(file, crate::OperatingSystemClock.now())
        .map_err(|_| Error::Input)?;
    database.check_integrity().map_err(|_| Error::Material)?;
    Ok(AuthoritativeRepository::new(database))
}

fn check_history(repository: &AuthoritativeRepository, root: &Path) -> Result<(), Error> {
    let now = crate::OperatingSystemClock.now();
    let mut history = VersionPublicationStore::open(root, now).map_err(|_| Error::History)?;
    let catalog = DurableContentCatalog::open(root, now).map_err(|_| Error::History)?;
    super::history::verify_backup_history(repository, &mut history, &catalog)
}

fn file_digest(file: &Path) -> Result<([u8; 32], u64), Error> {
    let mut input = protected_file::open_read(file).map_err(|_| Error::Input)?;
    let mut digest = DigestWriter::new();
    io::copy(&mut input, &mut digest).map_err(|_| Error::Material)?;
    Ok(digest.finish())
}

fn print_report(report: &serde_json::Value) -> Result<(), Error> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, report).map_err(|_| Error::Worker)?;
    output.write_all(b"\n").map_err(|_| Error::Worker)
}
