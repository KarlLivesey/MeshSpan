// SPDX-License-Identifier: GPL-2.0-only

//! Node-local attachment of the original restored journals, without copying write history.

use super::Error;
use crate::{LocalNodeIdentity, OperatingSystemClock};
use meshspan_domain::Clock as _;
use meshspan_metadata::{AuthoritativeRepository, LocalDatabase, LocalRecoveredTarget};
use meshspan_recovery_bundle::RecoveryStateTransfer;
use std::{ffi::OsString, fs, os::unix::ffi::OsStrExt as _, path::Path};

/// Each option binds an existing target workspace and folder, not a new registration command.
pub(super) fn validate_arguments(arguments: &[OsString]) -> Result<(), Error> {
    let (targets, remainder) = arguments.as_chunks::<3>();
    if targets.len() > 1024
        || !remainder.is_empty()
        || targets
            .iter()
            .any(|[flag, _, _]| flag != "--storage-target")
    {
        return Err(Error::StateInstallArguments);
    }
    Ok(())
}

pub(super) struct Installation<'a> {
    pub repository: &'a AuthoritativeRepository,
    pub transfer: &'a RecoveryStateTransfer,
    pub identity: &'a LocalNodeIdentity,
    pub root_certificate: &'a Path,
    pub destination: &'a Path,
}

pub(super) fn install(context: &Installation<'_>, arguments: &[OsString]) -> Result<(), Error> {
    validate_arguments(arguments)?;
    if arguments.is_empty() {
        return Ok(());
    }
    let local_path = context.destination.join("local.sqlite3");
    let mut local = LocalDatabase::open(
        &local_path,
        context.transfer.claims().node_id,
        OperatingSystemClock.now(),
    )
    .map_err(|_| Error::Workspace)?;
    let destination = fs::canonicalize(context.destination).map_err(|_| Error::Workspace)?;
    for [_, work, folder] in arguments.as_chunks::<3>().0 {
        let work = fs::canonicalize(work).map_err(|_| Error::Workspace)?;
        let folder = fs::canonicalize(folder).map_err(|_| Error::Content)?;
        if work.starts_with(&folder)
            || folder.starts_with(&work)
            || destination.starts_with(&work)
            || work.starts_with(&destination)
            || destination.starts_with(&folder)
            || folder.starts_with(&destination)
        {
            return Err(Error::Workspace);
        }
        let record = verify_mount(context, &work, &folder)?;
        local
            .install_local_recovered_target(&record)
            .map_err(|_| Error::Conflict)?;
    }
    local.check_integrity().map_err(|_| Error::Material)?;
    drop(local);
    super::sync_private(&local_path)
}

fn verify_mount(
    context: &Installation<'_>,
    work: &Path,
    folder: &Path,
) -> Result<LocalRecoveredTarget, Error> {
    let target = super::super::restoration::load_target(
        work,
        context.transfer,
        context.identity,
        context.root_certificate,
    )?;
    let provider = context
        .repository
        .storage_target_provider_context_by_target(target.target_id)?
        .ok_or(Error::Authority)?;
    let claims = target.authorization.claims();
    if provider.mesh_id != claims.mesh_id
        || provider.node_id != target.node_id
        || provider.generation != target.generation
        || provider.usage_limit != target.usage_limit
        || provider.catalogue_revision != claims.source_revision
        || provider.policy_revision
            != claims
                .source_revision
                .next()
                .map_err(|_| Error::Authority)?
        || context
            .repository
            .recovery_storage_target_marker(target.target_id, target.generation)?
            != Some(target.marker_fingerprint)
    {
        return Err(Error::Authority);
    }
    // Reopen under exclusive folder ownership. This includes WAL, journal identity, capacity
    // and pack consistency; a missing journal must not create a new empty write history.
    let restored = super::super::restoration::open_provider(&target, folder, work, true)?;
    let record = LocalRecoveredTarget {
        target_id: target.target_id,
        node_id: target.node_id,
        mesh_id: claims.mesh_id,
        recovery_id: claims.recovery_id,
        state_digest: context.transfer.claims().state_digest,
        generation: target.generation,
        marker_fingerprint: target.marker_fingerprint,
        canonical_path: folder.as_os_str().as_bytes().to_vec(),
        journal_directory: work.as_os_str().as_bytes().to_vec(),
        policy_revision: provider.policy_revision,
        usage_limit: target.usage_limit,
    };
    drop(restored);
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_arguments_are_optional_repeatable_and_bounded() {
        assert!(validate_arguments(&[]).is_ok());
        let target = [
            OsString::from("--storage-target"),
            OsString::from("state"),
            OsString::from("folder"),
        ];
        assert!(validate_arguments(&target).is_ok());
        let mut maximum: Vec<_> = (0..1024).flat_map(|_| target.clone()).collect();
        assert!(validate_arguments(&maximum).is_ok());
        maximum.extend(target.clone());
        assert!(validate_arguments(&maximum).is_err());
        assert!(validate_arguments(&target[..2]).is_err());
        assert!(
            validate_arguments(&[
                OsString::from("--unknown"),
                OsString::from("state"),
                OsString::from("folder")
            ])
            .is_err()
        );
    }
}
