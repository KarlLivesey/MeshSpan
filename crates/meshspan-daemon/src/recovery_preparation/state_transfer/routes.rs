// SPDX-License-Identifier: GPL-2.0-only

//! Isolated route projection from revalidated node receipts and the original archive.

use super::{CONTENT, Error, NAMESPACE};
use meshspan_contracts::ShardReceipt;
use meshspan_domain::Clock as _;
use meshspan_filesystem::DurableContentCatalog;
use meshspan_metadata::{AuthoritativeRepository, RecoveryShardRestoration};
use meshspan_recovery_bundle::RecoveredAuthority;
use std::{fs, path::Path};

pub(super) fn prepare(
    repository: &AuthoritativeRepository,
    authority: &RecoveredAuthority,
    backup: &Path,
    staging: &Path,
) -> Result<u64, Error> {
    let authorization = repository.recovery_preparation_authorization(authority)?;
    let original = staging.join("archive");
    super::private_directory(&original)?;
    let (mut history, source) = super::super::history::restore_archived_history(
        backup,
        &original,
        authority,
        authorization.claims(),
    )?;
    super::super::history::verify_backup_history(repository, &mut history, &source)?;
    let (mut projected_history, mut projected) = meshspan_filesystem::snapshot_recovery_journals(
        &original,
        staging,
        crate::OperatingSystemClock.now(),
    )
    .map_err(|_| Error::History)?;
    let revision = authorization
        .claims()
        .source_revision
        .next()
        .map_err(|_| Error::Conflict)?;
    let mut references = 0_u64;
    repository.visit_recovery_restored_shards(authority, |claim, receipt| {
        project(&source, &mut projected, claim, receipt, revision)
            .map_err(|_| meshspan_metadata::RepositoryError::CorruptState)?;
        references = references
            .checked_add(1)
            .ok_or(meshspan_metadata::RepositoryError::CorruptState)?;
        Ok(())
    })?;
    super::super::history::verify_backup_history(repository, &mut projected_history, &projected)?;
    drop(projected);
    drop(projected_history);
    drop(source);
    drop(history);
    for name in [CONTENT, NAMESPACE] {
        fs::remove_file(original.join(name)).map_err(|_| Error::Cleanup)?;
    }
    fs::remove_dir(original).map_err(|_| Error::Cleanup)?;
    Ok(references)
}

fn project(
    source: &DurableContentCatalog,
    projected: &mut DurableContentCatalog,
    claim: &RecoveryShardRestoration,
    receipt: ShardReceipt,
    revision: meshspan_domain::Revision,
) -> Result<(), Error> {
    let candidate = source
        .shard_repair_candidate(
            claim.source_target_id,
            claim.source_generation,
            receipt.shard,
        )
        .map_err(|_| Error::History)?
        .ok_or(Error::Content)?;
    let mut expected = candidate.source_receipt;
    expected.operation_id =
        super::super::restoration::replacement_operation(&claim.target, expected)?;
    expected.target_id = claim.target.target_id;
    expected.target_generation = claim.target.generation;
    if expected != receipt {
        return Err(Error::Content);
    }
    let content = source
        .committed_content_by_manifest(candidate.manifest_id)
        .map_err(|_| Error::History)?
        .ok_or(Error::History)?;
    projected
        .prepare_recovery_shard_route(content, candidate, receipt, revision)
        .map_err(|_| Error::Content)
}
