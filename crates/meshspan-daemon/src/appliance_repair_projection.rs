// SPDX-License-Identifier: GPL-2.0-only

//! Bounded replay of committed repair routes on every gateway, including storage-free ones.

use meshspan_domain::UnixMicros;
use meshspan_filesystem::{
    ContentCatalogError, DurableContentCatalog, RepairProjectionCursor, RepairProjectionManifest,
    ShardRepairTransition,
};
use meshspan_metadata::{
    AuthoritativeRepository, PageLimit, RepositoryError, ShardRepairEffectCursor,
};
use thiserror::Error;

use super::StorageTargetRuntime;

const MAXIMUM_EFFECTS_PER_MANIFEST_STEP: usize = 32;

#[derive(Debug, Error)]
pub(crate) enum RepairProjectionError {
    #[error("committed repair effects could not be read")]
    Authority(#[from] RepositoryError),
    #[error("committed repair route could not be projected")]
    Catalogue(#[from] ContentCatalogError),
    #[error("committed repair effect contradicts its manifest scope")]
    Scope,
}

/// One bounded page and whether its authority snapshot contained further effects.
pub(crate) struct RepairProjectionStep {
    pub(crate) applied: usize,
    pub(crate) pending: bool,
}

impl StorageTargetRuntime {
    pub(super) fn project_one_repair_manifest(&mut self, now: UnixMicros) -> Result<usize, ()> {
        let mut catalogue = self
            .native_filesystem
            .maintenance_catalogue(now)
            .map_err(|_| ())?;
        let page = catalogue
            .repair_projection_manifests(self.repair_projection_after, 1)
            .map_err(|_| ())?;
        // Fairness is only local scan progress. Every manifest's durable feed cursor is
        // stored with its applied routes, so restart or a late import loses no effects.
        self.repair_projection_after = page.next;
        let Some(manifest) = page.manifests.as_slice().first().copied() else {
            return Ok(0);
        };
        project_manifest(
            self.maintenance_authority.reader(),
            &mut catalogue,
            manifest,
        )
        .map(|step| step.applied)
        .map_err(|_| ())
    }
}

pub(crate) fn project_manifest(
    authority: &AuthoritativeRepository,
    catalogue: &mut DurableContentCatalog,
    manifest: RepairProjectionManifest,
) -> Result<RepairProjectionStep, RepairProjectionError> {
    let partition = authority.partition_id();
    let mut cursor = catalogue.repair_projection_cursor(partition, manifest.content)?;
    let page = authority.shard_repair_effects(
        manifest.volume_id,
        manifest.content.manifest.manifest_id,
        cursor.map(|position| ShardRepairEffectCursor {
            revision: position.revision,
            effect_operation_id: position.effect_operation_id,
        }),
        PageLimit::new(MAXIMUM_EFFECTS_PER_MANIFEST_STEP)?,
    )?;
    let count = page.items.len();
    let pending = page.next.is_some();
    for effect in page.items {
        if effect.volume_id != manifest.volume_id
            || effect.manifest_id != manifest.content.manifest.manifest_id
            || effect.source_receipt.shard.manifest_digest != manifest.content.manifest.root_digest
        {
            return Err(RepairProjectionError::Scope);
        }
        let transition = ShardRepairTransition {
            effect_operation_id: effect.effect_operation_id,
            source_layout_generation: effect.source_layout_generation,
            replacement_layout_generation: effect.replacement_layout_generation,
            source_receipt: effect.source_receipt,
            replacement_receipt: effect.replacement_receipt,
            committed_revision: effect.revision,
        };
        catalogue.project_shard_repair(partition, manifest.content, cursor, &transition)?;
        cursor = Some(RepairProjectionCursor {
            revision: effect.revision,
            effect_operation_id: effect.effect_operation_id,
        });
    }
    Ok(RepairProjectionStep {
        applied: count,
        pending,
    })
}

#[cfg(test)]
pub(super) fn snapshot_repair_catalogue(
    runtime: &StorageTargetRuntime,
) -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let source = rusqlite::Connection::open_with_flags(
        runtime
            .state_directory
            .join("filesystem/filesystem-content.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    // SQLite's snapshot boundary captures a stale gateway catalogue before the effect,
    // without copying a live WAL file or altering either authoritative database.
    source.backup(
        rusqlite::MAIN_DB,
        directory.path().join("filesystem-content.sqlite3"),
        None,
    )?;
    Ok(directory)
}

#[cfg(test)]
pub(super) fn assert_stale_catalogue_replays(
    runtime: &StorageTargetRuntime,
    directory: &std::path::Path,
    effect: &meshspan_metadata::ShardRepairEffectRecord,
    now: UnixMicros,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut catalogue = DurableContentCatalog::open(directory, now)?;
    let content = catalogue
        .committed_content_by_manifest(effect.manifest_id)?
        .ok_or("stale manifest")?;
    let source = effect.source_receipt;
    let before = catalogue
        .shard_repair_candidate(source.target_id, source.target_generation, source.shard)?
        .ok_or("stale gateway still has the original route")?;
    assert_eq!(before.source_receipt, source);
    assert_eq!(before.source_layout_generation, 1);
    let manifest = RepairProjectionManifest {
        volume_id: effect.volume_id,
        content,
    };
    assert_eq!(
        project_manifest(
            runtime.maintenance_authority.reader(),
            &mut catalogue,
            manifest
        )?
        .applied,
        1
    );
    let partition = runtime.maintenance_authority.reader().partition_id();
    let cursor = RepairProjectionCursor {
        revision: effect.revision,
        effect_operation_id: effect.effect_operation_id,
    };
    assert_eq!(
        catalogue.repair_projection_cursor(partition, content)?,
        Some(cursor)
    );
    assert_eq!(
        catalogue.shard_repair_candidate(
            source.target_id,
            source.target_generation,
            source.shard
        )?,
        None
    );
    drop(catalogue);
    let mut reopened = DurableContentCatalog::open(directory, now)?;
    assert_eq!(
        project_manifest(
            runtime.maintenance_authority.reader(),
            &mut reopened,
            manifest
        )?
        .applied,
        0
    );
    assert_eq!(
        reopened.repair_projection_cursor(partition, content)?,
        Some(cursor)
    );
    let replacement = effect.replacement_receipt;
    let current = reopened
        .shard_repair_candidate(
            replacement.target_id,
            replacement.target_generation,
            replacement.shard,
        )?
        .ok_or("reopened gateway replacement route")?;
    assert_eq!(current.source_receipt, replacement);
    assert_eq!(current.source_layout_generation, 2);
    Ok(())
}
