// SPDX-License-Identifier: GPL-2.0-only

//! Durable source-side contract for one atomic namespace relocation.

use meshspan_domain::{NamespaceCommitId, ObjectId, ObjectRevisionId};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{StoredCommit, load_commit, load_object_revision, validate_directory_transition};
use crate::publication::{decode_identifier, from_i64, to_i64};
use crate::{
    BranchMutationIntent, BranchRenameIntent, NamespaceComponent, NamespacePath, PublicationError,
};

type StoredRenameIntent = (i64, i64, Vec<u8>);

pub(super) fn validate_shape(intent: &BranchMutationIntent) -> Result<(), PublicationError> {
    let Some(rename) = &intent.rename else {
        return Ok(());
    };
    let same_canonical_path = intent.path.components().len()
        == rename.source_path.components().len()
        && intent
            .path
            .components()
            .iter()
            .zip(rename.source_path.components())
            .all(|(target, source)| target.canonical() == source.canonical());
    if rename.source_entry_generation == 0
        || rename.source_ancestors.len().checked_add(1)
            != Some(rename.source_path.components().len())
        || same_canonical_path
    {
        return Err(PublicationError::InvalidInput);
    }
    Ok(())
}

pub(super) fn persist(
    transaction: &Transaction<'_>,
    commit_id: NamespaceCommitId,
    rename: &BranchRenameIntent,
) -> Result<(), PublicationError> {
    transaction.execute(
        "INSERT INTO namespace_commit_renames(
            namespace_commit_id, source_path_depth, source_entry_generation,
            intermediate_root_object_revision_id
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            commit_id.as_bytes().as_slice(),
            to_i64(
                u64::try_from(rename.source_path.components().len())
                    .map_err(|_| PublicationError::InvalidInput)?
            )?,
            to_i64(rename.source_entry_generation)?,
            rename
                .intermediate_root_object_revision_id
                .as_bytes()
                .as_slice(),
        ],
    )?;
    persist_components(transaction, commit_id, rename)?;
    persist_ancestors(transaction, commit_id, rename)
}

fn persist_components(
    transaction: &Transaction<'_>,
    commit_id: NamespaceCommitId,
    rename: &BranchRenameIntent,
) -> Result<(), PublicationError> {
    for (ordinal, component) in rename.source_path.components().iter().enumerate() {
        transaction.execute(
            "INSERT INTO namespace_commit_rename_source_components(
                namespace_commit_id, component_ordinal, display_name, canonical_name
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                commit_id.as_bytes().as_slice(),
                to_i64(u64::try_from(ordinal).map_err(|_| PublicationError::InvalidInput)?)?,
                component.display(),
                component.canonical(),
            ],
        )?;
    }
    Ok(())
}

fn persist_ancestors(
    transaction: &Transaction<'_>,
    commit_id: NamespaceCommitId,
    rename: &BranchRenameIntent,
) -> Result<(), PublicationError> {
    for (ordinal, ancestor) in rename.source_ancestors.iter().enumerate() {
        transaction.execute(
            "INSERT INTO namespace_commit_rename_source_ancestors(
                namespace_commit_id, ancestor_ordinal, object_id, prior_revision_id,
                resulting_revision_id
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                commit_id.as_bytes().as_slice(),
                to_i64(u64::try_from(ordinal).map_err(|_| PublicationError::InvalidInput)?)?,
                ancestor.object_id().as_bytes().as_slice(),
                ancestor.expected_revision_id().as_bytes().as_slice(),
                ancestor.new_revision_id().as_bytes().as_slice(),
            ],
        )?;
    }
    Ok(())
}

pub(super) fn load(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<Option<BranchRenameIntent>, PublicationError> {
    let stored: Option<StoredRenameIntent> = connection
        .query_row(
            "SELECT source_path_depth, source_entry_generation,
                    intermediate_root_object_revision_id
             FROM namespace_commit_renames WHERE namespace_commit_id = ?1",
            [commit_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    stored
        .map(|stored| decode(connection, commit_id, &stored))
        .transpose()
}

fn decode(
    connection: &Connection,
    commit_id: NamespaceCommitId,
    stored: &StoredRenameIntent,
) -> Result<BranchRenameIntent, PublicationError> {
    let path_depth = usize::try_from(from_i64(stored.0)?).map_err(|_| PublicationError::Corrupt)?;
    let source_path = load_path(connection, commit_id, path_depth)?;
    Ok(BranchRenameIntent {
        source_path,
        source_ancestors: load_ancestors(connection, commit_id, path_depth)?,
        source_entry_generation: from_i64(stored.1)?,
        intermediate_root_object_revision_id: decode_identifier(
            &stored.2,
            ObjectRevisionId::from_bytes,
        )?,
    })
}

fn load_path(
    connection: &Connection,
    commit_id: NamespaceCommitId,
    path_depth: usize,
) -> Result<NamespacePath, PublicationError> {
    let mut statement = connection.prepare(
        "SELECT component_ordinal, display_name, canonical_name
         FROM namespace_commit_rename_source_components
         WHERE namespace_commit_id = ?1 ORDER BY component_ordinal",
    )?;
    let rows = statement.query_map([commit_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut components = Vec::new();
    for row in rows {
        let (ordinal, display, canonical) = row?;
        if usize::try_from(from_i64(ordinal)?) != Ok(components.len()) {
            return Err(PublicationError::Corrupt);
        }
        components.push(
            NamespaceComponent::from_stored(&display, &canonical)
                .map_err(|_| PublicationError::Corrupt)?,
        );
    }
    if components.len() != path_depth {
        return Err(PublicationError::Corrupt);
    }
    NamespacePath::from_stored_components(components).map_err(|_| PublicationError::Corrupt)
}

fn load_ancestors(
    connection: &Connection,
    commit_id: NamespaceCommitId,
    path_depth: usize,
) -> Result<Vec<crate::DirectoryRevisionTransition>, PublicationError> {
    let mut statement = connection.prepare(
        "SELECT ancestor_ordinal, object_id, prior_revision_id, resulting_revision_id
         FROM namespace_commit_rename_source_ancestors
         WHERE namespace_commit_id = ?1 ORDER BY ancestor_ordinal",
    )?;
    let rows = statement.query_map([commit_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    let mut ancestors = Vec::new();
    for row in rows {
        let (ordinal, object, prior, resulting) = row?;
        if usize::try_from(from_i64(ordinal)?) != Ok(ancestors.len()) {
            return Err(PublicationError::Corrupt);
        }
        ancestors.push(
            crate::DirectoryRevisionTransition::new(
                decode_identifier(&object, ObjectId::from_bytes)?,
                decode_identifier(&prior, ObjectRevisionId::from_bytes)?,
                decode_identifier(&resulting, ObjectRevisionId::from_bytes)?,
            )
            .map_err(|_| PublicationError::Corrupt)?,
        );
    }
    if ancestors.len().checked_add(1) == Some(path_depth) {
        Ok(ancestors)
    } else {
        Err(PublicationError::Corrupt)
    }
}

pub(super) fn validate_loaded(
    connection: &Connection,
    commit: &StoredCommit,
    rename: &BranchRenameIntent,
) -> Result<(), PublicationError> {
    let parent_id = commit.parent_id.ok_or(PublicationError::Corrupt)?;
    let parent = load_commit(connection, parent_id)?;
    let intermediate =
        load_object_revision(connection, rename.intermediate_root_object_revision_id)?;
    let final_root = load_object_revision(connection, commit.root_object_revision_id)?;
    if parent.volume_id != commit.volume_id
        || parent.root_object_id != commit.root_object_id
        || intermediate.volume_id != commit.volume_id
        || intermediate.object_id != commit.root_object_id
        || intermediate.kind != 1
        || intermediate.directory_root.is_none()
        || intermediate.file_version_id.is_some()
        || intermediate.prior_revision_id != Some(parent.root_object_revision_id)
        || final_root.volume_id != commit.volume_id
        || final_root.object_id != commit.root_object_id
        || final_root.kind != 1
        || final_root.directory_root.is_none()
        || final_root.file_version_id.is_some()
        || final_root.prior_revision_id != Some(rename.intermediate_root_object_revision_id)
    {
        return Err(PublicationError::Corrupt);
    }
    for ancestor in &rename.source_ancestors {
        validate_directory_transition(connection, commit.volume_id, *ancestor)?;
    }
    Ok(())
}
