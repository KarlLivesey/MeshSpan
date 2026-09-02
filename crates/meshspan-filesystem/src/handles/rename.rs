// SPDX-License-Identifier: GPL-2.0-only

//! Share-mode admission and logical-path relocation for namespace rename.

use meshspan_domain::{
    BranchId, FileVersionId, HandleId, ObjectId, ObjectRevisionId, UnixMicros, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::{DELETE_ACCESS, HandleError, expire_stale_handles, path};
use crate::{NamespacePath, NamespaceUnlinkAuthority, NamespaceUnlinkPublication};

/// Exact durable delete-on-close work item ready for logical namespace removal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyNamespaceDelete {
    /// Branch containing the pending name.
    pub branch_id: BranchId,
    /// Volume containing the pending name.
    pub volume_id: VolumeId,
    /// Stable file object to remove.
    pub object_id: ObjectId,
    /// Handle that originally requested delete-on-close.
    pub requesting_handle_id: HandleId,
    /// Latest immutable object revision committed before the handle closed.
    pub object_revision_id: ObjectRevisionId,
    /// Latest immutable file version committed before the handle closed.
    pub file_version_id: FileVersionId,
    /// Logical path retained by the closed handle.
    pub path: NamespacePath,
    /// Authoritative instant at which deletion became pending.
    pub requested_at: UnixMicros,
    /// Authoritative instant at which no live handle remained.
    pub ready_at: UnixMicros,
}

/// One bounded page of durable delete-on-close work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyNamespaceDeletePage {
    /// Exact work items ordered by stable object identity.
    pub entries: Vec<ReadyNamespaceDelete>,
    /// Cursor to present after this page, absent when the scan is complete.
    pub next_after_object_id: Option<ObjectId>,
}

pub(crate) fn load_ready_deletes(
    connection: &mut Connection,
    branch_id: BranchId,
    volume_id: VolumeId,
    after_object_id: Option<ObjectId>,
    maximum_results: u16,
    observed_at: UnixMicros,
) -> Result<ReadyNamespaceDeletePage, HandleError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    expire_stale_handles(&transaction, observed_at)?;
    let page = read_ready_deletes(
        &transaction,
        branch_id,
        volume_id,
        after_object_id,
        maximum_results,
    )?;
    transaction.commit()?;
    Ok(page)
}

pub(crate) fn load_ready_delete(
    connection: &mut Connection,
    requesting_handle_id: HandleId,
    observed_at: UnixMicros,
) -> Result<ReadyNamespaceDelete, HandleError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    expire_stale_handles(&transaction, observed_at)?;
    let stored = transaction
        .query_row(
            "SELECT branch_id, volume_id, object_id, object_revision_id, version_id,
                    requested_at, ready_at
             FROM pending_object_deletes
             WHERE requesting_handle_id = ?1 AND state = 2",
            [requesting_handle_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or(HandleError::DeletePending)?;
    let (branch, volume, object, revision, version, requested_at, ready_at) = stored;
    if ready_at < requested_at {
        return Err(HandleError::Corrupt);
    }
    let ready = ReadyNamespaceDelete {
        branch_id: super::identifier(&branch, BranchId::from_bytes)?,
        volume_id: super::identifier(&volume, VolumeId::from_bytes)?,
        object_id: super::identifier(&object, ObjectId::from_bytes)?,
        requesting_handle_id,
        object_revision_id: super::identifier(&revision, ObjectRevisionId::from_bytes)?,
        file_version_id: super::identifier(&version, FileVersionId::from_bytes)?,
        path: path::load(&transaction, requesting_handle_id)?,
        requested_at: UnixMicros::new(requested_at),
        ready_at: UnixMicros::new(ready_at),
    };
    transaction.commit()?;
    Ok(ready)
}

fn read_ready_deletes(
    connection: &Connection,
    branch_id: BranchId,
    volume_id: VolumeId,
    after_object_id: Option<ObjectId>,
    maximum_results: u16,
) -> Result<ReadyNamespaceDeletePage, HandleError> {
    const MAXIMUM_PAGE: u16 = 1_024;
    if maximum_results == 0 || maximum_results > MAXIMUM_PAGE {
        return Err(HandleError::InvalidInput);
    }
    let after = after_object_id.map(ObjectId::as_bytes);
    let fetch_limit = i64::from(maximum_results) + 1;
    let mut statement = connection.prepare(
        "SELECT object_id, requesting_handle_id, object_revision_id, version_id,
                requested_at, ready_at
         FROM pending_object_deletes
         WHERE branch_id = ?1 AND volume_id = ?2 AND state = 2
           AND (?3 IS NULL OR object_id > ?3)
         ORDER BY object_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            branch_id.as_bytes().as_slice(),
            volume_id.as_bytes().as_slice(),
            after.as_ref().map(<[u8; 16]>::as_slice),
            fetch_limit,
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    let mut entries = Vec::with_capacity(usize::from(maximum_results) + 1);
    for row in rows {
        let (object, handle, revision, version, requested_at, ready_at) = row?;
        if ready_at < requested_at {
            return Err(HandleError::Corrupt);
        }
        let requesting_handle_id = super::identifier(&handle, HandleId::from_bytes)?;
        entries.push(ReadyNamespaceDelete {
            branch_id,
            volume_id,
            object_id: super::identifier(&object, ObjectId::from_bytes)?,
            requesting_handle_id,
            object_revision_id: super::identifier(&revision, ObjectRevisionId::from_bytes)?,
            file_version_id: super::identifier(&version, FileVersionId::from_bytes)?,
            path: path::load(connection, requesting_handle_id)?,
            requested_at: UnixMicros::new(requested_at),
            ready_at: UnixMicros::new(ready_at),
        });
    }
    let has_more = entries.len() > usize::from(maximum_results);
    if has_more {
        entries.pop();
    }
    let next_after_object_id = has_more
        .then(|| entries.last().map(|entry| entry.object_id))
        .flatten();
    Ok(ReadyNamespaceDeletePage {
        entries,
        next_after_object_id,
    })
}

pub(crate) fn prepare(
    transaction: &Transaction<'_>,
    branch_id: BranchId,
    volume_id: VolumeId,
    object_id: ObjectId,
    requesting_handle_id: Option<HandleId>,
    now: UnixMicros,
) -> Result<(), HandleError> {
    expire_stale_handles(transaction, now)?;
    if let Some(handle_id) = requesting_handle_id {
        require_delete_handle(transaction, branch_id, volume_id, object_id, handle_id, now)?;
    }
    reject_share_conflict(
        transaction,
        branch_id,
        volume_id,
        object_id,
        requesting_handle_id,
        now,
    )?;
    reject_pending_delete(transaction, branch_id, volume_id, object_id)?;
    reject_unfinished_flush(transaction, branch_id, volume_id, object_id)
}

pub(crate) fn prepare_unlink(
    transaction: &Transaction<'_>,
    publication: &NamespaceUnlinkPublication,
) -> Result<(), HandleError> {
    match publication.authority {
        NamespaceUnlinkAuthority::Direct {
            requesting_handle_id,
        } => prepare(
            transaction,
            publication.branch_id,
            publication.volume_id,
            publication.expected_object_id,
            requesting_handle_id,
            publication.created_at,
        ),
        NamespaceUnlinkAuthority::DeleteOnClose {
            requesting_handle_id,
            requested_at,
            ready_at,
        } => {
            expire_stale_handles(transaction, publication.created_at)?;
            reject_unfinished_flush(
                transaction,
                publication.branch_id,
                publication.volume_id,
                publication.expected_object_id,
            )?;
            let version_id = publication
                .expected_file_version_id
                .ok_or(HandleError::InvalidInput)?;
            let valid: i64 = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pending_object_deletes pending
                    WHERE pending.branch_id = ?1 AND pending.volume_id = ?2
                      AND pending.object_id = ?3 AND pending.requesting_handle_id = ?4
                      AND pending.object_revision_id = ?5 AND pending.version_id = ?6
                      AND pending.state = 2 AND pending.requested_at = ?7
                      AND pending.ready_at = ?8
                      AND NOT EXISTS(
                          SELECT 1 FROM open_handles handles
                          WHERE handles.branch_id = pending.branch_id
                            AND handles.volume_id = pending.volume_id
                            AND handles.object_id = pending.object_id
                            AND handles.state = 1 AND handles.lease_expires_at > ?9
                      )
                 )",
                params![
                    publication.branch_id.as_bytes().as_slice(),
                    publication.volume_id.as_bytes().as_slice(),
                    publication.expected_object_id.as_bytes().as_slice(),
                    requesting_handle_id.as_bytes().as_slice(),
                    publication
                        .expected_object_revision_id
                        .as_bytes()
                        .as_slice(),
                    version_id.as_bytes().as_slice(),
                    requested_at.get(),
                    ready_at.get(),
                    publication.created_at.get(),
                ],
                |row| row.get(0),
            )?;
            if valid == 1 {
                Ok(())
            } else {
                Err(HandleError::DeletePending)
            }
        }
    }
}

pub(crate) fn consume_unlink_authority(
    transaction: &Transaction<'_>,
    publication: &NamespaceUnlinkPublication,
) -> Result<(), HandleError> {
    let NamespaceUnlinkAuthority::DeleteOnClose {
        requesting_handle_id,
        requested_at,
        ready_at,
    } = publication.authority
    else {
        return Ok(());
    };
    let version_id = publication
        .expected_file_version_id
        .ok_or(HandleError::InvalidInput)?;
    let removed = transaction.execute(
        "DELETE FROM pending_object_deletes
         WHERE branch_id = ?1 AND volume_id = ?2 AND object_id = ?3
           AND requesting_handle_id = ?4 AND object_revision_id = ?5 AND version_id = ?6
           AND state = 2 AND requested_at = ?7 AND ready_at = ?8",
        params![
            publication.branch_id.as_bytes().as_slice(),
            publication.volume_id.as_bytes().as_slice(),
            publication.expected_object_id.as_bytes().as_slice(),
            requesting_handle_id.as_bytes().as_slice(),
            publication
                .expected_object_revision_id
                .as_bytes()
                .as_slice(),
            version_id.as_bytes().as_slice(),
            requested_at.get(),
            ready_at.get(),
        ],
    )?;
    if removed == 1 {
        Ok(())
    } else {
        Err(HandleError::Corrupt)
    }
}

fn require_delete_handle(
    transaction: &Transaction<'_>,
    branch_id: BranchId,
    volume_id: VolumeId,
    object_id: ObjectId,
    handle_id: HandleId,
    now: UnixMicros,
) -> Result<(), HandleError> {
    let desired: Option<i64> = transaction
        .query_row(
            "SELECT desired_access FROM open_handles
             WHERE handle_id = ?1 AND branch_id = ?2 AND volume_id = ?3 AND object_id = ?4
               AND state = 1 AND lease_expires_at > ?5",
            params![
                handle_id.as_bytes().as_slice(),
                branch_id.as_bytes().as_slice(),
                volume_id.as_bytes().as_slice(),
                object_id.as_bytes().as_slice(),
                now.get(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    match desired.and_then(|value| u8::try_from(value).ok()) {
        Some(bits) if bits & DELETE_ACCESS != 0 => Ok(()),
        Some(_) => Err(HandleError::InvalidInput),
        None => Err(HandleError::StaleHandle),
    }
}

fn reject_share_conflict(
    transaction: &Transaction<'_>,
    branch_id: BranchId,
    volume_id: VolumeId,
    object_id: ObjectId,
    requesting_handle_id: Option<HandleId>,
    now: UnixMicros,
) -> Result<(), HandleError> {
    let requester = requesting_handle_id.map(HandleId::as_bytes);
    let conflicts: i64 = transaction.query_row(
        "SELECT count(*) FROM open_handles
         WHERE branch_id = ?1 AND volume_id = ?2 AND object_id = ?3
           AND state = 1 AND lease_expires_at > ?4
           AND (share_access & ?5) = 0
           AND (?6 IS NULL OR handle_id != ?6)",
        params![
            branch_id.as_bytes().as_slice(),
            volume_id.as_bytes().as_slice(),
            object_id.as_bytes().as_slice(),
            now.get(),
            DELETE_ACCESS,
            requester.as_ref().map(<[u8; 16]>::as_slice),
        ],
        |row| row.get(0),
    )?;
    if conflicts == 0 {
        Ok(())
    } else {
        Err(HandleError::SharingViolation)
    }
}

fn reject_pending_delete(
    transaction: &Transaction<'_>,
    branch_id: BranchId,
    volume_id: VolumeId,
    object_id: ObjectId,
) -> Result<(), HandleError> {
    let pending: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM pending_object_deletes
            WHERE branch_id = ?1 AND volume_id = ?2 AND object_id = ?3
         )",
        params![
            branch_id.as_bytes().as_slice(),
            volume_id.as_bytes().as_slice(),
            object_id.as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    if pending == 0 {
        Ok(())
    } else {
        Err(HandleError::DeletePending)
    }
}

fn reject_unfinished_flush(
    transaction: &Transaction<'_>,
    branch_id: BranchId,
    volume_id: VolumeId,
    object_id: ObjectId,
) -> Result<(), HandleError> {
    let unfinished: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM handle_flush_plans plans
            LEFT JOIN handle_flush_progress progress
              ON progress.flush_operation_id = plans.operation_id
            WHERE plans.branch_id = ?1 AND plans.volume_id = ?2 AND plans.object_id = ?3
              AND progress.flush_operation_id IS NULL
         )",
        params![
            branch_id.as_bytes().as_slice(),
            volume_id.as_bytes().as_slice(),
            object_id.as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    if unfinished == 0 {
        Ok(())
    } else {
        Err(HandleError::FlushInProgress)
    }
}

pub(crate) fn relocate_paths(
    transaction: &Transaction<'_>,
    branch_id: BranchId,
    volume_id: VolumeId,
    object_id: ObjectId,
    source: &NamespacePath,
    target: &NamespacePath,
) -> Result<(), HandleError> {
    let mut statement = transaction.prepare(
        "SELECT handle_id FROM open_handles
         WHERE branch_id = ?1 AND volume_id = ?2 AND object_id = ?3 AND state = 1
         ORDER BY handle_id",
    )?;
    let rows = statement.query_map(
        params![
            branch_id.as_bytes().as_slice(),
            volume_id.as_bytes().as_slice(),
            object_id.as_bytes().as_slice(),
        ],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let handles = rows
        .map(|row| {
            HandleId::from_bytes(row?.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for handle_id in handles {
        if path::load(transaction, handle_id)? != *source {
            return Err(HandleError::Corrupt);
        }
        transaction.execute(
            "DELETE FROM open_handle_path_components WHERE handle_id = ?1",
            [handle_id.as_bytes().as_slice()],
        )?;
        path::persist(transaction, handle_id, target)?;
    }
    Ok(())
}
