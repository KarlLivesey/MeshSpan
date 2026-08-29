// SPDX-License-Identifier: GPL-2.0-only

//! Share-mode admission and logical-path relocation for namespace rename.

use meshspan_domain::{BranchId, HandleId, ObjectId, UnixMicros, VolumeId};
use rusqlite::{OptionalExtension, Transaction, params};

use super::{DELETE_ACCESS, HandleError, expire_stale_handles, path};
use crate::NamespacePath;

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
