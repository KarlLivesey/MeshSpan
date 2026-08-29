// SPDX-License-Identifier: GPL-2.0-only

//! Independently decoded current handle state shared by lease and lock operations.

use meshspan_domain::{
    BranchId, FileVersionId, HandleId, NamespaceCommitId, NodeId, ObjectId, ObjectRevisionId,
    PrincipalId, Revision, UnixMicros, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, params};

use super::{
    HandleAccess, HandleAuthorityTarget, HandleError, HandleShare, identifier,
    validate_open_lineage,
};

pub(super) struct ActiveHandle {
    pub handle: HandleId,
    pub branch: BranchId,
    pub volume: VolumeId,
    pub object: ObjectId,
    pub object_revision: ObjectRevisionId,
    pub version: FileVersionId,
    pub principal: PrincipalId,
    pub authorization_revision: Revision,
    pub gateway: NodeId,
    pub fence: u64,
    pub desired_access: HandleAccess,
    pub delete_on_close: bool,
    pub lease_expires_at: UnixMicros,
}

struct StoredHandle {
    branch: Vec<u8>,
    volume: Vec<u8>,
    namespace_commit: Vec<u8>,
    object: Vec<u8>,
    object_revision: Vec<u8>,
    version: Vec<u8>,
    principal: Vec<u8>,
    authorization_revision: i64,
    gateway: Vec<u8>,
    fence: i64,
    desired_access: i64,
    share_access: i64,
    delete_on_close: i64,
    lease_expires_at: i64,
}

pub(super) fn load_active(
    connection: &Connection,
    handle: HandleId,
    observed_at: UnixMicros,
) -> Result<ActiveHandle, HandleError> {
    let stored: Option<StoredHandle> = connection
        .query_row(
            "SELECT branch_id, volume_id, opened_namespace_commit_id, object_id,
                    object_revision_id, opened_version_id, principal_id,
                    authorization_revision, gateway_node_id, handle_fence,
                    desired_access, share_access, delete_on_close, lease_expires_at
             FROM open_handles
             WHERE handle_id = ?1 AND state = 1 AND lease_expires_at > ?2",
            params![handle.as_bytes().as_slice(), observed_at.get()],
            |row| {
                Ok(StoredHandle {
                    branch: row.get(0)?,
                    volume: row.get(1)?,
                    namespace_commit: row.get(2)?,
                    object: row.get(3)?,
                    object_revision: row.get(4)?,
                    version: row.get(5)?,
                    principal: row.get(6)?,
                    authorization_revision: row.get(7)?,
                    gateway: row.get(8)?,
                    fence: row.get(9)?,
                    desired_access: row.get(10)?,
                    share_access: row.get(11)?,
                    delete_on_close: row.get(12)?,
                    lease_expires_at: row.get(13)?,
                })
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Err(HandleError::StaleHandle);
    };
    decode(connection, handle, observed_at, &stored)
}

pub(crate) fn uses_private_stage(
    connection: &Connection,
    handle: HandleId,
) -> Result<bool, HandleError> {
    let desired: Option<i64> = connection
        .query_row(
            "SELECT desired_access FROM open_handles WHERE handle_id = ?1",
            [handle.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let desired = desired.ok_or(HandleError::StaleHandle)?;
    let access = HandleAccess::from_bits(u8::try_from(desired).map_err(|_| HandleError::Corrupt)?)?;
    Ok(access.writes())
}

pub(crate) fn authority_target(
    connection: &Connection,
    handle: HandleId,
    observed_at: UnixMicros,
) -> Result<HandleAuthorityTarget, HandleError> {
    let active = load_active(connection, handle, observed_at)?;
    Ok(HandleAuthorityTarget {
        volume_id: active.volume,
        object_id: active.object,
        principal_id: active.principal,
        gateway_node_id: active.gateway,
        authorization_revision: active.authorization_revision,
        desired_access: active.desired_access,
        lease_expires_at: active.lease_expires_at,
    })
}

fn decode(
    connection: &Connection,
    handle: HandleId,
    observed_at: UnixMicros,
    stored: &StoredHandle,
) -> Result<ActiveHandle, HandleError> {
    let branch = identifier(&stored.branch, BranchId::from_bytes)?;
    let volume = identifier(&stored.volume, VolumeId::from_bytes)?;
    let namespace_commit = identifier(&stored.namespace_commit, NamespaceCommitId::from_bytes)?;
    let object = identifier(&stored.object, ObjectId::from_bytes)?;
    let object_revision = identifier(&stored.object_revision, ObjectRevisionId::from_bytes)?;
    let version = identifier(&stored.version, FileVersionId::from_bytes)?;
    let authorization_revision =
        u64::try_from(stored.authorization_revision).map_err(|_| HandleError::Corrupt)?;
    let fence = u64::try_from(stored.fence).map_err(|_| HandleError::Corrupt)?;
    let desired_access = HandleAccess::from_bits(
        u8::try_from(stored.desired_access).map_err(|_| HandleError::Corrupt)?,
    )?;
    HandleShare::from_bits(u8::try_from(stored.share_access).map_err(|_| HandleError::Corrupt)?)?;
    if authorization_revision == 0
        || fence == 0
        || !matches!(stored.delete_on_close, 0 | 1)
        || stored.lease_expires_at <= observed_at.get()
    {
        return Err(HandleError::Corrupt);
    }
    validate_open_lineage(
        connection,
        branch,
        volume,
        namespace_commit,
        object,
        object_revision,
        version,
    )?;
    Ok(ActiveHandle {
        handle,
        branch,
        volume,
        object,
        object_revision,
        version,
        principal: identifier(&stored.principal, PrincipalId::from_bytes)?,
        authorization_revision: Revision::new(authorization_revision),
        gateway: identifier(&stored.gateway, NodeId::from_bytes)?,
        fence,
        desired_access,
        delete_on_close: stored.delete_on_close == 1,
        lease_expires_at: UnixMicros::new(stored.lease_expires_at),
    })
}
