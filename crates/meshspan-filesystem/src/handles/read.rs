// SPDX-License-Identifier: GPL-2.0-only

//! Exact live-handle validation and immutable-base selection for bounded reads.

use meshspan_domain::FileVersionId;
use rusqlite::Connection;

use super::{HandleError, state};
use crate::{FilesystemHandleReadRequest, PublishedContentReference};

#[derive(Clone, Copy)]
pub(crate) struct HandleReadPlan {
    pub base: Option<PublishedContentReference>,
    pub opened_version_id: FileVersionId,
    pub uses_private_stage: bool,
}

pub(crate) fn prepare_read(
    connection: &Connection,
    request: FilesystemHandleReadRequest,
) -> Result<HandleReadPlan, HandleError> {
    let handle = state::load_active(connection, request.handle_id, request.observed_at)?;
    if request.handle_fence != handle.fence
        || request.principal_id != handle.principal
        || request.authorization_revision != handle.authorization_revision
        || request.gateway_node_id != handle.gateway
        || !handle.desired_access.reads()
    {
        return Err(HandleError::StaleHandle);
    }
    let base = super::flush::base_content(connection, request.handle_id)?;
    if !handle.desired_access.writes() && base.is_none() {
        return Err(HandleError::Corrupt);
    }
    Ok(HandleReadPlan {
        base,
        opened_version_id: handle.version,
        uses_private_stage: handle.desired_access.writes(),
    })
}
