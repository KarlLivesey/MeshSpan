// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative SMB-export publication and withdrawal.

use std::collections::BTreeSet;

use meshspan_domain::Revision;
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, PublishSmbExport, SmbExportGatewaySelection, WithdrawSmbExport};

const ACTIVE_VOLUME_STATE: i64 = 1;
const ACTIVE_NODE_STATE: i64 = 2;
const FOLDER_OBJECT_KIND: i64 = 1;
const GATEWAY_ROLE_CODE: i64 = 2;
const MAXIMUM_GATEWAYS: usize = 1_024;
const MAXIMUM_SHARE_NAME_BYTES: usize = 240;
const MAXIMUM_REASON_BYTES: usize = 1_024;

pub(super) fn publish(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &PublishSmbExport,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.share_name.display().len() > MAXIMUM_SHARE_NAME_BYTES
        || command.share_name.canonical().len() > MAXIMUM_SHARE_NAME_BYTES
    {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_root(transaction, command)?;
    let gateway_policy = match &command.gateways {
        SmbExportGatewaySelection::AllEligible => 1,
        SmbExportGatewaySelection::Selected(nodes) => {
            validate_gateways(transaction, nodes.as_slice())?;
            2
        }
    };
    let export = command.export_id.as_bytes();
    transaction.execute(
        "INSERT INTO smb_exports(
            export_id, volume_id, root_object_id, display_name, canonical_name,
            gateway_policy, encryption_required, state, created_by, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, ?9, ?10)",
        params![
            export.as_slice(),
            command.volume_id.as_bytes().as_slice(),
            command.root_object_id.as_bytes().as_slice(),
            command.share_name.display(),
            command.share_name.canonical(),
            gateway_policy,
            i64::from(command.encryption_required),
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    if let SmbExportGatewaySelection::Selected(nodes) = &command.gateways {
        for node in nodes.as_slice() {
            transaction.execute(
                "INSERT INTO smb_export_gateways(export_id, node_id, revision)
                 VALUES (?1, ?2, ?3)",
                params![
                    export.as_slice(),
                    node.as_bytes().as_slice(),
                    to_i64(revision.get())?,
                ],
            )?;
        }
    }
    Ok(EntityReference {
        kind: EntityKind::SmbExport,
        id: export,
    })
}

pub(super) fn withdraw(
    transaction: &Transaction<'_>,
    command: &WithdrawSmbExport,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.reason.trim().is_empty() || command.reason.len() > MAXIMUM_REASON_BYTES {
        return Err(RepositoryError::InvalidCommand);
    }
    let export = command.export_id.as_bytes();
    let updated = transaction.execute(
        "UPDATE smb_exports SET state = 2, revision = ?2
         WHERE export_id = ?1 AND state = 1",
        params![export.as_slice(), to_i64(revision.get())?],
    )?;
    if updated != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(EntityReference {
        kind: EntityKind::SmbExport,
        id: export,
    })
}

fn validate_root(
    transaction: &Transaction<'_>,
    command: &PublishSmbExport,
) -> Result<(), RepositoryError> {
    let root: Option<(i64, i64)> = transaction
        .query_row(
            "SELECT object.object_kind, volume.state
             FROM namespace_objects AS object
             JOIN volumes AS volume ON volume.volume_id = object.volume_id
             WHERE object.object_id = ?1 AND object.volume_id = ?2 AND object.state = 1",
            params![
                command.root_object_id.as_bytes().as_slice(),
                command.volume_id.as_bytes().as_slice(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if root != Some((FOLDER_OBJECT_KIND, ACTIVE_VOLUME_STATE)) {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn validate_gateways(
    transaction: &Transaction<'_>,
    nodes: &[meshspan_domain::NodeId],
) -> Result<(), RepositoryError> {
    if nodes.is_empty() || nodes.len() > MAXIMUM_GATEWAYS {
        return Err(RepositoryError::InvalidCommand);
    }
    let mut unique = BTreeSet::new();
    for node in nodes {
        if !unique.insert(*node) {
            return Err(RepositoryError::InvalidCommand);
        }
        let eligible = transaction
            .query_row(
                "SELECT 1 FROM nodes AS node
                 JOIN node_roles AS role
                   ON role.node_id = node.node_id AND role.role_code = ?2
                 WHERE node.node_id = ?1 AND node.state = ?3 AND node.retired_at IS NULL",
                params![
                    node.as_bytes().as_slice(),
                    GATEWAY_ROLE_CODE,
                    ACTIVE_NODE_STATE,
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !eligible {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    Ok(())
}
