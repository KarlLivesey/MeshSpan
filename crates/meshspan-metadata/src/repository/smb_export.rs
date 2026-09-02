// SPDX-License-Identifier: GPL-2.0-only

//! Replicated SMB-export desired state for one eligible gateway.

use meshspan_domain::{NodeId, ObjectId, Revision, SmbExportId, VolumeId};
use rusqlite::params;

use super::RepositoryError;
use crate::PartitionDatabase;

const MAXIMUM_EXPORTS_PER_GATEWAY: usize = 1_024;
const MAXIMUM_ROOT_DEPTH: usize = 1_024;

/// Gateway selection attached to one published export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmbExportGatewayPolicy {
    /// Every active node with the gateway role may publish the share.
    AllEligible,
    /// Only explicitly selected gateway nodes may publish the share.
    Selected,
}

/// One active, validated SMB export assigned to the queried gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmbExportRecord {
    /// Stable export identity.
    pub export_id: SmbExportId,
    /// Logical volume containing the exported root.
    pub volume_id: VolumeId,
    /// Exact directory exposed as the tree root.
    pub root_object_id: ObjectId,
    /// Case-preserved user-visible share name.
    pub display_name: String,
    /// Canonical case-insensitive share name.
    pub canonical_name: String,
    /// Gateway-selection policy.
    pub gateway_policy: SmbExportGatewayPolicy,
    /// Whether packets after tree connection must be encrypted.
    pub encryption_required: bool,
    /// Root-relative case-preserved path components, empty for a volume root.
    pub root_components: Vec<String>,
    /// Last authoritative configuration revision.
    pub revision: Revision,
}

pub(super) fn smb_exports_for_gateway(
    database: &PartitionDatabase,
    node_id: NodeId,
) -> Result<Vec<SmbExportRecord>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT export.export_id, export.volume_id, export.root_object_id,
                export.display_name, export.canonical_name, export.gateway_policy,
                export.encryption_required, export.revision
         FROM smb_exports AS export
         WHERE export.state = 1
           AND (export.gateway_policy = 1 OR EXISTS (
                SELECT 1 FROM smb_export_gateways AS gateway
                WHERE gateway.export_id = export.export_id AND gateway.node_id = ?1
           ))
         ORDER BY export.canonical_name, export.export_id
         LIMIT ?2",
    )?;
    let limit = i64::try_from(MAXIMUM_EXPORTS_PER_GATEWAY + 1)
        .map_err(|_| RepositoryError::CapacityExceeded)?;
    let rows = statement.query_map(params![node_id.as_bytes().as_slice(), limit], |row| {
        Ok(StoredSmbExport {
            export_id: row.get(0)?,
            volume_id: row.get(1)?,
            root_object_id: row.get(2)?,
            display_name: row.get(3)?,
            canonical_name: row.get(4)?,
            gateway_policy: row.get(5)?,
            encryption_required: row.get(6)?,
            revision: row.get(7)?,
        })
    })?;
    let mut exports = Vec::new();
    for row in rows {
        if exports.len() == MAXIMUM_EXPORTS_PER_GATEWAY {
            return Err(RepositoryError::CapacityExceeded);
        }
        exports.push(parse_export(database, row?)?);
    }
    Ok(exports)
}

struct StoredSmbExport {
    export_id: Vec<u8>,
    volume_id: Vec<u8>,
    root_object_id: Vec<u8>,
    display_name: String,
    canonical_name: String,
    gateway_policy: i64,
    encryption_required: i64,
    revision: i64,
}

fn parse_export(
    database: &PartitionDatabase,
    stored: StoredSmbExport,
) -> Result<SmbExportRecord, RepositoryError> {
    let volume_id = VolumeId::from_bytes(identifier(&stored.volume_id)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let root_object_id = ObjectId::from_bytes(identifier(&stored.root_object_id)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let gateway_policy = match stored.gateway_policy {
        1 => SmbExportGatewayPolicy::AllEligible,
        2 => SmbExportGatewayPolicy::Selected,
        _ => return Err(RepositoryError::CorruptState),
    };
    let encryption_required = match stored.encryption_required {
        0 => false,
        1 => true,
        _ => return Err(RepositoryError::CorruptState),
    };
    if stored.display_name.is_empty() || stored.canonical_name.is_empty() {
        return Err(RepositoryError::CorruptState);
    }
    Ok(SmbExportRecord {
        export_id: SmbExportId::from_bytes(identifier(&stored.export_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        volume_id,
        root_object_id,
        display_name: stored.display_name,
        canonical_name: stored.canonical_name,
        gateway_policy,
        encryption_required,
        root_components: load_root_components(database, volume_id, root_object_id)?,
        revision: Revision::new(
            u64::try_from(stored.revision).map_err(|_| RepositoryError::CorruptState)?,
        ),
    })
}

fn load_root_components(
    database: &PartitionDatabase,
    volume_id: VolumeId,
    root_object_id: ObjectId,
) -> Result<Vec<String>, RepositoryError> {
    let mut components = Vec::new();
    let mut current = root_object_id;
    loop {
        let row = database.connection().query_row(
            "SELECT parent_object_id, object_kind, display_name
             FROM namespace_objects
             WHERE object_id = ?1 AND volume_id = ?2 AND state = 1",
            params![
                current.as_bytes().as_slice(),
                volume_id.as_bytes().as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        if row.1 != 1 {
            return Err(RepositoryError::CorruptState);
        }
        let Some(parent) = row.0 else {
            if !row.2.is_empty() {
                return Err(RepositoryError::CorruptState);
            }
            break;
        };
        if row.2.is_empty() || components.len() == MAXIMUM_ROOT_DEPTH {
            return Err(RepositoryError::CorruptState);
        }
        components.push(row.2);
        current = ObjectId::from_bytes(identifier(&parent)?)
            .map_err(|_| RepositoryError::CorruptState)?;
    }
    components.reverse();
    Ok(components)
}

fn identifier(value: &[u8]) -> Result<[u8; 16], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}
