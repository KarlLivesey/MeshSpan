// SPDX-License-Identifier: GPL-2.0-only

//! Exact local mesh identity read for root-scoped runtime capabilities.

use meshspan_domain::MeshId;

use super::RepositoryError;
use crate::PartitionDatabase;

pub(super) fn local_mesh_id(
    database: &PartitionDatabase,
) -> Result<Option<MeshId>, RepositoryError> {
    let mut statement = database
        .connection()
        .prepare("SELECT mesh_id FROM meshes ORDER BY mesh_id LIMIT 2")?;
    let rows = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    match rows.as_slice() {
        [] => Ok(None),
        [mesh_id] => MeshId::from_bytes(
            <[u8; 16]>::try_from(mesh_id.as_slice()).map_err(|_| RepositoryError::CorruptState)?,
        )
        .map(Some)
        .map_err(|_| RepositoryError::CorruptState),
        [_, _, ..] => Err(RepositoryError::CorruptState),
    }
}
