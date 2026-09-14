// SPDX-License-Identifier: GPL-2.0-only

//! Exact local mesh identity read for root-scoped runtime capabilities.

use meshspan_domain::MeshId;

use super::RepositoryError;
use crate::PartitionDatabase;

pub(super) fn local_mesh_name(
    database: &PartitionDatabase,
) -> Result<Option<crate::RecordName>, RepositoryError> {
    let Some(id) = local_mesh_id(database)? else {
        return Ok(None);
    };
    let (display, canonical): (String, String) = database.connection().query_row(
        "SELECT display_name, canonical_name FROM meshes WHERE mesh_id = ?1",
        [id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let name = crate::RecordName::new(&display).map_err(|_| RepositoryError::CorruptState)?;
    if name.canonical() != canonical {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(name))
}

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
