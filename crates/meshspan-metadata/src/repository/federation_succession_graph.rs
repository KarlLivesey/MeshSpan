// SPDX-License-Identifier: GPL-2.0-only

//! Bounded signed ancestry and acyclic recovery-succession graph proofs.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{FederationSuccessionId, MeshId, Revision};
use rusqlite::{Connection, Transaction, params};

use super::RepositoryError;
use super::apply::to_i64;
use crate::{DesignateFederationSuccessor, FederationSuccessionEdge};

pub(super) const MAXIMUM_ANCESTRY_EDGES: usize = 64;

pub(super) fn verify_ancestry(
    connection: &Connection,
    command: &DesignateFederationSuccessor,
) -> Result<(), RepositoryError> {
    let ancestry = command.ancestry.as_slice();
    if ancestry
        .first()
        .is_some_and(|edge| edge.successor_mesh_id != command.retiring_mesh_id)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    for edge in ancestry {
        if edge.retiring_mesh_id == edge.successor_mesh_id
            || edge.retiring_mesh_id == command.successor_mesh_id
            || edge.successor_mesh_id == command.successor_mesh_id
        {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    for pair in ancestry.windows(2) {
        if pair[1].successor_mesh_id != pair[0].retiring_mesh_id {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    ensure_graph_acyclic(
        connection,
        Some((command.retiring_mesh_id, command.successor_mesh_id)),
        ancestry,
    )
}

pub(super) fn ensure_active_graph_acyclic(
    connection: &Connection,
    retiring_mesh_id: MeshId,
    successor_mesh_id: MeshId,
) -> Result<(), RepositoryError> {
    ensure_graph_acyclic(connection, Some((retiring_mesh_id, successor_mesh_id)), &[])
}

pub(super) fn ensure_graph_acyclic(
    connection: &Connection,
    proposed: Option<(MeshId, MeshId)>,
    presented: &[FederationSuccessionEdge],
) -> Result<(), RepositoryError> {
    let mut edges = BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT retiring_mesh_id, successor_mesh_id
         FROM federation_ownership_successions WHERE state = 3 ORDER BY retiring_mesh_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let row = row?;
        insert_edge(&mut edges, parse_mesh(&row.0)?, parse_mesh(&row.1)?)?;
    }
    for edge in presented {
        insert_edge(&mut edges, edge.retiring_mesh_id, edge.successor_mesh_id)?;
    }
    if let Some((retiring, successor)) = proposed {
        insert_edge(&mut edges, retiring, successor)?;
    }
    for start in edges.keys().copied() {
        let mut visited = BTreeSet::new();
        let mut current = start;
        while let Some(next) = edges.get(&current).copied() {
            if !visited.insert(current) {
                return Err(RepositoryError::InvalidCommand);
            }
            current = next;
        }
    }
    Ok(())
}

pub(super) fn persist_ancestry(
    transaction: &Transaction<'_>,
    command: &DesignateFederationSuccessor,
    revision: Revision,
) -> Result<(), RepositoryError> {
    for (sequence, edge) in command.ancestry.as_slice().iter().enumerate() {
        transaction.execute(
            "INSERT INTO federation_ownership_succession_ancestry(
                succession_id, edge_sequence, retiring_mesh_id, successor_mesh_id, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                command.succession_id.as_bytes().as_slice(),
                to_i64(u64::try_from(sequence).map_err(|_| RepositoryError::CapacityExceeded)?)?,
                edge.retiring_mesh_id.as_bytes().as_slice(),
                edge.successor_mesh_id.as_bytes().as_slice(),
                to_i64(revision.get())?,
            ],
        )?;
    }
    Ok(())
}

pub(super) fn load_ancestry(
    connection: &Connection,
    succession_id: FederationSuccessionId,
) -> Result<Vec<FederationSuccessionEdge>, RepositoryError> {
    let mut statement = connection.prepare(
        "SELECT edge_sequence, retiring_mesh_id, successor_mesh_id
         FROM federation_ownership_succession_ancestry
         WHERE succession_id = ?1 ORDER BY edge_sequence",
    )?;
    let rows = statement.query_map([succession_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut ancestry = Vec::new();
    for (expected, row) in rows.enumerate() {
        let row = row?;
        if positive_or_zero(row.0)?
            != u64::try_from(expected).map_err(|_| RepositoryError::CorruptState)?
        {
            return Err(RepositoryError::CorruptState);
        }
        ancestry.push(FederationSuccessionEdge {
            retiring_mesh_id: parse_mesh(&row.1)?,
            successor_mesh_id: parse_mesh(&row.2)?,
        });
    }
    Ok(ancestry)
}

fn insert_edge(
    edges: &mut BTreeMap<MeshId, MeshId>,
    retiring: MeshId,
    successor: MeshId,
) -> Result<(), RepositoryError> {
    if retiring == successor
        || edges
            .insert(retiring, successor)
            .is_some_and(|existing| existing != successor)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn parse_mesh(value: &[u8]) -> Result<MeshId, RepositoryError> {
    MeshId::from_bytes(
        value
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn positive_or_zero(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}
