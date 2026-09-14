// SPDX-License-Identifier: GPL-2.0-only

//! Recovery-installed mount hints. Every runtime use still needs current replicated authority.

use meshspan_domain::{MeshId, NodeId, OperationId, Revision, TargetId};
use rusqlite::{Row, TransactionBehavior, params};

use crate::{LocalDatabase, LocalTargetDisposition, LocalTargetError, StorageUsageLimit};

const COLUMNS: &str = "target_id, node_id, mesh_id, recovery_id, state_digest, generation,
    marker_fingerprint, canonical_path, journal_directory, policy_revision,
    usage_limit_kind, usage_limit_value";

/// Node-local locations bound to a verified recovery transfer; never a user registration intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalRecoveredTarget {
    /// Exact restored storage target.
    pub target_id: TargetId,
    /// Node which owns the journal and folder.
    pub node_id: NodeId,
    /// Owning swarm.
    pub mesh_id: MeshId,
    /// Offline-root authorised recovery operation.
    pub recovery_id: OperationId,
    /// Exact common encrypted state archive digest.
    pub state_digest: [u8; 32],
    /// Exact restored target generation.
    pub generation: u64,
    /// Expected durable folder marker.
    pub marker_fingerprint: [u8; 32],
    /// Canonical provider folder in opaque OS bytes, never replicated.
    pub canonical_path: Vec<u8>,
    /// Existing node-private journal root. Recovery does not clone the journal.
    pub journal_directory: Vec<u8>,
    /// Minimum applied authority revision required before runtime use.
    pub policy_revision: Revision,
    /// Prepared capacity ceiling, used to verify the original marker binding.
    pub usage_limit: StorageUsageLimit,
}

impl LocalDatabase {
    /// Saves a verified mount binding atomically, preserving the exact first installation.
    ///
    /// The caller verifies root/node signatures, canonical metadata, folder and existing journal.
    /// This does not grant authority, change replicated metadata or mark the provider active.
    ///
    /// # Errors
    /// Rejects malformed/node-foreign records, changed retries, ordinary-registration collisions
    /// and failed durable writes.
    pub fn install_local_recovered_target(
        &mut self,
        target: &LocalRecoveredTarget,
    ) -> Result<LocalTargetDisposition, LocalTargetError> {
        validate(target, self.node_id())?;
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let query = format!(
            "SELECT {COLUMNS} FROM local_recovered_targets WHERE target_id = ?1 OR canonical_path = ?2 LIMIT 2"
        );
        let existing = read_targets(
            &transaction,
            &query,
            params![
                target.target_id.as_bytes().as_slice(),
                target.canonical_path
            ],
        )?;
        if !existing.is_empty() {
            return if existing.len() == 1 && existing.first() == Some(target) {
                Ok(LocalTargetDisposition::Replayed)
            } else {
                Err(LocalTargetError::Conflict)
            };
        }
        let (kind, value) = match target.usage_limit {
            StorageUsageLimit::Percent(value) => (1, i64::from(value)),
            StorageUsageLimit::Bytes(value) => (2, integer(value)?),
        };
        transaction.execute(
            &format!("INSERT INTO local_recovered_targets ({COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"),
            params![target.target_id.as_bytes().as_slice(), target.node_id.as_bytes().as_slice(),
                target.mesh_id.as_bytes().as_slice(), target.recovery_id.as_bytes().as_slice(),
                target.state_digest.as_slice(), integer(target.generation)?, target.marker_fingerprint.as_slice(),
                target.canonical_path, target.journal_directory, integer(target.policy_revision.get())?, kind, value],
        )?;
        transaction.commit()?;
        Ok(LocalTargetDisposition::Applied)
    }

    /// Lists the bounded recovered mount set, including providers not yet admitted or reachable.
    ///
    /// # Errors
    /// Rejects malformed/foreign rows, excessive counts and storage failure.
    pub fn local_recovered_targets(&self) -> Result<Vec<LocalRecoveredTarget>, LocalTargetError> {
        let query =
            format!("SELECT {COLUMNS} FROM local_recovered_targets ORDER BY target_id LIMIT 1025");
        let records = read_targets(self.connection(), &query, [])?;
        if records.len() > 1024 {
            return Err(LocalTargetError::Invalid);
        }
        for record in &records {
            validate(record, self.node_id())?;
        }
        Ok(records)
    }

    /// Looks up a recovered mount by its exact local canonical folder bytes.
    ///
    /// # Errors
    /// Rejects malformed/foreign evidence, invalid path length and storage failure.
    pub fn local_recovered_target_by_path(
        &self,
        canonical_path: &[u8],
    ) -> Result<Option<LocalRecoveredTarget>, LocalTargetError> {
        validate_path(canonical_path)?;
        let query = format!(
            "SELECT {COLUMNS} FROM local_recovered_targets WHERE canonical_path = ?1 LIMIT 1"
        );
        let record = read_targets(self.connection(), &query, [canonical_path])?.pop();
        if let Some(record) = &record {
            validate(record, self.node_id())?;
        }
        Ok(record)
    }
}

fn validate(target: &LocalRecoveredTarget, node: NodeId) -> Result<(), LocalTargetError> {
    target
        .usage_limit
        .validate()
        .map_err(|_| LocalTargetError::Invalid)?;
    validate_path(&target.canonical_path)?;
    validate_path(&target.journal_directory)?;
    integer(target.generation)?;
    integer(target.policy_revision.get())?;
    if target.node_id != node
        || target.generation == 0
        || target.policy_revision == Revision::ZERO
        || target.state_digest == [0; 32]
        || target.marker_fingerprint == [0; 32]
    {
        return Err(LocalTargetError::Invalid);
    }
    Ok(())
}

fn validate_path(bytes: &[u8]) -> Result<(), LocalTargetError> {
    if bytes.is_empty() || bytes.len() > 16384 || bytes.contains(&0) {
        Err(LocalTargetError::Invalid)
    } else {
        Ok(())
    }
}

fn read_targets(
    connection: &rusqlite::Connection,
    query: &str,
    parameters: impl rusqlite::Params,
) -> Result<Vec<LocalRecoveredTarget>, LocalTargetError> {
    let mut statement = connection.prepare(query)?;
    let mut rows = statement.query(parameters)?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        records.push(decode(row)?);
    }
    Ok(records)
}

fn decode(row: &Row<'_>) -> Result<LocalRecoveredTarget, LocalTargetError> {
    let usage_limit = match row.get::<_, i64>(10)? {
        1 => StorageUsageLimit::Percent(row.get(11)?),
        2 => StorageUsageLimit::Bytes(unsigned(row, 11)?),
        _ => return Err(LocalTargetError::Invalid),
    };
    Ok(LocalRecoveredTarget {
        target_id: TargetId::from_bytes(bytes(row, 0)?)?,
        node_id: NodeId::from_bytes(bytes(row, 1)?)?,
        mesh_id: MeshId::from_bytes(bytes(row, 2)?)?,
        recovery_id: OperationId::from_bytes(bytes(row, 3)?)?,
        state_digest: bytes(row, 4)?,
        generation: unsigned(row, 5)?,
        marker_fingerprint: bytes(row, 6)?,
        canonical_path: path_bytes(row, 7)?,
        journal_directory: path_bytes(row, 8)?,
        policy_revision: Revision::new(unsigned(row, 9)?),
        usage_limit,
    })
}

fn bytes<const N: usize>(row: &Row<'_>, index: usize) -> Result<[u8; N], LocalTargetError> {
    row.get_ref(index)?
        .as_blob()
        .map_err(|_| LocalTargetError::Invalid)?
        .try_into()
        .map_err(|_| LocalTargetError::Invalid)
}

fn path_bytes(row: &Row<'_>, index: usize) -> Result<Vec<u8>, LocalTargetError> {
    let value = row.get_ref(index)?;
    let bytes = value.as_blob().map_err(|_| LocalTargetError::Invalid)?;
    validate_path(bytes)?;
    Ok(bytes.to_vec())
}

fn integer(value: u64) -> Result<i64, LocalTargetError> {
    i64::try_from(value).map_err(|_| LocalTargetError::Invalid)
}

fn unsigned(row: &Row<'_>, index: usize) -> Result<u64, LocalTargetError> {
    u64::try_from(row.get::<_, i64>(index)?).map_err(|_| LocalTargetError::Invalid)
}

#[cfg(test)]
mod tests;
