// SPDX-License-Identifier: GPL-2.0-only

//! Durable source-branch delivery; transport never owns the publication's lifetime.

use meshspan_domain::{
    BranchId, FileVersionId, NamespaceCommitId, NodeId, ObjectRevisionId, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::publication::{decode_identifier, from_i64, to_i64};
use crate::{PublicationError, VersionPublicationStore};

/// One published source-branch head awaiting delivery to a particular peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceDelivery {
    /// Monotonic local journal position, not a consensus index or causal clock.
    pub sequence: u64,
    /// Immutable commit whose namespace and content layout must be accepted together.
    pub namespace_commit_id: NamespaceCommitId,
    /// Volume containing the commit.
    pub volume_id: VolumeId,
    /// Exact immutable root advertised to the receiver.
    pub root_object_revision_id: ObjectRevisionId,
    /// File version introduced by this mutation, if it is a file publication.
    pub file_version_id: Option<FileVersionId>,
}

impl VersionPublicationStore {
    /// Returns at most one pending source publication using the indexed peer cursor.
    ///
    /// A new peer starts at the beginning. Failure or process loss does not advance its
    /// cursor; callers must verify the exact remote receipt before acknowledging delivery.
    /// No transaction or provider IO survives this call.
    ///
    /// # Errors
    /// Returns corrupt-state or database failures rather than skipping a publication.
    pub fn next_namespace_delivery(
        &self,
        branch: BranchId,
        peer: NodeId,
    ) -> Result<Option<NamespaceDelivery>, PublicationError> {
        next(&self.connection, branch, peer)
    }

    /// Advances only the next pending delivery after the caller validates remote acceptance.
    /// Exact acknowledgement retries are harmless, including after restart. A stale,
    /// substituted or out-of-order acknowledgement cannot skip pending work.
    ///
    /// # Errors
    /// Returns `OperationConflict` for mismatched receipts and propagates database failures.
    pub fn acknowledge_namespace_delivery(
        &mut self,
        branch: BranchId,
        peer: NodeId,
        delivery: NamespaceDelivery,
    ) -> Result<(), PublicationError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<i64> = transaction.query_row(
            "SELECT delivery_sequence FROM namespace_delivery_cursors WHERE branch_id = ?1 AND peer_node_id = ?2",
            params![branch.as_bytes().as_slice(), peer.as_bytes().as_slice()],
            |row| row.get(0),
        ).optional()?;
        let expected = load(&transaction, branch, delivery.sequence)?;
        if expected != Some(delivery) {
            return Err(PublicationError::OperationConflict);
        }
        if current == Some(to_i64(delivery.sequence)?) {
            return Ok(());
        }
        if next(&transaction, branch, peer)? != Some(delivery) {
            return Err(PublicationError::OperationConflict);
        }
        transaction.execute(
            "INSERT INTO namespace_delivery_cursors(branch_id, peer_node_id, delivery_sequence)
             VALUES (?1, ?2, ?3) ON CONFLICT(branch_id, peer_node_id)
             DO UPDATE SET delivery_sequence = excluded.delivery_sequence",
            params![
                branch.as_bytes().as_slice(),
                peer.as_bytes().as_slice(),
                to_i64(delivery.sequence)?
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

fn next(
    connection: &Connection,
    branch: BranchId,
    peer: NodeId,
) -> Result<Option<NamespaceDelivery>, PublicationError> {
    let sequence: Option<i64> = connection.query_row(
        "SELECT delivery_sequence FROM namespace_delivery_journal
         WHERE branch_id = ?1 AND delivery_sequence > COALESCE(
            (SELECT delivery_sequence FROM namespace_delivery_cursors WHERE branch_id = ?1 AND peer_node_id = ?2), 0)
         ORDER BY delivery_sequence LIMIT 1",
        params![branch.as_bytes().as_slice(), peer.as_bytes().as_slice()],
        |row| row.get(0),
    ).optional()?;
    sequence
        .map(|sequence| {
            load(connection, branch, from_i64(sequence)?)?.ok_or(PublicationError::Corrupt)
        })
        .transpose()
}

fn load(
    connection: &Connection,
    branch: BranchId,
    sequence: u64,
) -> Result<Option<NamespaceDelivery>, PublicationError> {
    type Stored = (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);
    let stored: Option<Stored> = connection.query_row(
        "SELECT c.namespace_commit_id, c.volume_id, c.root_object_revision_id, i.file_version_id
         FROM namespace_delivery_journal AS j
         JOIN namespace_commits AS c ON c.namespace_commit_id = j.namespace_commit_id
         LEFT JOIN namespace_commit_intents AS i ON i.namespace_commit_id = c.namespace_commit_id
         WHERE j.branch_id = ?1 AND j.delivery_sequence = ?2",
        params![branch.as_bytes().as_slice(), to_i64(sequence)?],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional()?;
    stored
        .map(|(commit, volume, root, version)| {
            Ok(NamespaceDelivery {
                sequence,
                namespace_commit_id: decode_identifier(&commit, NamespaceCommitId::from_bytes)?,
                volume_id: decode_identifier(&volume, VolumeId::from_bytes)?,
                root_object_revision_id: decode_identifier(&root, ObjectRevisionId::from_bytes)?,
                file_version_id: version
                    .map(|bytes| decode_identifier(&bytes, FileVersionId::from_bytes))
                    .transpose()?,
            })
        })
        .transpose()
}
