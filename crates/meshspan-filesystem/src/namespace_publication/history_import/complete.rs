// SPDX-License-Identifier: GPL-2.0-only

//! Atomic assembly, cross-record validation and publication of one terminal receive session.

use meshspan_domain::UnixMicros;
use rusqlite::{Connection, Transaction, TransactionBehavior, params};

use super::super::federated_admission;
use super::super::history_records::immutable::Decoded;
use super::super::history_records::{
    NamespaceHistoryCommitRecord, NamespaceHistoryImmutableRecord,
};
use super::super::transfer::import::import_history_transaction;
use super::repository::{integer, load_heads, load_session};
use super::{
    NamespaceHistoryMutationDecision, NamespaceHistoryReceiveCompletion,
    NamespaceHistoryReceivePreparation, RECORD_COMMIT, RECORD_IMMUTABLE,
};
use crate::{
    NamespaceHistoryBundle, NamespaceHistoryImport, PublicationDisposition, PublicationError,
};

pub(super) fn run(
    connection: &mut Connection,
    session_id: [u8; 32],
    now: UnixMicros,
    decisions: Option<&[NamespaceHistoryMutationDecision]>,
) -> Result<NamespaceHistoryReceiveCompletion, PublicationError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let session = load_session(&transaction, session_id)?.ok_or(PublicationError::InvalidInput)?;
    let admission_digest = decisions
        .map(federated_admission::decision_set_digest)
        .transpose()?;
    if let Some(import) = session.completion {
        if session.admission_digest != admission_digest {
            return Err(PublicationError::OperationConflict);
        }
        transaction.commit()?;
        return Ok(NamespaceHistoryReceiveCompletion {
            disposition: PublicationDisposition::Replayed,
            import,
        });
    }
    require_ready(&transaction, session_id, now)?;
    let bundle = assemble(&transaction, session_id, session.volume_id)?;
    let import = import_history_transaction(&transaction, &bundle, session.limits, decisions)?;
    store_receipt(&transaction, session_id, now, import, admission_digest)?;
    transaction.commit()?;
    Ok(NamespaceHistoryReceiveCompletion {
        disposition: PublicationDisposition::Applied,
        import,
    })
}

pub(super) fn prepare(
    connection: &Connection,
    session_id: [u8; 32],
    now: UnixMicros,
) -> Result<NamespaceHistoryReceivePreparation, PublicationError> {
    let session = load_session(connection, session_id)?.ok_or(PublicationError::InvalidInput)?;
    if session.completion.is_none() {
        require_ready(connection, session_id, now)?;
    }
    let bundle = assemble(connection, session_id, session.volume_id)?;
    Ok(NamespaceHistoryReceivePreparation::new(
        session.created_at,
        bundle
            .commit_records()
            .map_err(|_| PublicationError::Corrupt)?,
    ))
}

fn require_ready(
    connection: &Connection,
    session_id: [u8; 32],
    now: UnixMicros,
) -> Result<(), PublicationError> {
    let session = load_session(connection, session_id)?.ok_or(PublicationError::InvalidInput)?;
    if now.get() >= session.expires_at.get()
        || !session.terminal
        || session.export_token.is_none()
        || has_missing_objects(connection, session_id)?
    {
        Err(PublicationError::InvalidInput)
    } else {
        Ok(())
    }
}

fn has_missing_objects(
    connection: &Connection,
    session_id: [u8; 32],
) -> Result<bool, PublicationError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM namespace_history_import_records
         WHERE session_id = ?1 AND record_kind = ?2 AND canonical_bytes IS NULL)",
        params![session_id.as_slice(), RECORD_IMMUTABLE],
        |row| row.get::<_, i64>(0),
    )? != 0)
}

fn assemble(
    connection: &Connection,
    session_id: [u8; 32],
    volume_id: meshspan_domain::VolumeId,
) -> Result<NamespaceHistoryBundle, PublicationError> {
    let mut bundle = NamespaceHistoryBundle {
        volume_id,
        heads: load_heads(connection, session_id)?,
        commits: Vec::new(),
        directory_nodes: Vec::new(),
        manifests: Vec::new(),
        file_versions: Vec::new(),
        object_revisions: Vec::new(),
    };
    let mut statement = connection.prepare(
        "SELECT record_kind, record_digest, canonical_bytes
         FROM namespace_history_import_records
         WHERE session_id = ?1 ORDER BY record_ordinal",
    )?;
    let rows = statement.query_map([session_id.as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    for row in rows {
        let (kind, digest, bytes) = row?;
        let expected: [u8; 32] = digest.try_into().map_err(|_| PublicationError::Corrupt)?;
        match kind {
            RECORD_COMMIT => decode_commit(expected, bytes, &mut bundle)?,
            RECORD_IMMUTABLE => decode_immutable(expected, bytes, &mut bundle)?,
            _ => return Err(PublicationError::Corrupt),
        }
    }
    Ok(bundle)
}

fn decode_commit(
    expected: [u8; 32],
    bytes: Vec<u8>,
    bundle: &mut NamespaceHistoryBundle,
) -> Result<(), PublicationError> {
    let record = NamespaceHistoryCommitRecord::from_canonical_bytes(bytes)
        .map_err(|_| PublicationError::Corrupt)?;
    if record.digest() != expected {
        return Err(PublicationError::Corrupt);
    }
    bundle
        .commits
        .push(record.decoded().map_err(|_| PublicationError::Corrupt)?);
    Ok(())
}

fn decode_immutable(
    expected: [u8; 32],
    bytes: Vec<u8>,
    bundle: &mut NamespaceHistoryBundle,
) -> Result<(), PublicationError> {
    let record = NamespaceHistoryImmutableRecord::from_expected_digest(expected, bytes)
        .map_err(|_| PublicationError::Corrupt)?;
    match record.decoded().map_err(|_| PublicationError::Corrupt)? {
        Decoded::DirectoryNode(value) => bundle.directory_nodes.push(value),
        Decoded::Manifest(value) => bundle.manifests.push(value),
        Decoded::FileVersion(value) => bundle.file_versions.push(value),
        Decoded::ObjectRevision(value) => bundle.object_revisions.push(value),
    }
    Ok(())
}

fn store_receipt(
    transaction: &Transaction<'_>,
    session_id: [u8; 32],
    now: UnixMicros,
    import: NamespaceHistoryImport,
    admission_digest: Option<[u8; 32]>,
) -> Result<(), PublicationError> {
    let changed = transaction.execute(
        "UPDATE namespace_history_imports
         SET completed_at = ?2, imported_commits = ?3, supplied_commits = ?4,
             immutable_records = ?5, admission_digest = ?6
         WHERE session_id = ?1 AND completed_at IS NULL",
        params![
            session_id.as_slice(),
            now.get(),
            integer(import.imported_commits)?,
            integer(import.supplied_commits)?,
            integer(import.immutable_records)?,
            admission_digest.as_ref().map(<[u8; 32]>::as_slice)
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(PublicationError::OperationConflict)
    }
}
