// SPDX-License-Identifier: GPL-2.0-only

//! Reuse canonical secret/envelope persistence inside an open offline recovery projection.

use super::{insert_recipient, insert_secret, secret_identity, validate};
use crate::repository::apply::to_i64;
use crate::{CommitSecretGeneration, RepositoryError};
use meshspan_domain::{Revision, UnixMicros};
use rusqlite::{OptionalExtension as _, Transaction, params};

pub(in crate::repository) fn install(
    transaction: &Transaction<'_>,
    command: &CommitSecretGeneration,
    created_at: UnixMicros,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let permitted: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM partition_recovery_node_key_projection
         WHERE completed = 0 AND projected_at = ?1 AND reserved_revision = ?2)",
        params![created_at.get(), to_i64(revision.get())?],
        |row| row.get(0),
    )?;
    if !permitted {
        return Err(RepositoryError::InvalidCommand);
    }
    let (secret, recipients) = validate(command)?;
    let identity = secret.context();
    let existing: Option<bool> = transaction.query_row(
        "SELECT format_version = ?4 AND nonce = ?5 AND ciphertext = ?6 AND ciphertext_digest = ?7
         FROM secret_generations WHERE secret_kind = ?1 AND secret_id = ?2 AND generation = ?3",
        params![identity.kind(), identity.id().as_slice(), to_i64(identity.generation())?,
            command.secret.format_version, command.secret.nonce.as_slice(), &command.secret.ciphertext,
            command.secret.digest.as_slice()], |row| row.get(0)).optional()?;
    let stored_revision = to_i64(revision.get())?;
    match existing {
        Some(false) => return Err(RepositoryError::OperationConflict),
        Some(true) => {}
        None => insert_secret(transaction, created_at, command, identity, stored_revision)?,
    }
    // Retained ciphertext never changes. Replace its complete recipient set atomically;
    // retaining all retired envelopes would grow beyond the bounded recipient contract.
    transaction.execute(
        "DELETE FROM secret_recipient_envelopes
        WHERE secret_kind = ?1 AND secret_id = ?2 AND secret_generation = ?3",
        secret_identity(identity)?,
    )?;
    for (envelope, parts) in recipients.iter().zip(&command.recipients) {
        insert_recipient(
            transaction,
            created_at,
            identity,
            envelope,
            parts,
            stored_revision,
        )?;
    }
    Ok(())
}
