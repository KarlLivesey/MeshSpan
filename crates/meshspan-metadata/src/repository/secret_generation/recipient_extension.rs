// SPDX-License-Identifier: GPL-2.0-only

//! Additive gateway access to historical volume keys, without changing encrypted file versions.

use super::{current_volume_key_recipients, insert_recipient, secret_identity, to_i64, validate};
use crate::repository::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, CommitSecretGeneration, VOLUME_CONTENT_KEY_SECRET_KIND};
use meshspan_domain::Revision;
use meshspan_secret_envelope::MAXIMUM_SECRET_RECIPIENTS;
use rusqlite::{OptionalExtension, Transaction, params};

pub(in crate::repository) fn extend_volume_recipients(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CommitSecretGeneration,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let (secret, recipients) = validate(command)?;
    let identity = secret.context();
    if identity.kind() != VOLUME_CONTENT_KEY_SECRET_KIND {
        return Err(RepositoryError::InvalidCommand);
    }
    let original: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT ciphertext_digest FROM secret_generations
         WHERE secret_kind = ?1 AND secret_id = ?2 AND generation = ?3",
            secret_identity(identity)?,
            |row| row.get(0),
        )
        .optional()?;
    if original.as_deref() != Some(command.secret.digest.as_slice()) {
        return Err(RepositoryError::OperationConflict);
    }
    let current = current_volume_key_recipients(transaction)?;
    for (envelope, parts) in recipients.iter().zip(&command.recipients) {
        let recipient = envelope
            .recipient_public_key()
            .map_err(|_| RepositoryError::InvalidCommand)?;
        if !current.contains(&recipient) {
            return Err(RepositoryError::InvalidCommand);
        }
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT envelope_digest FROM secret_recipient_envelopes
             WHERE secret_kind = ?1 AND secret_id = ?2 AND secret_generation = ?3
             AND recipient_key_fingerprint = ?4",
                params![
                    identity.kind(),
                    identity.id().as_slice(),
                    to_i64(identity.generation())?,
                    recipient.fingerprint().as_slice()
                ],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(digest) if digest == parts.digest => {}
            Some(_) => return Err(RepositoryError::OperationConflict),
            None => insert_recipient(
                transaction,
                context.occurred_at,
                identity,
                envelope,
                parts,
                to_i64(revision.get())?,
            )?,
        }
    }
    let count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM secret_recipient_envelopes
         WHERE secret_kind = ?1 AND secret_id = ?2 AND secret_generation = ?3",
        secret_identity(identity)?,
        |row| row.get(0),
    )?;
    if usize::try_from(count).map_err(|_| RepositoryError::CorruptState)?
        > MAXIMUM_SECRET_RECIPIENTS
    {
        return Err(RepositoryError::CapacityExceeded);
    }
    Ok(EntityReference {
        kind: EntityKind::SecretGeneration,
        id: identity.id(),
    })
}
