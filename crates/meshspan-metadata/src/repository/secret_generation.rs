// SPDX-License-Identifier: GPL-2.0-only

//! Atomic encrypted secret generations and complete recipient envelopes.

use meshspan_domain::{Revision, VolumeId};
use meshspan_secret_envelope::{
    EncryptedSecret, EncryptedSecretParts, MAXIMUM_SECRET_RECIPIENTS, RecipientEnvelopeParts,
    RecipientKeyEnvelope, SecretContext, WrappingPublicKey,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError, recovery_authority};
use crate::{
    CommandContext, CommitSecretGeneration, PartitionDatabase, VOLUME_CONTENT_KEY_SECRET_KIND,
};

const VOLUME_CONTENT_KEY_BYTES: usize = 32;
const AUTHENTICATION_TAG_BYTES: usize = 16;
const RECIPIENT_KIND_NODE: i64 = 1;
const RECIPIENT_KIND_OFFLINE_RECOVERY: i64 = 2;
const CURRENT_STATE: i64 = 1;
const ACTIVE_NODE_STATE: i64 = 2;
const GATEWAY_ROLE_CODE: i64 = 2;
const VERIFIED_RECOVERY_STATE: i64 = 2;

/// One validated persisted encrypted secret and every exact recipient envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretGenerationRecord {
    /// Authenticated encrypted secret bytes.
    pub secret: EncryptedSecret,
    /// Strictly fingerprint-ordered complete recipient set.
    pub recipients: Vec<RecipientKeyEnvelope>,
    /// Revision which committed ciphertext and recipients atomically.
    pub revision: Revision,
}

struct StoredRecipient {
    format_version: i64,
    recipient: Vec<u8>,
    ephemeral: Vec<u8>,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    digest: Vec<u8>,
}

pub(super) fn commit(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CommitSecretGeneration,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let (secret, recipients) = validate(command)?;
    let recovery = recovery_authority::verified_recipient(transaction)?;
    if !recipients.iter().any(|recipient| {
        recipient
            .recipient_fingerprint()
            .is_ok_and(|fingerprint| fingerprint == recovery.key_fingerprint)
            && recipient
                .recipient_public_key()
                .is_ok_and(|public_key| public_key == recovery.public_key)
    }) {
        return Err(RepositoryError::InvalidCommand);
    }
    let secret_context = secret.context();
    let stored_revision = to_i64(revision.get())?;
    insert_secret(
        transaction,
        context,
        command,
        secret_context,
        stored_revision,
    )?;
    for (envelope, parts) in recipients.iter().zip(&command.recipients) {
        insert_recipient(
            transaction,
            context,
            secret_context,
            envelope,
            parts,
            stored_revision,
        )?;
    }
    Ok(EntityReference {
        kind: EntityKind::SecretGeneration,
        id: secret_context.id(),
    })
}

pub(super) fn commit_initial_volume_key(
    transaction: &Transaction<'_>,
    context: CommandContext,
    volume_id: VolumeId,
    command: &CommitSecretGeneration,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let secret_context = command.secret.context;
    if secret_context.kind() != VOLUME_CONTENT_KEY_SECRET_KIND
        || secret_context.id() != volume_id.as_bytes()
        || secret_context.generation() != 1
        || command.secret.ciphertext.len()
            != VOLUME_CONTENT_KEY_BYTES.saturating_add(AUTHENTICATION_TAG_BYTES)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let (_, supplied_recipients) = validate(command)?;
    let expected_recipients = current_volume_key_recipients(transaction)?;
    let supplied_recipients = supplied_recipients
        .iter()
        .map(RecipientKeyEnvelope::recipient_public_key)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RepositoryError::InvalidCommand)?;
    if supplied_recipients != expected_recipients {
        return Err(RepositoryError::InvalidCommand);
    }
    commit(transaction, context, command, revision).map(|_| ())
}

pub(super) fn volume_key_recipients(
    database: &PartitionDatabase,
) -> Result<Vec<WrappingPublicKey>, RepositoryError> {
    current_volume_key_recipients(database.connection())
}

fn current_volume_key_recipients(
    connection: &Connection,
) -> Result<Vec<WrappingPublicKey>, RepositoryError> {
    let active_gateway_count = connection.query_row(
        "SELECT count(*)
         FROM nodes AS node
         JOIN node_roles AS role
           ON role.node_id = node.node_id AND role.role_code = ?1
         WHERE node.state = ?2 AND node.retired_at IS NULL",
        params![GATEWAY_ROLE_CODE, ACTIVE_NODE_STATE],
        |row| row.get::<_, i64>(0),
    )?;
    let active_gateway_count =
        usize::try_from(active_gateway_count).map_err(|_| RepositoryError::CorruptState)?;
    if active_gateway_count == 0
        || active_gateway_count.saturating_add(1) > MAXIMUM_SECRET_RECIPIENTS
    {
        return Err(RepositoryError::CorruptState);
    }
    let mut statement = connection.prepare(
        "SELECT recipient.public_key, recipient.key_fingerprint, recipient.recipient_kind
         FROM secret_wrapping_recipients AS recipient
         LEFT JOIN nodes AS node
           ON recipient.recipient_kind = ?1 AND node.node_id = recipient.owner_id
         LEFT JOIN node_roles AS role
           ON role.node_id = node.node_id AND role.role_code = ?2
         LEFT JOIN node_wrapping_keys AS node_key
           ON recipient.recipient_kind = ?1
          AND node_key.node_id = recipient.owner_id
          AND node_key.generation = recipient.generation
          AND node_key.public_key = recipient.public_key
          AND node_key.key_fingerprint = recipient.key_fingerprint
         LEFT JOIN mesh_recovery_authorities AS recovery
           ON recipient.recipient_kind = ?3
          AND recovery.mesh_id = recipient.owner_id
          AND recovery.recovery_key_fingerprint = recipient.key_fingerprint
         WHERE recipient.state = ?4 AND recipient.retired_at IS NULL
           AND ((recipient.recipient_kind = ?1
                 AND node.state = ?5 AND node.retired_at IS NULL
                 AND role.role_code = ?2
                 AND node_key.state = ?4 AND node_key.retired_at IS NULL)
             OR (recipient.recipient_kind = ?3 AND recovery.state = ?6))
         ORDER BY recipient.key_fingerprint
         LIMIT ?7",
    )?;
    let rows = statement.query_map(
        params![
            RECIPIENT_KIND_NODE,
            GATEWAY_ROLE_CODE,
            RECIPIENT_KIND_OFFLINE_RECOVERY,
            CURRENT_STATE,
            ACTIVE_NODE_STATE,
            VERIFIED_RECOVERY_STATE,
            i64::try_from(MAXIMUM_SECRET_RECIPIENTS.saturating_add(1))
                .map_err(|_| RepositoryError::CorruptState)?,
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    let mut recipients = Vec::new();
    let mut node_count = 0_usize;
    let mut recovery_count = 0_usize;
    for row in rows {
        let (public_key, fingerprint, kind) = row?;
        let public_key = WrappingPublicKey::from_bytes(exact_array(public_key)?)
            .map_err(|_| RepositoryError::CorruptState)?;
        if public_key.fingerprint() != exact_array(fingerprint)? {
            return Err(RepositoryError::CorruptState);
        }
        if kind == RECIPIENT_KIND_OFFLINE_RECOVERY {
            recovery_count = recovery_count.saturating_add(1);
        } else if kind == RECIPIENT_KIND_NODE {
            node_count = node_count.saturating_add(1);
        } else {
            return Err(RepositoryError::CorruptState);
        }
        recipients.push(public_key);
    }
    if recipients.len() > MAXIMUM_SECRET_RECIPIENTS
        || node_count != active_gateway_count
        || recovery_count != 1
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(recipients)
}

pub(super) fn load(
    database: &PartitionDatabase,
    context: SecretContext,
) -> Result<Option<SecretGenerationRecord>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT format_version, nonce, ciphertext, ciphertext_digest, revision
             FROM secret_generations
             WHERE secret_kind = ?1 AND secret_id = ?2 AND generation = ?3",
            secret_identity(context)?,
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((format_version, nonce, ciphertext, digest, revision)) = stored else {
        return Ok(None);
    };
    let secret = EncryptedSecret::from_parts(EncryptedSecretParts {
        format_version: exact_u8(format_version)?,
        context,
        nonce: exact_array(nonce)?,
        ciphertext,
        digest: exact_array(digest)?,
    })
    .map_err(|_| RepositoryError::CorruptState)?;
    let recipients = load_recipients(database, context)?;
    if recipients.is_empty() || recipients.len() > MAXIMUM_SECRET_RECIPIENTS {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(SecretGenerationRecord {
        secret,
        recipients,
        revision: Revision::new(
            u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?,
        ),
    }))
}

pub(super) fn latest_volume_generation(
    database: &PartitionDatabase,
    volume_id: VolumeId,
) -> Result<Option<u64>, RepositoryError> {
    let stored = database.connection().query_row(
        "SELECT MAX(generation)
         FROM secret_generations
         WHERE secret_kind = ?1 AND secret_id = ?2",
        params![
            i64::from(VOLUME_CONTENT_KEY_SECRET_KIND),
            volume_id.as_bytes().as_slice()
        ],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    stored
        .map(|generation| {
            u64::try_from(generation)
                .ok()
                .filter(|value| *value != 0)
                .ok_or(RepositoryError::CorruptState)
        })
        .transpose()
}

fn insert_secret(
    transaction: &Transaction<'_>,
    command_context: CommandContext,
    command: &CommitSecretGeneration,
    secret_context: SecretContext,
    revision: i64,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO secret_generations(
            secret_kind, secret_id, generation, format_version, nonce, ciphertext,
            ciphertext_digest, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            i64::from(secret_context.kind()),
            secret_context.id().as_slice(),
            to_i64(secret_context.generation())?,
            i64::from(command.secret.format_version),
            command.secret.nonce.as_slice(),
            command.secret.ciphertext.as_slice(),
            command.secret.digest.as_slice(),
            command_context.occurred_at.get(),
            revision,
        ],
    )?;
    Ok(())
}

fn insert_recipient(
    transaction: &Transaction<'_>,
    command_context: CommandContext,
    secret_context: SecretContext,
    envelope: &RecipientKeyEnvelope,
    parts: &RecipientEnvelopeParts,
    revision: i64,
) -> Result<(), RepositoryError> {
    let fingerprint = envelope
        .recipient_fingerprint()
        .map_err(|_| RepositoryError::InvalidCommand)?;
    transaction.execute(
        "INSERT INTO secret_recipient_envelopes(
            secret_kind, secret_id, secret_generation, recipient_key_fingerprint,
            format_version, recipient_public_key, ephemeral_public_key, salt, nonce,
            ciphertext, envelope_digest, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            i64::from(secret_context.kind()),
            secret_context.id().as_slice(),
            to_i64(secret_context.generation())?,
            fingerprint.as_slice(),
            i64::from(parts.format_version),
            parts.recipient_public_key.as_slice(),
            parts.ephemeral_public_key.as_slice(),
            parts.salt.as_slice(),
            parts.nonce.as_slice(),
            parts.ciphertext.as_slice(),
            parts.digest.as_slice(),
            command_context.occurred_at.get(),
            revision,
        ],
    )?;
    Ok(())
}

fn load_recipients(
    database: &PartitionDatabase,
    context: SecretContext,
) -> Result<Vec<RecipientKeyEnvelope>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT format_version, recipient_public_key, ephemeral_public_key, salt, nonce,
                ciphertext, envelope_digest
         FROM secret_recipient_envelopes
         WHERE secret_kind = ?1 AND secret_id = ?2 AND secret_generation = ?3
         ORDER BY recipient_key_fingerprint",
    )?;
    let rows = statement.query_map(secret_identity(context)?, |row| {
        Ok(StoredRecipient {
            format_version: row.get(0)?,
            recipient: row.get(1)?,
            ephemeral: row.get(2)?,
            salt: row.get(3)?,
            nonce: row.get(4)?,
            ciphertext: row.get(5)?,
            digest: row.get(6)?,
        })
    })?;
    let mut recipients = Vec::new();
    for row in rows {
        recipients.push(decode_recipient(context, row?)?);
    }
    Ok(recipients)
}

fn decode_recipient(
    context: SecretContext,
    stored: StoredRecipient,
) -> Result<RecipientKeyEnvelope, RepositoryError> {
    RecipientKeyEnvelope::from_parts(RecipientEnvelopeParts {
        format_version: exact_u8(stored.format_version)?,
        context,
        recipient_public_key: exact_array(stored.recipient)?,
        ephemeral_public_key: exact_array(stored.ephemeral)?,
        salt: exact_array(stored.salt)?,
        nonce: exact_array(stored.nonce)?,
        ciphertext: stored.ciphertext,
        digest: exact_array(stored.digest)?,
    })
    .map_err(|_| RepositoryError::CorruptState)
}

fn validate(
    command: &CommitSecretGeneration,
) -> Result<(EncryptedSecret, Vec<RecipientKeyEnvelope>), RepositoryError> {
    let secret = EncryptedSecret::from_parts(command.secret.clone())
        .map_err(|_| RepositoryError::InvalidCommand)?;
    if command.recipients.is_empty() || command.recipients.len() > MAXIMUM_SECRET_RECIPIENTS {
        return Err(RepositoryError::InvalidCommand);
    }
    let mut recipients = Vec::with_capacity(command.recipients.len());
    let mut previous = None;
    for parts in &command.recipients {
        let envelope = RecipientKeyEnvelope::from_parts(parts.clone())
            .map_err(|_| RepositoryError::InvalidCommand)?;
        let fingerprint = envelope
            .recipient_fingerprint()
            .map_err(|_| RepositoryError::InvalidCommand)?;
        if envelope.context() != secret.context()
            || previous.is_some_and(|prior| prior >= fingerprint)
        {
            return Err(RepositoryError::InvalidCommand);
        }
        previous = Some(fingerprint);
        recipients.push(envelope);
    }
    Ok((secret, recipients))
}

fn secret_identity(context: SecretContext) -> Result<(i64, [u8; 16], i64), RepositoryError> {
    Ok((
        i64::from(context.kind()),
        context.id(),
        to_i64(context.generation())?,
    ))
}

fn exact_u8(value: i64) -> Result<u8, RepositoryError> {
    u8::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn exact_array<const LENGTH: usize>(value: Vec<u8>) -> Result<[u8; LENGTH], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}
