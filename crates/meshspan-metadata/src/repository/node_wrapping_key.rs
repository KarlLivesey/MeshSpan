// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative public node wrapping-key generations.

use meshspan_domain::{NodeId, Revision, UnixMicros};
use meshspan_secret_envelope::WrappingPublicKey;
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, PartitionDatabase, RegisterNodeWrappingKey};

const ACTIVE_STATE: u8 = 1;

/// One current public node wrapping-key generation safe for secret envelope creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeWrappingKeyRecord {
    /// Node retaining the matching private key.
    pub node_id: NodeId,
    /// Positive immutable key generation.
    pub generation: u64,
    /// Validated public wrapping key.
    pub public_key: WrappingPublicKey,
    /// Authoritative registration instant.
    pub registered_at: UnixMicros,
    /// Revision which admitted this generation.
    pub revision: Revision,
}

pub(super) fn register(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: RegisterNodeWrappingKey,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let public_key = validate(command)?;
    transaction.execute(
        "INSERT INTO node_wrapping_keys(
            node_id, generation, public_key, key_fingerprint, state, registered_at,
            retired_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
        params![
            command.node_id.as_bytes().as_slice(),
            to_i64(command.generation)?,
            public_key.as_bytes().as_slice(),
            command.key_fingerprint.as_slice(),
            ACTIVE_STATE,
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    transaction.execute(
        "INSERT INTO secret_wrapping_recipients(
            key_fingerprint, recipient_kind, owner_id, generation, public_key, state,
            registered_at, retired_at, revision
         ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
        params![
            command.key_fingerprint.as_slice(),
            command.node_id.as_bytes().as_slice(),
            to_i64(command.generation)?,
            public_key.as_bytes().as_slice(),
            ACTIVE_STATE,
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::NodeWrappingKey,
        id: command.node_id.as_bytes(),
    })
}

pub(super) fn current(
    database: &PartitionDatabase,
    node_id: NodeId,
) -> Result<Option<NodeWrappingKeyRecord>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT generation, public_key, registered_at, revision
             FROM node_wrapping_keys WHERE node_id = ?1 AND state = ?2",
            params![node_id.as_bytes().as_slice(), ACTIVE_STATE],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    stored.map_or(Ok(None), |stored| decode_record(node_id, stored))
}

fn decode_record(
    node_id: NodeId,
    stored: (i64, Vec<u8>, i64, i64),
) -> Result<Option<NodeWrappingKeyRecord>, RepositoryError> {
    let (generation, public_key, registered_at, revision) = stored;
    Ok(Some(NodeWrappingKeyRecord {
        node_id,
        generation: u64::try_from(generation).map_err(|_| RepositoryError::CorruptState)?,
        public_key: WrappingPublicKey::from_bytes(exact_public_key(public_key)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        registered_at: UnixMicros::new(registered_at),
        revision: Revision::new(
            u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?,
        ),
    }))
}

fn validate(command: RegisterNodeWrappingKey) -> Result<WrappingPublicKey, RepositoryError> {
    let public_key = WrappingPublicKey::from_bytes(command.public_key)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    if command.generation == 0 || public_key.fingerprint() != command.key_fingerprint {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(public_key)
    }
}

fn exact_public_key(value: Vec<u8>) -> Result<[u8; 32], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}
