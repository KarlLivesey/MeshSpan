// SPDX-License-Identifier: GPL-2.0-only

//! Atomic authoritative lifecycle for protocol-neutral authentication methods.

use meshspan_domain::Revision;
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, CreateApiKeyAuthenticationMethod, RevokeAuthenticationMethod};

const API_KEY_METHOD: i64 = 4;
const ACTIVE: i64 = 1;
const REVOKED: i64 = 3;
const MAXIMUM_LABEL_CHARACTERS: usize = 128;
const MAXIMUM_REASON_CHARACTERS: usize = 1_024;
const MAXIMUM_SERVICE_SCOPE: u8 = 7;

pub(super) fn create_api_key(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateApiKeyAuthenticationMethod,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_creation(context, command)?;
    require_active_user(transaction, command.principal_id.as_bytes())?;
    let method_id = command.method_id.as_bytes();
    let key_id = command.key_id.as_bytes();
    let duplicate: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM authentication_methods WHERE method_id = ?1
            UNION ALL
            SELECT 1 FROM api_keys WHERE key_id = ?2 OR key_digest = ?3
         )",
        params![
            method_id.as_slice(),
            key_id.as_slice(),
            command.key_digest.as_slice(),
        ],
        |row| row.get(0),
    )?;
    if duplicate != 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    let owner = command.principal_id.as_bytes();
    let revision = to_i64(revision.get())?;
    transaction.execute(
        "INSERT INTO authentication_methods(
            method_id, user_principal_id, method_kind, label, service_scope,
            state, created_at, last_used_at, expires_at,
            credential_generation, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, 1, ?9)",
        params![
            method_id.as_slice(),
            owner.as_slice(),
            API_KEY_METHOD,
            command.label,
            command.service_scope,
            ACTIVE,
            context.occurred_at.get(),
            command.valid_until.map(meshspan_domain::UnixMicros::get),
            revision,
        ],
    )?;
    transaction.execute(
        "INSERT INTO api_keys(
            method_id, key_id, key_digest, scopes,
            valid_from, valid_until, last_used_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
        params![
            method_id.as_slice(),
            key_id.as_slice(),
            command.key_digest.as_slice(),
            to_i64(command.scopes)?,
            command.valid_from.get(),
            command.valid_until.map(meshspan_domain::UnixMicros::get),
            revision,
        ],
    )?;
    transaction.execute(
        "INSERT INTO authentication_method_events(
            method_id, event_sequence, event_kind, prior_state, resulting_state,
            reason, changed_by, changed_at, revision
         ) VALUES (?1, 1, 1, NULL, ?2, NULL, ?3, ?4, ?5)",
        params![
            method_id.as_slice(),
            ACTIVE,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            revision,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::AuthenticationMethod,
        id: method_id,
    })
}

pub(super) fn revoke(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RevokeAuthenticationMethod,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_text(&command.reason, MAXIMUM_REASON_CHARACTERS)?;
    let method_id = command.method_id.as_bytes();
    let stored: Option<(Vec<u8>, i64, i64)> = transaction
        .query_row(
            "SELECT user_principal_id, state, created_at
             FROM authentication_methods WHERE method_id = ?1",
            [method_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((owner, state, created_at)) = stored else {
        return Err(RepositoryError::InvalidCommand);
    };
    if owner.as_slice() != command.principal_id.as_bytes()
        || state == REVOKED
        || context.occurred_at.get() < created_at
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let updated = transaction.execute(
        "UPDATE authentication_methods SET state = ?1, revision = ?2
         WHERE method_id = ?3 AND state <> ?1",
        params![REVOKED, to_i64(revision.get())?, method_id.as_slice()],
    )?;
    if updated != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO authentication_method_events(
            method_id, event_sequence, event_kind, prior_state, resulting_state,
            reason, changed_by, changed_at, revision
         ) VALUES (?1, 2, 2, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            method_id.as_slice(),
            state,
            REVOKED,
            command.reason,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::AuthenticationMethod,
        id: method_id,
    })
}

fn validate_creation(
    context: CommandContext,
    command: &CreateApiKeyAuthenticationMethod,
) -> Result<(), RepositoryError> {
    validate_text(&command.label, MAXIMUM_LABEL_CHARACTERS)?;
    if command.service_scope == 0
        || command.service_scope > MAXIMUM_SERVICE_SCOPE
        || command.scopes == 0
        || command.key_digest == [0; 32]
        || command
            .valid_until
            .is_some_and(|end| end <= command.valid_from || end <= context.occurred_at)
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, maximum_characters: usize) -> Result<(), RepositoryError> {
    let count = value.chars().count();
    if count == 0
        || count > maximum_characters
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn require_active_user(
    transaction: &Transaction<'_>,
    principal: [u8; 16],
) -> Result<(), RepositoryError> {
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM users u JOIN principals p ON p.principal_id = u.principal_id
            WHERE u.principal_id = ?1 AND p.state = 1
         )",
        [principal.as_slice()],
        |row| row.get(0),
    )?;
    if exists == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}
