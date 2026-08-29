// SPDX-License-Identifier: GPL-2.0-only

//! Mesh-wide authentication-session issuance and revocation.

use meshspan_domain::{AssuranceLevel, Revision};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, IssueAuthenticationSession, RevokeAuthenticationSession};

pub(super) fn issue(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: IssueAuthenticationSession,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.token_digest == [0; 32] || command.expires_at <= context.occurred_at {
        return Err(RepositoryError::InvalidCommand);
    }
    require_active_user(transaction, command.principal_id.as_bytes())?;
    let session = command.session_id.as_bytes();
    let duplicate: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM authentication_sessions
            WHERE session_id = ?1 OR token_digest = ?2
         )",
        params![session.as_slice(), command.token_digest.as_slice()],
        |row| row.get(0),
    )?;
    if duplicate != 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    let identity_revision =
        transaction.query_row("SELECT identity_revision FROM meshes LIMIT 2", [], |row| {
            row.get::<_, i64>(0)
        })?;
    if identity_revision <= 0 {
        return Err(RepositoryError::CorruptState);
    }
    let principal = command.principal_id.as_bytes();
    transaction.execute(
        "INSERT INTO authentication_sessions(
            session_id, token_digest, user_principal_id, assurance, identity_revision,
            issued_at, expires_at, revoked_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
        params![
            session.as_slice(),
            command.token_digest.as_slice(),
            principal.as_slice(),
            assurance_code(command.assurance),
            identity_revision,
            context.occurred_at.get(),
            command.expires_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::AuthenticationSession,
        id: session,
    })
}

pub(super) fn revoke(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: RevokeAuthenticationSession,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let session = command.session_id.as_bytes();
    let principal = command.principal_id.as_bytes();
    let stored: Option<(Vec<u8>, i64, Option<i64>)> = transaction
        .query_row(
            "SELECT user_principal_id, issued_at, revoked_at
             FROM authentication_sessions WHERE session_id = ?1",
            [session.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((owner, issued_at, revoked_at)) = stored else {
        return Err(RepositoryError::InvalidCommand);
    };
    if owner.as_slice() != principal
        || revoked_at.is_some()
        || context.occurred_at.get() < issued_at
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let updated = transaction.execute(
        "UPDATE authentication_sessions SET revoked_at = ?1, revision = ?2
         WHERE session_id = ?3 AND revoked_at IS NULL",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            session.as_slice(),
        ],
    )?;
    if updated != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(EntityReference {
        kind: EntityKind::AuthenticationSession,
        id: session,
    })
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

const fn assurance_code(assurance: AssuranceLevel) -> u8 {
    match assurance {
        AssuranceLevel::SingleFactor => 1,
        AssuranceLevel::MultiFactor => 2,
        AssuranceLevel::RecentStepUp => 3,
    }
}
