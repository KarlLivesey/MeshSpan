// SPDX-License-Identifier: GPL-2.0-only

//! Atomic authoritative lifecycle for protocol-neutral authentication methods.

use meshspan_domain::{ApiKeyId, AuthenticationMethodId, PrincipalId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, RevokeAuthenticationMethod};

const API_KEY_METHOD: i64 = 4;
const ACTIVE: i64 = 1;
const REVOKED: i64 = 3;
const MAXIMUM_REASON_CHARACTERS: usize = 1_024;
const MAXIMUM_SERVICE_SCOPE: u8 = 7;

/// One connector family against which an API key may authenticate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthenticationService {
    /// Browser and direct HTTPS file/application access.
    Https = 1,
    /// Headless public administration and data API access.
    HeadlessApi = 2,
    /// Embedded SMB 3.1.1 session establishment.
    Smb = 4,
}

/// Validated active API-key authority without its secret or verifier digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyAuthentication {
    /// User authenticated by the key.
    pub principal_id: PrincipalId,
    /// Common authentication-method identity.
    pub method_id: AuthenticationMethodId,
    /// Public API-key identity.
    pub key_id: ApiKeyId,
    /// Complete least-privilege capability bitset carried by the key.
    pub scopes: u64,
    /// Credential generation used to fence older derived sessions.
    pub credential_generation: u64,
    /// Authoritative method revision included in the decision.
    pub revision: Revision,
}

/// Resolves one verifier digest through its unique index and evaluates all current bounds.
pub(super) fn authenticate_api_key(
    transaction: &rusqlite::Connection,
    presented_key_digest: [u8; 32],
    service: AuthenticationService,
    required_scopes: u64,
    now: UnixMicros,
) -> Result<Option<ApiKeyAuthentication>, RepositoryError> {
    if presented_key_digest == [0; 32] || required_scopes == 0 {
        return Ok(None);
    }
    let stored = transaction
        .query_row(
            "SELECT method.method_id, key.key_id, method.user_principal_id,
                    method.method_kind, method.service_scope, method.state,
                    method.created_at, method.expires_at, method.credential_generation,
                    method.revision, key.scopes, key.valid_from, key.valid_until,
                    key.last_used_at, key.revision, principal.state
             FROM api_keys AS key
             JOIN authentication_methods AS method ON method.method_id = key.method_id
             JOIN principals AS principal ON principal.principal_id = method.user_principal_id
             WHERE key.key_digest = ?1 LIMIT 2",
            [presented_key_digest.as_slice()],
            |row| {
                Ok(StoredApiKey {
                    method_id: row.get(0)?,
                    key_id: row.get(1)?,
                    principal_id: row.get(2)?,
                    method_kind: row.get(3)?,
                    service_scope: row.get(4)?,
                    method_state: row.get(5)?,
                    created_at: row.get(6)?,
                    method_expires_at: row.get(7)?,
                    credential_generation: row.get(8)?,
                    method_revision: row.get(9)?,
                    scopes: row.get(10)?,
                    valid_from: row.get(11)?,
                    valid_until: row.get(12)?,
                    last_used_at: row.get(13)?,
                    key_revision: row.get(14)?,
                    principal_state: row.get(15)?,
                })
            },
        )
        .optional()?;
    stored
        .map(|stored| validate_authentication(stored, service, required_scopes, now))
        .transpose()
        .map(Option::flatten)
}

struct StoredApiKey {
    method_id: Vec<u8>,
    key_id: Vec<u8>,
    principal_id: Vec<u8>,
    method_kind: i64,
    service_scope: i64,
    method_state: i64,
    created_at: i64,
    method_expires_at: Option<i64>,
    credential_generation: i64,
    method_revision: i64,
    scopes: i64,
    valid_from: i64,
    valid_until: Option<i64>,
    last_used_at: Option<i64>,
    key_revision: i64,
    principal_state: i64,
}

fn validate_authentication(
    stored: StoredApiKey,
    service: AuthenticationService,
    required_scopes: u64,
    now: UnixMicros,
) -> Result<Option<ApiKeyAuthentication>, RepositoryError> {
    let service_scope = u8::try_from(stored.service_scope)
        .ok()
        .filter(|scope| (1..=MAXIMUM_SERVICE_SCOPE).contains(scope))
        .ok_or(RepositoryError::CorruptState)?;
    let scopes = positive_u64(stored.scopes)?;
    let generation = positive_u64(stored.credential_generation)?;
    let method_revision = positive_u64(stored.method_revision)?;
    positive_u64(stored.key_revision)?;
    if stored.method_kind != API_KEY_METHOD
        || !(1..=3).contains(&stored.method_state)
        || !(1..=3).contains(&stored.principal_state)
        || stored
            .valid_until
            .is_some_and(|end| end <= stored.valid_from)
        || stored
            .method_expires_at
            .is_some_and(|end| end <= stored.created_at)
        || stored.last_used_at.is_some_and(|used| {
            used < stored.valid_from || stored.valid_until.is_some_and(|end| used >= end)
        })
    {
        return Err(RepositoryError::CorruptState);
    }
    let service_allowed = service_scope & service as u8 != 0;
    let scopes_allowed = scopes & required_scopes == required_scopes;
    let time_allowed = now.get() >= stored.valid_from
        && stored.valid_until.is_none_or(|end| now.get() < end)
        && stored.method_expires_at.is_none_or(|end| now.get() < end);
    if stored.method_state != ACTIVE
        || stored.principal_state != ACTIVE
        || !service_allowed
        || !scopes_allowed
        || !time_allowed
    {
        return Ok(None);
    }
    Ok(Some(ApiKeyAuthentication {
        principal_id: PrincipalId::from_bytes(fixed(stored.principal_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        method_id: AuthenticationMethodId::from_bytes(fixed(stored.method_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        key_id: ApiKeyId::from_bytes(fixed(stored.key_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        scopes,
        credential_generation: generation,
        revision: Revision::new(method_revision),
    }))
}

fn positive_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::CorruptState)
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
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
