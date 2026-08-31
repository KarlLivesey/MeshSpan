// SPDX-License-Identifier: GPL-2.0-only

//! Atomic authoritative lifecycle for protocol-neutral authentication methods.

use meshspan_domain::{
    ApiKeyId, AuthenticationMethodId, AuthenticationMethodKind, AuthenticationService, OperationId,
    PrincipalId, Revision, UnixMicros,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, RevokeAuthenticationMethod};

const ACTIVE: i64 = 1;
const REVOKED: i64 = 3;
const MAXIMUM_REASON_CHARACTERS: usize = 1_024;
const MAXIMUM_SERVICE_SCOPE: u8 = 7;

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

/// Exact durable facts needed to reproduce one authentication-method revocation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationMethodRevocationReplay {
    /// Original semantic request digest used to reject changed operation reuse.
    pub request_digest: [u8; 32],
    /// Digest of the durable command result.
    pub result_digest: [u8; 32],
    /// Authentication method which was revoked.
    pub method_id: AuthenticationMethodId,
    /// User who owned the method.
    pub principal_id: PrincipalId,
    /// Principal which committed the revocation.
    pub actor_principal_id: PrincipalId,
    /// Original authoritative revocation instant.
    pub revoked_at: UnixMicros,
}

/// Current public verification material for one opaque passkey credential identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyVerificationMaterial {
    /// User account to which the credential is authoritatively bound.
    pub principal_id: PrincipalId,
    /// Common authentication-method identity.
    pub method_id: AuthenticationMethodId,
    /// Credential generation used to fence older ceremonies and sessions.
    pub credential_generation: u64,
    /// Authoritative method revision included in the verification decision.
    pub revision: Revision,
    /// Exact opaque credential identity selected by the browser.
    pub credential_id: Vec<u8>,
    /// COSE algorithm identifier. The initial supported value is ES256 (`-7`).
    pub public_key_algorithm: i32,
    /// Canonical algorithm-specific public-key bytes.
    pub public_key: Vec<u8>,
    /// Last authoritatively committed signature counter.
    pub signature_counter: u64,
    /// Whether the credential is eligible for backup/synchronisation.
    pub backup_eligible: bool,
    /// Last committed backup-state observation.
    pub backup_state: bool,
}

/// Resolves one passkey credential through its unique identity and current authority bounds.
pub(super) fn passkey_verification_material(
    transaction: &rusqlite::Connection,
    credential_id: &[u8],
    service: AuthenticationService,
    now: UnixMicros,
) -> Result<Option<PasskeyVerificationMaterial>, RepositoryError> {
    if credential_id.is_empty() || credential_id.len() > 1_024 {
        return Ok(None);
    }
    let stored = transaction
        .query_row(
            "SELECT method.method_id, method.user_principal_id, method.method_kind,
                    method.service_scope, method.state, method.created_at, method.expires_at,
                    method.credential_generation, method.revision, credential.credential_id,
                    credential.public_key_algorithm, credential.public_key,
                    credential.signature_counter, credential.backup_eligible,
                    credential.backup_state, credential.revision, principal.state
             FROM webauthn_credentials AS credential
             JOIN authentication_methods AS method USING(method_id)
             JOIN principals AS principal ON principal.principal_id = method.user_principal_id
             WHERE credential.credential_id = ?1 LIMIT 2",
            [credential_id],
            |row| {
                Ok(StoredPasskey {
                    method_id: row.get(0)?,
                    principal_id: row.get(1)?,
                    method_kind: row.get(2)?,
                    service_scope: row.get(3)?,
                    method_state: row.get(4)?,
                    created_at: row.get(5)?,
                    expires_at: row.get(6)?,
                    credential_generation: row.get(7)?,
                    method_revision: row.get(8)?,
                    credential_id: row.get(9)?,
                    algorithm: row.get(10)?,
                    public_key: row.get(11)?,
                    signature_counter: row.get(12)?,
                    backup_eligible: row.get(13)?,
                    backup_state: row.get(14)?,
                    credential_revision: row.get(15)?,
                    principal_state: row.get(16)?,
                })
            },
        )
        .optional()?;
    stored
        .map(|stored| validate_passkey_material(stored, service, now))
        .transpose()
        .map(Option::flatten)
}

struct StoredPasskey {
    method_id: Vec<u8>,
    principal_id: Vec<u8>,
    method_kind: i64,
    service_scope: i64,
    method_state: i64,
    created_at: i64,
    expires_at: Option<i64>,
    credential_generation: i64,
    method_revision: i64,
    credential_id: Vec<u8>,
    algorithm: i64,
    public_key: Vec<u8>,
    signature_counter: i64,
    backup_eligible: i64,
    backup_state: i64,
    credential_revision: i64,
    principal_state: i64,
}

fn validate_passkey_material(
    stored: StoredPasskey,
    service: AuthenticationService,
    now: UnixMicros,
) -> Result<Option<PasskeyVerificationMaterial>, RepositoryError> {
    let service_scope = u8::try_from(stored.service_scope)
        .ok()
        .filter(|scope| (1..=MAXIMUM_SERVICE_SCOPE).contains(scope))
        .ok_or(RepositoryError::CorruptState)?;
    let generation = positive_u64(stored.credential_generation)?;
    let method_revision = positive_u64(stored.method_revision)?;
    positive_u64(stored.credential_revision)?;
    let signature_counter =
        u64::try_from(stored.signature_counter).map_err(|_| RepositoryError::CorruptState)?;
    let backup_eligible = boolean(stored.backup_eligible)?;
    let backup_state = boolean(stored.backup_state)?;
    if stored.method_kind != AuthenticationMethodKind::Passkey as i64
        || !(1..=3).contains(&stored.method_state)
        || !(1..=3).contains(&stored.principal_state)
        || stored.algorithm != -7
        || stored.public_key.len() != 65
        || stored.credential_id.is_empty()
        || stored.credential_id.len() > 1_024
        || (backup_state && !backup_eligible)
        || stored
            .expires_at
            .is_some_and(|end| end <= stored.created_at)
    {
        return Err(RepositoryError::CorruptState);
    }
    if stored.method_state != ACTIVE
        || stored.principal_state != ACTIVE
        || service_scope & service.scope_bit() == 0
        || stored.expires_at.is_some_and(|end| now.get() >= end)
    {
        return Ok(None);
    }
    Ok(Some(PasskeyVerificationMaterial {
        principal_id: PrincipalId::from_bytes(fixed(stored.principal_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        method_id: AuthenticationMethodId::from_bytes(fixed(stored.method_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        credential_generation: generation,
        revision: Revision::new(method_revision),
        credential_id: stored.credential_id,
        public_key_algorithm: i32::try_from(stored.algorithm)
            .map_err(|_| RepositoryError::CorruptState)?,
        public_key: stored.public_key,
        signature_counter,
        backup_eligible,
        backup_state,
    }))
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
    if stored.method_kind != AuthenticationMethodKind::ApiKey as i64
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
    let service_allowed = service_scope & service.scope_bit() != 0;
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

fn boolean(value: i64) -> Result<bool, RepositoryError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RepositoryError::CorruptState),
    }
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

pub(super) fn resolve_revocation_replay(
    database: &crate::PartitionDatabase,
    operation_id: OperationId,
) -> Result<Option<AuthenticationMethodRevocationReplay>, RepositoryError> {
    let Some(receipt) = super::receipt::resolve_operation(database, operation_id)? else {
        return Ok(None);
    };
    if receipt.entity.kind != EntityKind::AuthenticationMethod {
        return Err(RepositoryError::OperationConflict);
    }
    let operation = operation_id.as_bytes();
    let method = receipt.entity.id;
    let stored = database
        .connection()
        .query_row(
            "SELECT operation.actor_principal_id, operation.operation_kind,
                    operation.started_at, method.user_principal_id, method.state,
                    method.revision, event.changed_by, event.changed_at, event.revision
             FROM operations AS operation
             JOIN authentication_methods AS method ON method.method_id = ?2
             JOIN authentication_method_events AS event
               ON event.method_id = method.method_id AND event.event_sequence = 2
             WHERE operation.operation_id = ?1",
            params![operation.as_slice(), method.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    let (
        actor,
        operation_kind,
        started_at,
        principal,
        state,
        method_revision,
        changed_by,
        changed_at,
        event_revision,
    ) = stored;
    if operation_kind != 75
        || state != REVOKED
        || actor != changed_by
        || started_at != changed_at
        || method_revision != event_revision
        || u64::try_from(method_revision).ok() != Some(receipt.committed_revision.get())
    {
        return Err(RepositoryError::OperationConflict);
    }
    Ok(Some(AuthenticationMethodRevocationReplay {
        request_digest: receipt.request_digest,
        result_digest: receipt.result_digest,
        method_id: AuthenticationMethodId::from_bytes(method)
            .map_err(|_| RepositoryError::CorruptState)?,
        principal_id: PrincipalId::from_bytes(fixed(principal)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        actor_principal_id: PrincipalId::from_bytes(fixed(actor)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        revoked_at: UnixMicros::new(changed_at),
    }))
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
