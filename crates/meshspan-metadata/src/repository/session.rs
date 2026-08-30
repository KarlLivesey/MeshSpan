// SPDX-License-Identifier: GPL-2.0-only

//! Mesh-wide authentication-session issuance, factor consumption and revocation.

use meshspan_domain::{
    AssuranceLevel, AuthenticationMethodKind, AuthenticationService, Revision, UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::authentication_policy::{self, SessionPolicyEvidence};
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    CommandContext, IssueAuthenticationSession, RevokeAuthenticationSession,
    SessionAuthenticationFactor,
};

const ACTIVE: i64 = 1;
const MAXIMUM_FACTORS: usize = 8;
const MAXIMUM_CLIENT_LABEL_CHARACTERS: usize = 80;
const MICROS_PER_SECOND: i64 = 1_000_000;

pub(super) fn issue(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &IssueAuthenticationSession,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_session_shape(command, context.occurred_at)?;
    require_active_user(transaction, command.principal_id.as_bytes())?;
    let admitted = admit_factors(transaction, context, command)?;
    if !admitted.iter().any(|factor| factor.kind.is_primary()) {
        return Err(RepositoryError::InvalidCommand);
    }
    authentication_policy::validate_session_establishment(
        transaction,
        command.service,
        admitted.iter().map(|factor| factor.kind),
        context.occurred_at,
        command.expires_at,
    )?;
    reject_duplicate_session(transaction, command)?;
    let identity_revision = current_identity_revision(transaction)?;
    let session = command.session_id.as_bytes();
    transaction.execute(
        "INSERT INTO authentication_sessions(
            session_id, token_digest, csrf_digest, client_label, persistent_cookie,
            user_principal_id, service, assurance, identity_revision, issued_at,
            expires_at, revoked_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, ?12)",
        params![
            session.as_slice(),
            command.token_digest.as_slice(),
            command.csrf_digest.as_slice(),
            command.client_label,
            command.persistent_cookie,
            command.principal_id.as_bytes().as_slice(),
            command.service.scope_bit(),
            assurance_code(derived_assurance(&admitted)),
            identity_revision,
            context.occurred_at.get(),
            command.expires_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    for (index, (factor, admitted)) in command.factors.as_slice().iter().zip(&admitted).enumerate()
    {
        persist_factor(
            transaction,
            context,
            command,
            factor,
            *admitted,
            index,
            revision,
        )?;
    }
    Ok(EntityReference {
        kind: EntityKind::AuthenticationSession,
        id: session,
    })
}

#[derive(Clone, Copy)]
struct AdmittedFactor {
    kind: AuthenticationMethodKind,
    method_revision: Revision,
}

fn admit_factors(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &IssueAuthenticationSession,
) -> Result<Vec<AdmittedFactor>, RepositoryError> {
    let mut admitted = Vec::with_capacity(command.factors.len());
    let mut previous = None;
    for factor in command.factors.as_slice() {
        let method_id = factor.method_id();
        if previous.is_some_and(|value| value >= method_id) {
            return Err(RepositoryError::InvalidCommand);
        }
        previous = Some(method_id);
        let stored = load_method(transaction, method_id.as_bytes())?;
        let kind = validate_method(&stored, context, command, factor)?;
        validate_typed_factor(
            transaction,
            context.occurred_at,
            command.service,
            factor,
            kind,
        )?;
        admitted.push(AdmittedFactor {
            kind,
            method_revision: Revision::new(parse_positive(stored.revision)?),
        });
    }
    Ok(admitted)
}

struct StoredMethod {
    principal_id: Vec<u8>,
    kind: i64,
    service_scope: i64,
    state: i64,
    created_at: i64,
    last_used_at: Option<i64>,
    expires_at: Option<i64>,
    credential_generation: i64,
    revision: i64,
}

fn load_method(
    transaction: &Transaction<'_>,
    method_id: [u8; 16],
) -> Result<StoredMethod, RepositoryError> {
    transaction
        .query_row(
            "SELECT user_principal_id, method_kind, service_scope, state,
                    created_at, last_used_at, expires_at, credential_generation, revision
             FROM authentication_methods WHERE method_id = ?1",
            [method_id.as_slice()],
            |row| {
                Ok(StoredMethod {
                    principal_id: row.get(0)?,
                    kind: row.get(1)?,
                    service_scope: row.get(2)?,
                    state: row.get(3)?,
                    created_at: row.get(4)?,
                    last_used_at: row.get(5)?,
                    expires_at: row.get(6)?,
                    credential_generation: row.get(7)?,
                    revision: row.get(8)?,
                })
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)
}

fn validate_method(
    stored: &StoredMethod,
    context: CommandContext,
    command: &IssueAuthenticationSession,
    factor: &SessionAuthenticationFactor,
) -> Result<AuthenticationMethodKind, RepositoryError> {
    let kind = parse_method_kind(stored.kind)?;
    let scope = u8::try_from(stored.service_scope)
        .ok()
        .filter(|value| (1..=7).contains(value))
        .ok_or(RepositoryError::CorruptState)?;
    let generation = parse_positive(stored.credential_generation)?;
    let method_revision = parse_positive(stored.revision)?;
    if !(1..=3).contains(&stored.state)
        || stored
            .expires_at
            .is_some_and(|expiry| expiry <= stored.created_at)
        || stored.last_used_at.is_some_and(|used| {
            used < stored.created_at || stored.expires_at.is_some_and(|expiry| used >= expiry)
        })
    {
        return Err(RepositoryError::CorruptState);
    }
    let principal = command.principal_id.as_bytes();
    if stored.principal_id.as_slice() != principal
        || stored.state != ACTIVE
        || scope & command.service.scope_bit() == 0
        || stored.created_at > context.occurred_at.get()
        || stored
            .expires_at
            .is_some_and(|expiry| context.occurred_at.get() >= expiry)
        || generation != factor.credential_generation()
        || method_revision != factor.method_revision().get()
        || kind != factor_kind(factor)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(kind)
}

fn validate_typed_factor(
    transaction: &Transaction<'_>,
    now: UnixMicros,
    service: AuthenticationService,
    factor: &SessionAuthenticationFactor,
    kind: AuthenticationMethodKind,
) -> Result<(), RepositoryError> {
    match factor {
        SessionAuthenticationFactor::Passkey {
            method_id,
            credential_id,
            signature_counter,
            backup_state,
            ..
        } => validate_passkey(
            transaction,
            method_id.as_bytes(),
            credential_id,
            *signature_counter,
            *backup_state,
        ),
        SessionAuthenticationFactor::Totp {
            method_id,
            accepted_step,
            ..
        } => validate_totp(transaction, method_id.as_bytes(), *accepted_step, now),
        SessionAuthenticationFactor::RecoveryCode {
            method_id, code_id, ..
        } => validate_recovery_code(transaction, method_id.as_bytes(), code_id.as_bytes(), now),
        SessionAuthenticationFactor::ApiKey {
            method_id, key_id, ..
        } => validate_api_key(
            transaction,
            method_id.as_bytes(),
            key_id.as_bytes(),
            service,
            now,
        ),
    }?;
    if kind == factor_kind(factor) {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_passkey(
    transaction: &Transaction<'_>,
    method_id: [u8; 16],
    credential_id: &[u8],
    new_counter: u64,
    new_backup_state: bool,
) -> Result<(), RepositoryError> {
    let stored: Option<(i64, i64, i64)> = transaction
        .query_row(
            "SELECT signature_counter, backup_eligible, backup_state
             FROM webauthn_credentials WHERE method_id = ?1 AND credential_id = ?2",
            params![method_id.as_slice(), credential_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((counter, eligible, backup_state)) = stored else {
        return Err(RepositoryError::InvalidCommand);
    };
    let counter = u64::try_from(counter).map_err(|_| RepositoryError::CorruptState)?;
    let eligible = parse_boolean(eligible)?;
    parse_boolean(backup_state)?;
    if credential_id.is_empty()
        || credential_id.len() > 1_024
        || i64::try_from(new_counter).is_err()
        || (counter > 0 && new_counter <= counter)
        || (new_backup_state && !eligible)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn validate_totp(
    transaction: &Transaction<'_>,
    method_id: [u8; 16],
    accepted_step: u64,
    now: UnixMicros,
) -> Result<(), RepositoryError> {
    let stored: Option<(i64, i64, Option<i64>)> = transaction
        .query_row(
            "SELECT period_seconds, accepted_step_window, last_accepted_step
             FROM totp_credentials WHERE method_id = ?1",
            [method_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((period, window, previous)) = stored else {
        return Err(RepositoryError::InvalidCommand);
    };
    let period = u64::try_from(period)
        .ok()
        .filter(|value| (15..=300).contains(value))
        .ok_or(RepositoryError::CorruptState)?;
    let window = u64::try_from(window)
        .ok()
        .filter(|value| *value <= 10)
        .ok_or(RepositoryError::CorruptState)?;
    let now_seconds = u64::try_from(now.get()).map_err(|_| RepositoryError::InvalidCommand)?
        / u64::try_from(MICROS_PER_SECOND).map_err(|_| RepositoryError::CorruptState)?;
    let current_step = now_seconds / period;
    let distance = current_step.abs_diff(accepted_step);
    let previous = previous
        .map(u64::try_from)
        .transpose()
        .map_err(|_| RepositoryError::CorruptState)?;
    if distance > window
        || i64::try_from(accepted_step).is_err()
        || previous.is_some_and(|value| accepted_step <= value)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn validate_recovery_code(
    transaction: &Transaction<'_>,
    method_id: [u8; 16],
    code_id: [u8; 16],
    now: UnixMicros,
) -> Result<(), RepositoryError> {
    let stored: Option<(i64, Option<i64>)> = transaction
        .query_row(
            "SELECT created_at, used_at FROM recovery_codes
             WHERE method_id = ?1 AND code_id = ?2",
            params![method_id.as_slice(), code_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match stored {
        Some((created_at, None)) if created_at <= now.get() => Ok(()),
        Some((created_at, Some(used_at))) if used_at < created_at => {
            Err(RepositoryError::CorruptState)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn validate_api_key(
    transaction: &Transaction<'_>,
    method_id: [u8; 16],
    key_id: [u8; 16],
    service: AuthenticationService,
    now: UnixMicros,
) -> Result<(), RepositoryError> {
    let stored: Option<(i64, i64, Option<i64>, Option<i64>)> = transaction
        .query_row(
            "SELECT scopes, valid_from, valid_until, last_used_at
             FROM api_keys WHERE method_id = ?1 AND key_id = ?2",
            params![method_id.as_slice(), key_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((scopes, valid_from, valid_until, last_used_at)) = stored else {
        return Err(RepositoryError::InvalidCommand);
    };
    let scopes = parse_positive(scopes)?;
    if valid_until.is_some_and(|end| end <= valid_from)
        || last_used_at
            .is_some_and(|used| used < valid_from || valid_until.is_some_and(|end| used >= end))
    {
        return Err(RepositoryError::CorruptState);
    }
    if scopes & service.api_key_login_scope() == 0
        || now.get() < valid_from
        || valid_until.is_some_and(|end| now.get() >= end)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn persist_factor(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &IssueAuthenticationSession,
    factor: &SessionAuthenticationFactor,
    admitted: AdmittedFactor,
    index: usize,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let sequence = i64::try_from(index + 1).map_err(|_| RepositoryError::CapacityExceeded)?;
    let session = command.session_id.as_bytes();
    let reference = credential_reference(factor);
    transaction.execute(
        "INSERT INTO authentication_session_factors(
            session_id, factor_sequence, method_id, method_kind, credential_reference,
            credential_generation, method_revision, authenticated_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            session.as_slice(),
            sequence,
            factor.method_id().as_bytes().as_slice(),
            admitted.kind as u8,
            reference.as_slice(),
            to_i64(factor.credential_generation())?,
            to_i64(admitted.method_revision.get())?,
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    advance_credential(transaction, context.occurred_at, factor, revision)?;
    let updated = transaction.execute(
        "UPDATE authentication_methods SET last_used_at = ?1, revision = ?2
         WHERE method_id = ?3 AND revision = ?4",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            factor.method_id().as_bytes().as_slice(),
            to_i64(admitted.method_revision.get())?,
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn advance_credential(
    transaction: &Transaction<'_>,
    now: UnixMicros,
    factor: &SessionAuthenticationFactor,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let updated = match factor {
        SessionAuthenticationFactor::Passkey {
            method_id,
            credential_id,
            signature_counter,
            backup_state,
            ..
        } => transaction.execute(
            "UPDATE webauthn_credentials
             SET signature_counter = ?1, backup_state = ?2, revision = ?3
             WHERE method_id = ?4 AND credential_id = ?5",
            params![
                to_i64(*signature_counter)?,
                backup_state,
                to_i64(revision.get())?,
                method_id.as_bytes().as_slice(),
                credential_id,
            ],
        )?,
        SessionAuthenticationFactor::Totp {
            method_id,
            accepted_step,
            ..
        } => transaction.execute(
            "UPDATE totp_credentials SET last_accepted_step = ?1, revision = ?2
             WHERE method_id = ?3",
            params![
                to_i64(*accepted_step)?,
                to_i64(revision.get())?,
                method_id.as_bytes().as_slice(),
            ],
        )?,
        SessionAuthenticationFactor::RecoveryCode {
            method_id, code_id, ..
        } => transaction.execute(
            "UPDATE recovery_codes SET used_at = ?1, revision = ?2
             WHERE method_id = ?3 AND code_id = ?4 AND used_at IS NULL",
            params![
                now.get(),
                to_i64(revision.get())?,
                method_id.as_bytes().as_slice(),
                code_id.as_bytes().as_slice(),
            ],
        )?,
        SessionAuthenticationFactor::ApiKey {
            method_id, key_id, ..
        } => transaction.execute(
            "UPDATE api_keys SET last_used_at = ?1, revision = ?2
             WHERE method_id = ?3 AND key_id = ?4",
            params![
                now.get(),
                to_i64(revision.get())?,
                method_id.as_bytes().as_slice(),
                key_id.as_bytes().as_slice(),
            ],
        )?,
    };
    if updated == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn reject_duplicate_session(
    transaction: &Transaction<'_>,
    command: &IssueAuthenticationSession,
) -> Result<(), RepositoryError> {
    let duplicate: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM authentication_sessions
            WHERE session_id = ?1 OR token_digest = ?2 OR csrf_digest = ?3
         )",
        params![
            command.session_id.as_bytes().as_slice(),
            command.token_digest.as_slice(),
            command.csrf_digest.as_slice()
        ],
        |row| row.get(0),
    )?;
    if duplicate == 0 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn current_identity_revision(transaction: &Transaction<'_>) -> Result<i64, RepositoryError> {
    let revision =
        transaction.query_row("SELECT identity_revision FROM meshes LIMIT 2", [], |row| {
            row.get::<_, i64>(0)
        })?;
    parse_positive(revision)?;
    Ok(revision)
}

fn validate_session_shape(
    command: &IssueAuthenticationSession,
    now: UnixMicros,
) -> Result<(), RepositoryError> {
    if command.token_digest == [0; 32]
        || command.csrf_digest == [0; 32]
        || command.token_digest == command.csrf_digest
        || command.client_label.as_ref().is_some_and(|label| {
            let characters = label.chars().count();
            characters == 0
                || characters > MAXIMUM_CLIENT_LABEL_CHARACTERS
                || label.trim() != label
                || label.chars().any(char::is_control)
        })
        || command.expires_at <= now
        || command.factors.is_empty()
        || command.factors.len() > MAXIMUM_FACTORS
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
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

fn derived_assurance(factors: &[AdmittedFactor]) -> AssuranceLevel {
    let has_primary = factors.iter().any(|factor| factor.kind.is_primary());
    let has_additional = factors.iter().any(|factor| !factor.kind.is_primary());
    if has_primary && has_additional {
        AssuranceLevel::MultiFactor
    } else {
        AssuranceLevel::SingleFactor
    }
}

const fn assurance_code(assurance: AssuranceLevel) -> u8 {
    match assurance {
        AssuranceLevel::SingleFactor => 1,
        AssuranceLevel::MultiFactor => 2,
        AssuranceLevel::RecentStepUp => 3,
    }
}

const fn factor_kind(factor: &SessionAuthenticationFactor) -> AuthenticationMethodKind {
    match factor {
        SessionAuthenticationFactor::Passkey { .. } => AuthenticationMethodKind::Passkey,
        SessionAuthenticationFactor::Totp { .. } => AuthenticationMethodKind::Totp,
        SessionAuthenticationFactor::RecoveryCode { .. } => AuthenticationMethodKind::RecoveryCode,
        SessionAuthenticationFactor::ApiKey { .. } => AuthenticationMethodKind::ApiKey,
    }
}

fn credential_reference(factor: &SessionAuthenticationFactor) -> Vec<u8> {
    match factor {
        SessionAuthenticationFactor::Passkey { credential_id, .. } => credential_id.clone(),
        SessionAuthenticationFactor::Totp { method_id, .. } => method_id.as_bytes().to_vec(),
        SessionAuthenticationFactor::RecoveryCode { code_id, .. } => code_id.as_bytes().to_vec(),
        SessionAuthenticationFactor::ApiKey { key_id, .. } => key_id.as_bytes().to_vec(),
    }
}

/// Current derived factor state for one otherwise live session.
#[derive(Clone, Copy)]
pub(super) struct SessionFactorState {
    /// Assurance derived from current typed factor classes.
    pub(super) assurance: AssuranceLevel,
    /// Connector family bound to the session.
    pub(super) service: AuthenticationService,
    /// Union of exact current factor classes.
    pub(super) factor_classes: u8,
    /// Number of distinct current methods retained by the session.
    pub(super) factor_count: u8,
    /// Authoritative session-creation instant.
    pub(super) issued_at: UnixMicros,
    /// Instant of the most recently accepted factor.
    pub(super) latest_authenticated_at: UnixMicros,
}

/// Revalidates every retained method and exact credential reference at request time.
pub(super) fn active_factor_state(
    connection: &Connection,
    session_id: &[u8],
    now: UnixMicros,
) -> Result<Option<SessionFactorState>, RepositoryError> {
    let mut statement = connection.prepare(
        "SELECT factor.factor_sequence, factor.method_kind, factor.credential_reference,
                factor.credential_generation, factor.authenticated_at,
                method.method_kind, method.user_principal_id = session.user_principal_id,
                method.service_scope, method.state, method.created_at, method.expires_at,
                method.credential_generation, session.service, session.issued_at
         FROM authentication_session_factors AS factor
         JOIN authentication_sessions AS session USING(session_id)
         JOIN authentication_methods AS method USING(method_id)
         WHERE factor.session_id = ?1 ORDER BY factor.factor_sequence",
    )?;
    let rows = statement.query_map([session_id], |row| {
        Ok(StoredSessionFactor {
            sequence: row.get(0)?,
            factor_kind: row.get(1)?,
            credential_reference: row.get(2)?,
            expected_generation: row.get(3)?,
            authenticated_at: row.get(4)?,
            method_kind: row.get(5)?,
            owner_matches: row.get(6)?,
            service_scope: row.get(7)?,
            method_state: row.get(8)?,
            method_created_at: row.get(9)?,
            method_expires_at: row.get(10)?,
            current_generation: row.get(11)?,
            service: row.get(12)?,
            issued_at: row.get(13)?,
        })
    })?;
    let mut factors = Vec::new();
    for row in rows {
        factors.push(row?);
        if factors.len() > MAXIMUM_FACTORS {
            return Err(RepositoryError::CorruptState);
        }
    }
    validate_current_factors(connection, session_id, &factors, now)
}

struct StoredSessionFactor {
    sequence: i64,
    factor_kind: i64,
    credential_reference: Vec<u8>,
    expected_generation: i64,
    authenticated_at: i64,
    method_kind: i64,
    owner_matches: i64,
    service_scope: i64,
    method_state: i64,
    method_created_at: i64,
    method_expires_at: Option<i64>,
    current_generation: i64,
    service: i64,
    issued_at: i64,
}

fn validate_current_factors(
    connection: &Connection,
    session_id: &[u8],
    factors: &[StoredSessionFactor],
    now: UnixMicros,
) -> Result<Option<SessionFactorState>, RepositoryError> {
    if factors.is_empty() {
        return Err(RepositoryError::CorruptState);
    }
    let mut has_primary = false;
    let mut has_additional = false;
    let mut factor_classes = 0_u8;
    let mut latest = i64::MIN;
    for (index, factor) in factors.iter().enumerate() {
        let expected_sequence =
            i64::try_from(index + 1).map_err(|_| RepositoryError::CapacityExceeded)?;
        let kind = validate_factor_shape(factor, expected_sequence)?;
        if !factor_is_current(connection, session_id, factor, kind, now)? {
            return Ok(None);
        }
        has_primary |= kind.is_primary();
        has_additional |= !kind.is_primary();
        factor_classes |= kind.class_bit();
        latest = latest.max(factor.authenticated_at);
    }
    if !has_primary || latest == i64::MIN {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(SessionFactorState {
        assurance: if has_additional {
            AssuranceLevel::MultiFactor
        } else {
            AssuranceLevel::SingleFactor
        },
        service: parse_service(factors[0].service)?,
        factor_classes,
        factor_count: u8::try_from(factors.len()).map_err(|_| RepositoryError::CorruptState)?,
        issued_at: UnixMicros::new(factors[0].issued_at),
        latest_authenticated_at: UnixMicros::new(latest),
    }))
}

fn validate_factor_shape(
    factor: &StoredSessionFactor,
    expected_sequence: i64,
) -> Result<AuthenticationMethodKind, RepositoryError> {
    let kind = parse_method_kind(factor.factor_kind)?;
    let service = u8::try_from(factor.service)
        .ok()
        .filter(|value| matches!(*value, 1 | 2 | 4))
        .ok_or(RepositoryError::CorruptState)?;
    let scope = u8::try_from(factor.service_scope)
        .ok()
        .filter(|value| (1..=7).contains(value))
        .ok_or(RepositoryError::CorruptState)?;
    let expected_generation = parse_positive(factor.expected_generation)?;
    let current_generation = parse_positive(factor.current_generation)?;
    if factor.sequence != expected_sequence
        || factor.method_kind != factor.factor_kind
        || factor.owner_matches != 1
        || !(1..=3).contains(&factor.method_state)
        || factor.authenticated_at != factor.issued_at
        || factor.method_created_at > factor.authenticated_at
        || factor
            .method_expires_at
            .is_some_and(|expiry| expiry <= factor.method_created_at)
        || current_generation < expected_generation
        || factor.credential_reference.is_empty()
        || factor.credential_reference.len() > 1_024
    {
        return Err(RepositoryError::CorruptState);
    }
    if scope & service == 0 || current_generation != expected_generation {
        return Ok(kind);
    }
    Ok(kind)
}

fn factor_is_current(
    connection: &Connection,
    session_id: &[u8],
    factor: &StoredSessionFactor,
    kind: AuthenticationMethodKind,
    now: UnixMicros,
) -> Result<bool, RepositoryError> {
    let current_generation = parse_positive(factor.current_generation)?;
    let expected_generation = parse_positive(factor.expected_generation)?;
    let service = u8::try_from(factor.service).map_err(|_| RepositoryError::CorruptState)?;
    let scope = u8::try_from(factor.service_scope).map_err(|_| RepositoryError::CorruptState)?;
    if factor.method_state != ACTIVE
        || current_generation != expected_generation
        || scope & service == 0
        || factor
            .method_expires_at
            .is_some_and(|expiry| now.get() >= expiry)
    {
        return Ok(false);
    }
    validate_current_credential(connection, session_id, factor, kind, now)
}

fn validate_current_credential(
    connection: &Connection,
    session_id: &[u8],
    factor: &StoredSessionFactor,
    kind: AuthenticationMethodKind,
    now: UnixMicros,
) -> Result<bool, RepositoryError> {
    let exact_exists: i64 = match kind {
        AuthenticationMethodKind::Passkey => connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM authentication_session_factors AS factor
                JOIN webauthn_credentials AS credential USING(method_id)
                WHERE factor.session_id = ?1 AND factor.factor_sequence = ?2
                  AND credential.credential_id = factor.credential_reference
             )",
            params![session_id, factor.sequence],
            |row| row.get(0),
        )?,
        AuthenticationMethodKind::Totp => connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM authentication_session_factors AS factor
                JOIN totp_credentials AS credential USING(method_id)
                WHERE factor.session_id = ?1 AND factor.factor_sequence = ?2
                  AND factor.credential_reference = factor.method_id
             )",
            params![session_id, factor.sequence],
            |row| row.get(0),
        )?,
        AuthenticationMethodKind::RecoveryCode => connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM authentication_session_factors AS factor
                JOIN recovery_codes AS credential USING(method_id)
                WHERE factor.session_id = ?1 AND factor.factor_sequence = ?2
                  AND credential.code_id = factor.credential_reference
                  AND credential.used_at = factor.authenticated_at
             )",
            params![session_id, factor.sequence],
            |row| row.get(0),
        )?,
        AuthenticationMethodKind::ApiKey => connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM authentication_session_factors AS factor
                JOIN api_keys AS credential USING(method_id)
                WHERE factor.session_id = ?1 AND factor.factor_sequence = ?2
                  AND credential.key_id = factor.credential_reference
             )",
            params![session_id, factor.sequence],
            |row| row.get(0),
        )?,
    };
    if exact_exists != 1 {
        return Err(RepositoryError::CorruptState);
    }
    if kind != AuthenticationMethodKind::ApiKey {
        return Ok(true);
    }
    let current: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM authentication_session_factors AS factor
            JOIN authentication_sessions AS session USING(session_id)
            JOIN api_keys AS credential USING(method_id)
            WHERE factor.session_id = ?1 AND factor.factor_sequence = ?2
              AND credential.key_id = factor.credential_reference
              AND (credential.scopes & session.service) = session.service
              AND credential.valid_from <= ?3
              AND (credential.valid_until IS NULL OR credential.valid_until > ?3)
         )",
        params![session_id, factor.sequence, now.get()],
        |row| row.get(0),
    )?;
    match current {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RepositoryError::CorruptState),
    }
}

/// Applies current service/operation policy to exact session evidence.
pub(super) fn meets_assurance(
    connection: &Connection,
    factors: SessionFactorState,
    required: AssuranceLevel,
    now: UnixMicros,
) -> Result<bool, RepositoryError> {
    authentication_policy::permits_operation(
        connection,
        factors.service,
        required,
        SessionPolicyEvidence {
            assurance: factors.assurance,
            factor_classes: factors.factor_classes,
            factor_count: factors.factor_count,
            issued_at: factors.issued_at,
            latest_authenticated_at: factors.latest_authenticated_at,
        },
        now,
    )
}

fn parse_service(value: i64) -> Result<AuthenticationService, RepositoryError> {
    match value {
        1 => Ok(AuthenticationService::Https),
        2 => Ok(AuthenticationService::HeadlessApi),
        4 => Ok(AuthenticationService::Smb),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_method_kind(value: i64) -> Result<AuthenticationMethodKind, RepositoryError> {
    match value {
        1 => Ok(AuthenticationMethodKind::Passkey),
        2 => Ok(AuthenticationMethodKind::Totp),
        3 => Ok(AuthenticationMethodKind::RecoveryCode),
        4 => Ok(AuthenticationMethodKind::ApiKey),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_positive(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::CorruptState)
}

fn parse_boolean(value: i64) -> Result<bool, RepositoryError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RepositoryError::CorruptState),
    }
}
