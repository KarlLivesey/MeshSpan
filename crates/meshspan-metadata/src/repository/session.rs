// SPDX-License-Identifier: GPL-2.0-only

//! Mesh-wide authentication-session issuance, factor consumption and revocation.

use meshspan_domain::{
    ApiKeyId, AssuranceLevel, AuthenticationMethodId, AuthenticationMethodKind,
    AuthenticationService, OperationId, PrincipalId, Revision, SessionId, UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::authentication_policy::{self, SessionPolicyEvidence};
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    CommandContext, IssueAuthenticationSession, RevokeAuthenticationSession,
    SessionAuthenticationFactor, SessionClientLabel, StepUpAuthenticationSession,
};

const ACTIVE: i64 = 1;
const MAXIMUM_FACTORS: usize = 8;
const MAXIMUM_CLIENT_LABEL_CHARACTERS: usize = 80;
const MICROS_PER_SECOND: i64 = 1_000_000;

/// Exact durable facts needed to reproduce one API-key session response safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeySessionReplay {
    /// Digest of the original authoritative result receipt.
    pub result_digest: [u8; 32],
    /// Stable session identity bound to the operation.
    pub session_id: SessionId,
    /// User which authenticated the original operation.
    pub principal_id: PrincipalId,
    /// Stored bearer verifier.
    pub token_digest: [u8; 32],
    /// Stored CSRF verifier.
    pub csrf_digest: [u8; 32],
    /// Exact missing, null or value label intent.
    pub client_label: SessionClientLabel,
    /// Exact cookie-persistence intent.
    pub persistent_cookie: bool,
    /// Connector family bound to the session.
    pub service: AuthenticationService,
    /// Original exclusive expiry returned to the caller.
    pub expires_at: UnixMicros,
    /// Explicit revocation instant, when the original session has since been fenced.
    pub revoked_at: Option<UnixMicros>,
    /// Authentication method used by the original operation.
    pub method_id: AuthenticationMethodId,
    /// Credential generation used by the original operation.
    pub credential_generation: u64,
    /// API-key identity used by the original operation.
    pub key_id: ApiKeyId,
}

/// Exact durable facts needed to reproduce one passkey session response safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeySessionReplay {
    /// Digest of the original authoritative result receipt.
    pub result_digest: [u8; 32],
    /// Stable session identity bound to the operation.
    pub session_id: SessionId,
    /// User which authenticated the original operation.
    pub principal_id: PrincipalId,
    /// Stored bearer verifier.
    pub token_digest: [u8; 32],
    /// Stored CSRF verifier.
    pub csrf_digest: [u8; 32],
    /// Exact missing, null or value label intent.
    pub client_label: SessionClientLabel,
    /// Exact cookie-persistence intent.
    pub persistent_cookie: bool,
    /// Connector family bound to the session.
    pub service: AuthenticationService,
    /// Original exclusive expiry returned to the caller.
    pub expires_at: UnixMicros,
    /// Explicit revocation instant, when the original session has since been fenced.
    pub revoked_at: Option<UnixMicros>,
    /// Authentication method used by the original operation.
    pub method_id: AuthenticationMethodId,
    /// Credential generation used by the original operation.
    pub credential_generation: u64,
    /// Opaque passkey credential identity used by the original operation.
    pub credential_id: Vec<u8>,
}

/// Exact durable facts for one session operation independently of its factor combination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationSessionReplay {
    /// Digest of the original authoritative result receipt.
    pub result_digest: [u8; 32],
    /// Stable session identity bound to the operation.
    pub session_id: SessionId,
    /// Source session atomically replaced by this step-up, when applicable.
    pub source_session_id: Option<SessionId>,
    /// User which authenticated the original operation.
    pub principal_id: PrincipalId,
    /// Stored bearer verifier.
    pub token_digest: [u8; 32],
    /// Stored CSRF verifier.
    pub csrf_digest: [u8; 32],
    /// Exact missing, null or value label intent.
    pub client_label: SessionClientLabel,
    /// Exact cookie-persistence intent.
    pub persistent_cookie: bool,
    /// Connector family bound to the session.
    pub service: AuthenticationService,
    /// Assurance derived from the committed factor combination.
    pub assurance: AssuranceLevel,
    /// Original authoritative factor-acceptance instant.
    pub issued_at: UnixMicros,
    /// Original exclusive expiry returned to the caller.
    pub expires_at: UnixMicros,
    /// Explicit revocation instant, when the original session has since been fenced.
    pub revoked_at: Option<UnixMicros>,
    /// Ordered exact factor evidence retained by the committed session.
    pub factors: Vec<AuthenticationSessionReplayFactor>,
}

/// One exact factor retained by a committed session operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationSessionReplayFactor {
    /// Common authentication-method identity.
    pub method_id: AuthenticationMethodId,
    /// Exact credential family.
    pub kind: AuthenticationMethodKind,
    /// Credential generation consumed by the operation.
    pub credential_generation: u64,
    /// Method revision consumed by the operation.
    pub method_revision: Revision,
    /// Family-specific public replay evidence.
    pub credential: AuthenticationSessionReplayCredential,
}

/// Family-specific non-secret evidence needed to validate an exact session retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationSessionReplayCredential {
    /// Opaque passkey credential identity.
    Passkey(Vec<u8>),
    /// Exact TOTP step atomically consumed by the session.
    Totp {
        /// Monotonic RFC 6238 counter accepted by authority.
        accepted_step: u64,
    },
    /// Exact single-use recovery-code identity.
    RecoveryCode(meshspan_domain::RecoveryCodeId),
    /// Exact public API-key identity.
    ApiKey(ApiKeyId),
}

/// Resolves one already-committed session with every ordered factor.
pub(super) fn resolve_session_replay(
    database: &crate::PartitionDatabase,
    operation_id: OperationId,
) -> Result<Option<AuthenticationSessionReplay>, RepositoryError> {
    let Some(receipt) = super::receipt::resolve_operation(database, operation_id)? else {
        return Ok(None);
    };
    if receipt.entity.kind != EntityKind::AuthenticationSession {
        return Err(RepositoryError::OperationConflict);
    }
    let session_id = receipt.entity.id;
    let common = database.connection().query_row(
        "SELECT user_principal_id, token_digest, csrf_digest, client_label_state,
                client_label, persistent_cookie, service, assurance, issued_at,
                expires_at, revoked_at, source_session_id
         FROM authentication_sessions WHERE session_id = ?1",
        [session_id.as_slice()],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?,
            ))
        },
    )?;
    let mut statement = database.connection().prepare(
        "SELECT factor_sequence, method_id, method_kind, credential_generation,
                method_revision, credential_reference, authenticated_at
         FROM authentication_session_factors
         WHERE session_id = ?1 ORDER BY factor_sequence LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            session_id.as_slice(),
            i64::try_from(MAXIMUM_FACTORS + 1).map_err(|_| RepositoryError::CapacityExceeded)?
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, i64>(6)?,
            ))
        },
    )?;
    let mut factors = Vec::new();
    for row in rows {
        let (sequence, method, kind, generation, revision, reference, authenticated_at) = row?;
        if sequence
            != i64::try_from(factors.len() + 1).map_err(|_| RepositoryError::CapacityExceeded)?
            || authenticated_at > common.8
            || (common.11.is_none() && authenticated_at != common.8)
            || factors.len() >= MAXIMUM_FACTORS
        {
            return Err(RepositoryError::CorruptState);
        }
        factors.push(parse_replay_factor(
            method, kind, generation, revision, reference,
        )?);
    }
    if factors.is_empty() || common.9 <= common.8 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(AuthenticationSessionReplay {
        result_digest: receipt.result_digest,
        session_id: SessionId::from_bytes(session_id).map_err(|_| RepositoryError::CorruptState)?,
        source_session_id: common
            .11
            .map(fixed_bytes)
            .transpose()?
            .map(SessionId::from_bytes)
            .transpose()
            .map_err(|_| RepositoryError::CorruptState)?,
        principal_id: PrincipalId::from_bytes(fixed_bytes(common.0)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        token_digest: fixed_bytes(common.1)?,
        csrf_digest: fixed_bytes(common.2)?,
        client_label: parse_client_label(common.3, common.4)?,
        persistent_cookie: parse_boolean(common.5)?,
        service: parse_service(common.6)?,
        assurance: parse_assurance(common.7)?,
        issued_at: UnixMicros::new(common.8),
        expires_at: UnixMicros::new(common.9),
        revoked_at: common.10.map(UnixMicros::new),
        factors,
    }))
}

pub(super) fn resolve_step_up_replay(
    database: &crate::PartitionDatabase,
    operation_id: OperationId,
    expected_source: SessionId,
    source_token_digest: [u8; 32],
    source_csrf_digest: [u8; 32],
) -> Result<Option<AuthenticationSessionReplay>, RepositoryError> {
    if source_token_digest == [0; 32]
        || source_csrf_digest == [0; 32]
        || source_token_digest == source_csrf_digest
    {
        return Ok(None);
    }
    let Some(replay) = resolve_session_replay(database, operation_id)? else {
        return Ok(None);
    };
    if replay.source_session_id != Some(expected_source) {
        return Err(RepositoryError::OperationConflict);
    }
    if replay.revoked_at.is_some() {
        return Err(RepositoryError::OperationConflict);
    }
    let stored: Option<(Vec<u8>, Vec<u8>)> = database
        .connection()
        .query_row(
            "SELECT token_digest, csrf_digest FROM authentication_sessions
             WHERE session_id = ?1",
            [expected_source.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((token, csrf)) = stored else {
        return Err(RepositoryError::CorruptState);
    };
    if fixed_bytes::<32>(token)? != source_token_digest
        || fixed_bytes::<32>(csrf)? != source_csrf_digest
    {
        return Ok(None);
    }
    Ok(Some(replay))
}

fn parse_replay_factor(
    method: Vec<u8>,
    kind: i64,
    generation: i64,
    revision: i64,
    reference: Vec<u8>,
) -> Result<AuthenticationSessionReplayFactor, RepositoryError> {
    let kind = parse_method_kind(kind)?;
    let credential = match kind {
        AuthenticationMethodKind::Passkey if !reference.is_empty() && reference.len() <= 1_024 => {
            AuthenticationSessionReplayCredential::Passkey(reference)
        }
        AuthenticationMethodKind::Totp => AuthenticationSessionReplayCredential::Totp {
            accepted_step: u64::from_be_bytes(fixed_bytes(reference)?),
        },
        AuthenticationMethodKind::RecoveryCode => {
            AuthenticationSessionReplayCredential::RecoveryCode(
                meshspan_domain::RecoveryCodeId::from_bytes(fixed_bytes(reference)?)
                    .map_err(|_| RepositoryError::CorruptState)?,
            )
        }
        AuthenticationMethodKind::ApiKey => AuthenticationSessionReplayCredential::ApiKey(
            ApiKeyId::from_bytes(fixed_bytes(reference)?)
                .map_err(|_| RepositoryError::CorruptState)?,
        ),
        AuthenticationMethodKind::Passkey => return Err(RepositoryError::CorruptState),
    };
    Ok(AuthenticationSessionReplayFactor {
        method_id: AuthenticationMethodId::from_bytes(fixed_bytes(method)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        kind,
        credential_generation: parse_positive(generation)?,
        method_revision: Revision::new(parse_positive(revision)?),
        credential,
    })
}

/// Exact durable result of a self-service session revocation retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionRevocationReplay {
    /// Digest of the original authoritative result receipt.
    pub result_digest: [u8; 32],
    /// Stable session identity revoked by the operation.
    pub session_id: SessionId,
    /// Owning user which performed the self-revocation.
    pub principal_id: PrincipalId,
    /// Authoritative instant at which the session became unusable.
    pub revoked_at: UnixMicros,
}

/// Resolves a committed self-revocation only when all presented evidence identifies it exactly.
pub(super) fn resolve_revocation_replay(
    database: &crate::PartitionDatabase,
    operation_id: OperationId,
    expected_session_id: SessionId,
    token_digest: [u8; 32],
    csrf_digest: [u8; 32],
) -> Result<Option<SessionRevocationReplay>, RepositoryError> {
    let Some(receipt) = super::receipt::resolve_operation(database, operation_id)? else {
        return Ok(None);
    };
    if receipt.entity.kind != EntityKind::AuthenticationSession
        || receipt.entity.id != expected_session_id.as_bytes()
    {
        return Err(RepositoryError::OperationConflict);
    }
    let operation = operation_id.as_bytes();
    let session = expected_session_id.as_bytes();
    let stored = database.connection().query_row(
        "SELECT operation.actor_principal_id, operation.operation_kind,
                operation.started_at, session.user_principal_id, session.token_digest,
                session.csrf_digest, session.revoked_at, session.revision
         FROM operations AS operation
         JOIN authentication_sessions AS session ON session.session_id = ?2
         WHERE operation.operation_id = ?1",
        params![operation.as_slice(), session.as_slice()],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, i64>(7)?,
            ))
        },
    )?;
    let (
        actor,
        operation_kind,
        started_at,
        principal,
        stored_token,
        stored_csrf,
        revoked_at,
        revision,
    ) = stored;
    let revoked_at = revoked_at.ok_or(RepositoryError::OperationConflict)?;
    if operation_kind != 46
        || actor != principal
        || revoked_at != started_at
        || u64::try_from(revision).ok() != Some(receipt.committed_revision.get())
        || !constant_time_equal(&stored_token, &token_digest)
        || !constant_time_equal(&stored_csrf, &csrf_digest)
    {
        return Err(RepositoryError::OperationConflict);
    }
    Ok(Some(SessionRevocationReplay {
        result_digest: receipt.result_digest,
        session_id: expected_session_id,
        principal_id: PrincipalId::from_bytes(fixed_bytes(principal)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        revoked_at: UnixMicros::new(revoked_at),
    }))
}

fn constant_time_equal(stored: &[u8], presented: &[u8; 32]) -> bool {
    stored.len() == presented.len()
        && stored
            .iter()
            .zip(presented)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

/// Resolves one already-committed, single-factor API-key session operation.
pub(super) fn resolve_api_key_replay(
    database: &crate::PartitionDatabase,
    operation_id: OperationId,
) -> Result<Option<ApiKeySessionReplay>, RepositoryError> {
    let Some(receipt) = super::receipt::resolve_operation(database, operation_id)? else {
        return Ok(None);
    };
    if receipt.entity.kind != EntityKind::AuthenticationSession {
        return Err(RepositoryError::OperationConflict);
    }
    let session_id = receipt.entity.id;
    let row = database.connection().query_row(
        "SELECT session.user_principal_id, session.token_digest, session.csrf_digest,
                session.client_label_state, session.client_label, session.persistent_cookie,
                session.service, session.expires_at, session.revoked_at, factor.method_id,
                factor.method_kind,
                factor.credential_generation, factor.credential_reference,
                (SELECT COUNT(*) FROM authentication_session_factors AS counted
                 WHERE counted.session_id = session.session_id)
         FROM authentication_sessions AS session
         JOIN authentication_session_factors AS factor
           ON factor.session_id = session.session_id AND factor.factor_sequence = 1
         WHERE session.session_id = ?1",
        [session_id.as_slice()],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, Vec<u8>>(12)?,
                row.get::<_, i64>(13)?,
            ))
        },
    )?;
    let (
        principal_id,
        token_digest,
        csrf_digest,
        label_state,
        label,
        persistent_cookie,
        service,
        expires_at,
        revoked_at,
        method_id,
        method_kind,
        credential_generation,
        key_id,
        factor_count,
    ) = row;
    if factor_count != 1 || method_kind != AuthenticationMethodKind::ApiKey as i64 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(ApiKeySessionReplay {
        result_digest: receipt.result_digest,
        session_id: SessionId::from_bytes(session_id).map_err(|_| RepositoryError::CorruptState)?,
        principal_id: PrincipalId::from_bytes(fixed_bytes(principal_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        token_digest: fixed_bytes(token_digest)?,
        csrf_digest: fixed_bytes(csrf_digest)?,
        client_label: parse_client_label(label_state, label)?,
        persistent_cookie: parse_boolean(persistent_cookie)?,
        service: parse_service(service)?,
        expires_at: UnixMicros::new(expires_at),
        revoked_at: revoked_at.map(UnixMicros::new),
        method_id: AuthenticationMethodId::from_bytes(fixed_bytes(method_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        credential_generation: parse_positive(credential_generation)?,
        key_id: ApiKeyId::from_bytes(fixed_bytes(key_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
    }))
}

/// Resolves one already-committed, single-factor passkey session operation.
pub(super) fn resolve_passkey_replay(
    database: &crate::PartitionDatabase,
    operation_id: OperationId,
) -> Result<Option<PasskeySessionReplay>, RepositoryError> {
    let Some(receipt) = super::receipt::resolve_operation(database, operation_id)? else {
        return Ok(None);
    };
    if receipt.entity.kind != EntityKind::AuthenticationSession {
        return Err(RepositoryError::OperationConflict);
    }
    let session_id = receipt.entity.id;
    let row = database.connection().query_row(
        "SELECT session.user_principal_id, session.token_digest, session.csrf_digest,
                session.client_label_state, session.client_label, session.persistent_cookie,
                session.service, session.expires_at, session.revoked_at, factor.method_id,
                factor.method_kind, factor.credential_generation, factor.credential_reference,
                (SELECT COUNT(*) FROM authentication_session_factors AS counted
                 WHERE counted.session_id = session.session_id)
         FROM authentication_sessions AS session
         JOIN authentication_session_factors AS factor
           ON factor.session_id = session.session_id AND factor.factor_sequence = 1
         WHERE session.session_id = ?1",
        [session_id.as_slice()],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, Vec<u8>>(12)?,
                row.get::<_, i64>(13)?,
            ))
        },
    )?;
    let (
        principal_id,
        token_digest,
        csrf_digest,
        label_state,
        label,
        persistent_cookie,
        service,
        expires_at,
        revoked_at,
        method_id,
        method_kind,
        credential_generation,
        credential_id,
        factor_count,
    ) = row;
    if factor_count != 1
        || method_kind != AuthenticationMethodKind::Passkey as i64
        || credential_id.is_empty()
        || credential_id.len() > 1_024
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(PasskeySessionReplay {
        result_digest: receipt.result_digest,
        session_id: SessionId::from_bytes(session_id).map_err(|_| RepositoryError::CorruptState)?,
        principal_id: PrincipalId::from_bytes(fixed_bytes(principal_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        token_digest: fixed_bytes(token_digest)?,
        csrf_digest: fixed_bytes(csrf_digest)?,
        client_label: parse_client_label(label_state, label)?,
        persistent_cookie: parse_boolean(persistent_cookie)?,
        service: parse_service(service)?,
        expires_at: UnixMicros::new(expires_at),
        revoked_at: revoked_at.map(UnixMicros::new),
        method_id: AuthenticationMethodId::from_bytes(fixed_bytes(method_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        credential_generation: parse_positive(credential_generation)?,
        credential_id,
    }))
}

fn parse_client_label(
    state: i64,
    value: Option<String>,
) -> Result<SessionClientLabel, RepositoryError> {
    match (state, value) {
        (1, None) => Ok(SessionClientLabel::Missing),
        (2, None) => Ok(SessionClientLabel::Null),
        (3, Some(value)) if !value.is_empty() && value.chars().count() <= 80 => {
            Ok(SessionClientLabel::Value(value))
        }
        _ => Err(RepositoryError::CorruptState),
    }
}

fn fixed_bytes<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

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
            session_id, token_digest, csrf_digest, client_label_state, client_label,
            persistent_cookie,
            user_principal_id, service, assurance, identity_revision, issued_at,
            expires_at, revoked_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, ?13)",
        params![
            session.as_slice(),
            command.token_digest.as_slice(),
            command.csrf_digest.as_slice(),
            client_label_state(&command.client_label),
            client_label_value(&command.client_label),
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

pub(super) fn step_up(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &StepUpAuthenticationSession,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_step_up_shape(command, context)?;
    require_active_user(transaction, command.principal_id.as_bytes())?;
    let source = load_step_up_source(transaction, command, context.occurred_at)?;
    let primary = load_source_primary(transaction, command.source_session_id)?;
    let additional = admit_step_up_factor(transaction, context, command, &source, &primary)?;
    authentication_policy::validate_session_establishment(
        transaction,
        source.service,
        [primary.kind, additional.kind],
        context.occurred_at,
        command.expires_at,
    )?;
    let replacement = step_up_issue_shape(command, &source)?;
    reject_duplicate_session(transaction, &replacement)?;
    insert_step_up_session(transaction, context, command, &source, revision)?;
    persist_step_up_factors(
        transaction,
        context,
        &replacement,
        &primary,
        &command.additional_factor,
        additional,
        revision,
    )?;
    let revoked = transaction.execute(
        "UPDATE authentication_sessions SET revoked_at = ?1, revision = ?2
         WHERE session_id = ?3 AND revoked_at IS NULL AND expires_at > ?1",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.source_session_id.as_bytes().as_slice(),
        ],
    )?;
    if revoked != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(EntityReference {
        kind: EntityKind::AuthenticationSession,
        id: command.replacement_session_id.as_bytes(),
    })
}

struct StepUpSource {
    service: AuthenticationService,
    client_label: SessionClientLabel,
    persistent_cookie: bool,
}

type StoredStepUpSource = (
    Vec<u8>,
    i64,
    i64,
    Option<String>,
    i64,
    i64,
    i64,
    Option<i64>,
);

struct SourcePrimary {
    method_id: AuthenticationMethodId,
    kind: AuthenticationMethodKind,
    credential_reference: Vec<u8>,
    credential_generation: u64,
    method_revision: Revision,
    authenticated_at: UnixMicros,
}

fn validate_step_up_shape(
    command: &StepUpAuthenticationSession,
    context: CommandContext,
) -> Result<(), RepositoryError> {
    if command.source_session_id == command.replacement_session_id
        || command.token_digest == [0; 32]
        || command.csrf_digest == [0; 32]
        || command.token_digest == command.csrf_digest
        || command.expires_at <= context.occurred_at
        || command.additional_factor.method_revision().get() == 0
        || command.additional_factor.credential_generation() == 0
        || matches!(
            command.additional_factor,
            SessionAuthenticationFactor::Passkey { .. }
                | SessionAuthenticationFactor::ApiKey { .. }
        )
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn load_step_up_source(
    transaction: &Transaction<'_>,
    command: &StepUpAuthenticationSession,
    now: UnixMicros,
) -> Result<StepUpSource, RepositoryError> {
    let stored: Option<StoredStepUpSource> = transaction
        .query_row(
            "SELECT user_principal_id, service, client_label_state, client_label,
                        persistent_cookie, issued_at, expires_at, revoked_at
                 FROM authentication_sessions WHERE session_id = ?1",
            [command.source_session_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    let Some((principal, service, label_state, label, persistent, issued, expires, revoked)) =
        stored
    else {
        return Err(RepositoryError::InvalidCommand);
    };
    if principal.as_slice() != command.principal_id.as_bytes().as_slice()
        || issued > now.get()
        || expires <= issued
        || expires <= now.get()
        || revoked.is_some()
        || active_factor_state(transaction, &command.source_session_id.as_bytes(), now)?.is_none()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(StepUpSource {
        service: parse_service(service)?,
        client_label: parse_client_label(label_state, label)?,
        persistent_cookie: parse_boolean(persistent)?,
    })
}

fn load_source_primary(
    transaction: &Transaction<'_>,
    source_session_id: SessionId,
) -> Result<SourcePrimary, RepositoryError> {
    let mut statement = transaction.prepare(
        "SELECT factor.method_id, factor.method_kind, factor.credential_reference,
                factor.credential_generation, method.revision, factor.authenticated_at
         FROM authentication_session_factors AS factor
         JOIN authentication_methods AS method USING(method_id)
         WHERE factor.session_id = ?1 AND factor.method_kind IN (1, 4)
         ORDER BY factor.factor_sequence LIMIT 2",
    )?;
    let rows = statement.query_map([source_session_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
        ))
    })?;
    let records = rows.collect::<Result<Vec<_>, _>>()?;
    let [(method, kind, reference, generation, revision, authenticated_at)] = records.as_slice()
    else {
        return Err(RepositoryError::InvalidCommand);
    };
    Ok(SourcePrimary {
        method_id: AuthenticationMethodId::from_bytes(fixed_bytes(method.clone())?)
            .map_err(|_| RepositoryError::CorruptState)?,
        kind: parse_method_kind(*kind)?,
        credential_reference: reference.clone(),
        credential_generation: parse_positive(*generation)?,
        method_revision: Revision::new(parse_positive(*revision)?),
        authenticated_at: UnixMicros::new(*authenticated_at),
    })
}

fn admit_step_up_factor(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &StepUpAuthenticationSession,
    source: &StepUpSource,
    primary: &SourcePrimary,
) -> Result<AdmittedFactor, RepositoryError> {
    if command.additional_factor.method_id() == primary.method_id {
        return Err(RepositoryError::InvalidCommand);
    }
    let replacement = step_up_issue_shape(command, source)?;
    let stored = load_method(
        transaction,
        command.additional_factor.method_id().as_bytes(),
    )?;
    let kind = validate_method(&stored, context, &replacement, &command.additional_factor)?;
    if kind.is_primary() {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_typed_factor(
        transaction,
        context.occurred_at,
        source.service,
        &command.additional_factor,
        kind,
    )?;
    Ok(AdmittedFactor {
        kind,
        method_revision: Revision::new(parse_positive(stored.revision)?),
    })
}

fn step_up_issue_shape(
    command: &StepUpAuthenticationSession,
    source: &StepUpSource,
) -> Result<IssueAuthenticationSession, RepositoryError> {
    Ok(IssueAuthenticationSession {
        session_id: command.replacement_session_id,
        principal_id: command.principal_id,
        token_digest: command.token_digest,
        csrf_digest: command.csrf_digest,
        client_label: source.client_label.clone(),
        persistent_cookie: source.persistent_cookie,
        service: source.service,
        factors: meshspan_contracts::BoundedItems::new(
            vec![command.additional_factor.clone()],
            MAXIMUM_FACTORS,
        )
        .map_err(|_| RepositoryError::InvalidCommand)?,
        expires_at: command.expires_at,
    })
}

fn insert_step_up_session(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &StepUpAuthenticationSession,
    source: &StepUpSource,
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO authentication_sessions(
            session_id, token_digest, csrf_digest, client_label_state, client_label,
            persistent_cookie, user_principal_id, service, assurance, identity_revision,
            issued_at, expires_at, revoked_at, revision, source_session_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, ?13, ?14)",
        params![
            command.replacement_session_id.as_bytes().as_slice(),
            command.token_digest.as_slice(),
            command.csrf_digest.as_slice(),
            client_label_state(&source.client_label),
            client_label_value(&source.client_label),
            source.persistent_cookie,
            command.principal_id.as_bytes().as_slice(),
            source.service.scope_bit(),
            assurance_code(AssuranceLevel::MultiFactor),
            current_identity_revision(transaction)?,
            context.occurred_at.get(),
            command.expires_at.get(),
            to_i64(revision.get())?,
            command.source_session_id.as_bytes().as_slice(),
        ],
    )?;
    Ok(())
}

fn persist_step_up_factors(
    transaction: &Transaction<'_>,
    context: CommandContext,
    replacement: &IssueAuthenticationSession,
    primary: &SourcePrimary,
    additional: &SessionAuthenticationFactor,
    admitted: AdmittedFactor,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let primary_first = primary.method_id < additional.method_id();
    let primary_index = usize::from(!primary_first);
    let additional_index = usize::from(primary_first);
    persist_copied_primary(transaction, replacement, primary, primary_index, revision)?;
    persist_factor(
        transaction,
        context,
        replacement,
        additional,
        admitted,
        additional_index,
        revision,
    )
}

fn persist_copied_primary(
    transaction: &Transaction<'_>,
    replacement: &IssueAuthenticationSession,
    primary: &SourcePrimary,
    index: usize,
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO authentication_session_factors(
            session_id, factor_sequence, method_id, method_kind, credential_reference,
            credential_generation, method_revision, authenticated_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            replacement.session_id.as_bytes().as_slice(),
            i64::try_from(index + 1).map_err(|_| RepositoryError::CapacityExceeded)?,
            primary.method_id.as_bytes().as_slice(),
            primary.kind as u8,
            primary.credential_reference.as_slice(),
            to_i64(primary.credential_generation)?,
            to_i64(primary.method_revision.get())?,
            primary.authenticated_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
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
        || matches!(&command.client_label, SessionClientLabel::Value(label) if {
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

const fn client_label_state(label: &SessionClientLabel) -> u8 {
    match label {
        SessionClientLabel::Missing => 1,
        SessionClientLabel::Null => 2,
        SessionClientLabel::Value(_) => 3,
    }
}

fn client_label_value(label: &SessionClientLabel) -> Option<&str> {
    match label {
        SessionClientLabel::Missing | SessionClientLabel::Null => None,
        SessionClientLabel::Value(value) => Some(value),
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
        SessionAuthenticationFactor::Totp { accepted_step, .. } => {
            accepted_step.to_be_bytes().to_vec()
        }
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
                method.credential_generation, session.service, session.issued_at,
                session.source_session_id
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
            source_session_id: row.get(14)?,
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
    source_session_id: Option<Vec<u8>>,
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
        || factor.authenticated_at > factor.issued_at
        || (factor.source_session_id.is_none() && factor.authenticated_at != factor.issued_at)
        || factor
            .source_session_id
            .as_ref()
            .is_some_and(|source| source.len() != 16)
        || factor.method_created_at > factor.authenticated_at
        || factor
            .method_expires_at
            .is_some_and(|expiry| expiry <= factor.method_created_at)
        || current_generation < expected_generation
        || !valid_credential_reference(kind, &factor.credential_reference)
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

fn valid_credential_reference(kind: AuthenticationMethodKind, reference: &[u8]) -> bool {
    match kind {
        AuthenticationMethodKind::Passkey => !reference.is_empty() && reference.len() <= 1_024,
        AuthenticationMethodKind::Totp => reference.len() == 8,
        AuthenticationMethodKind::RecoveryCode | AuthenticationMethodKind::ApiKey => {
            reference.len() == 16
        }
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

fn parse_assurance(value: i64) -> Result<AssuranceLevel, RepositoryError> {
    match value {
        1 => Ok(AssuranceLevel::SingleFactor),
        2 => Ok(AssuranceLevel::MultiFactor),
        3 => Ok(AssuranceLevel::RecentStepUp),
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
