// SPDX-License-Identifier: GPL-2.0-only

//! Indexed, secret-free current-user authentication-method inventory.

use meshspan_domain::{
    ApiKeyId, AuthenticationMethodId, AuthenticationMethodKind, PrincipalId, Revision, UnixMicros,
};
use rusqlite::params;

use super::{Page, PageLimit, RepositoryError};
use crate::PartitionDatabase;

/// Stable authentication-method seek cursor bound to one principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationMethodCursor {
    principal_id: PrincipalId,
    state: u8,
    kind: AuthenticationMethodKind,
    method_id: AuthenticationMethodId,
}

impl AuthenticationMethodCursor {
    /// Reconstructs one cursor after a public boundary validates every field.
    #[must_use]
    pub const fn new(
        principal_id: PrincipalId,
        state: u8,
        kind: AuthenticationMethodKind,
        method_id: AuthenticationMethodId,
    ) -> Self {
        Self {
            principal_id,
            state,
            kind,
            method_id,
        }
    }

    /// Returns the principal to which this continuation belongs.
    #[must_use]
    pub const fn principal_id(self) -> PrincipalId {
        self.principal_id
    }

    /// Returns the lifecycle sort key.
    #[must_use]
    pub const fn state(self) -> u8 {
        self.state
    }

    /// Returns the method-kind sort key.
    #[must_use]
    pub const fn kind(self) -> AuthenticationMethodKind {
        self.kind
    }

    /// Returns the final method-identity sort key.
    #[must_use]
    pub const fn method_id(self) -> AuthenticationMethodId {
        self.method_id
    }
}

/// Method-specific public facts with all credential material omitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationMethodRecordDetails {
    /// One passkey's current backup properties.
    Passkey {
        /// Whether the authenticator permits credential backup.
        backup_eligible: bool,
        /// Last authoritatively observed backup state.
        backup_state: bool,
    },
    /// One encrypted TOTP seed.
    Totp,
    /// One recovery-code set.
    RecoveryCodes {
        /// Number of codes not yet consumed.
        remaining_codes: u8,
    },
    /// One API key without its digest or secret.
    ApiKey {
        /// Public key identity.
        key_id: ApiKeyId,
        /// Exact connector-scope bits.
        scopes: u64,
        /// Inclusive first accepted instant.
        valid_from: UnixMicros,
    },
}

/// Secret-free authoritative authentication-method projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationMethodRecord {
    /// Owning user.
    pub principal_id: PrincipalId,
    /// Stable common method identity.
    pub method_id: AuthenticationMethodId,
    /// Method family.
    pub kind: AuthenticationMethodKind,
    /// User-facing label.
    pub label: String,
    /// Service-scope bitset.
    pub service_scope: u8,
    /// Lifecycle code: active 1, suspended 2 or revoked 3.
    pub state: u8,
    /// Original creation instant.
    pub created_at: UnixMicros,
    /// Last successful use.
    pub last_used_at: Option<UnixMicros>,
    /// Exclusive method expiry.
    pub expires_at: Option<UnixMicros>,
    /// Last authoritative revision.
    pub revision: Revision,
    /// Method-specific secret-free facts.
    pub details: AuthenticationMethodRecordDetails,
}

pub(super) fn authentication_methods(
    database: &PartitionDatabase,
    principal_id: PrincipalId,
    after: Option<AuthenticationMethodCursor>,
    limit: PageLimit,
) -> Result<Page<AuthenticationMethodRecord, AuthenticationMethodCursor>, RepositoryError> {
    let lower = lower_bound(principal_id, after)?;
    let principal = principal_id.as_bytes();
    let mut statement = database.connection().prepare(
        "SELECT method.method_id, method.method_kind, method.label, method.service_scope,
                method.state, method.created_at, method.last_used_at, method.expires_at,
                method.revision,
                (SELECT count(*) FROM webauthn_credentials AS passkey
                 WHERE passkey.method_id = method.method_id),
                (SELECT passkey.backup_eligible FROM webauthn_credentials AS passkey
                 WHERE passkey.method_id = method.method_id LIMIT 1),
                (SELECT passkey.backup_state FROM webauthn_credentials AS passkey
                 WHERE passkey.method_id = method.method_id LIMIT 1),
                (SELECT count(*) FROM totp_credentials AS totp
                 WHERE totp.method_id = method.method_id),
                (SELECT count(*) FROM recovery_codes AS recovery
                 WHERE recovery.method_id = method.method_id),
                (SELECT count(*) FROM recovery_codes AS recovery
                 WHERE recovery.method_id = method.method_id AND recovery.used_at IS NULL),
                (SELECT count(*) FROM api_keys AS api_key
                 WHERE api_key.method_id = method.method_id),
                (SELECT api_key.key_id FROM api_keys AS api_key
                 WHERE api_key.method_id = method.method_id LIMIT 1),
                (SELECT api_key.scopes FROM api_keys AS api_key
                 WHERE api_key.method_id = method.method_id LIMIT 1),
                (SELECT api_key.valid_from FROM api_keys AS api_key
                 WHERE api_key.method_id = method.method_id LIMIT 1)
         FROM authentication_methods AS method INDEXED BY authentication_methods_by_user
         WHERE method.user_principal_id = ?1
           AND (method.state, method.method_kind, method.method_id) > (?2, ?3, ?4)
         ORDER BY method.state, method.method_kind, method.method_id LIMIT ?5",
    )?;
    let rows = statement.query_map(
        params![
            principal.as_slice(),
            lower.state,
            lower.kind,
            lower.method_id.as_slice(),
            sql_limit(limit)?
        ],
        stored_row,
    )?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        items.push(parse_record(principal_id, row?)?);
    }
    let next = (items.len() > limit.get()).then(|| cursor(&items[limit.get() - 1]));
    items.truncate(limit.get());
    Ok(Page { items, next })
}

struct LowerBound {
    state: u8,
    kind: u8,
    method_id: [u8; 16],
}

fn lower_bound(
    principal_id: PrincipalId,
    after: Option<AuthenticationMethodCursor>,
) -> Result<LowerBound, RepositoryError> {
    match after {
        Some(cursor) if cursor.principal_id == principal_id && (1..=3).contains(&cursor.state) => {
            Ok(LowerBound {
                state: cursor.state,
                kind: cursor.kind as u8,
                method_id: cursor.method_id.as_bytes(),
            })
        }
        Some(_) => Err(RepositoryError::StaleRevision),
        None => Ok(LowerBound {
            state: 0,
            kind: 0,
            method_id: [0; 16],
        }),
    }
}

#[derive(Debug)]
struct StoredRow {
    method_id: Vec<u8>,
    method_kind: i64,
    label: String,
    service_scope: i64,
    state: i64,
    created_at: i64,
    last_used_at: Option<i64>,
    expires_at: Option<i64>,
    revision: i64,
    passkey_count: i64,
    backup_eligible: Option<i64>,
    backup_state: Option<i64>,
    totp_count: i64,
    recovery_count: i64,
    remaining_recovery_count: i64,
    api_key_count: i64,
    api_key_id: Option<Vec<u8>>,
    api_key_scopes: Option<i64>,
    api_key_valid_from: Option<i64>,
}

fn stored_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredRow> {
    Ok(StoredRow {
        method_id: row.get(0)?,
        method_kind: row.get(1)?,
        label: row.get(2)?,
        service_scope: row.get(3)?,
        state: row.get(4)?,
        created_at: row.get(5)?,
        last_used_at: row.get(6)?,
        expires_at: row.get(7)?,
        revision: row.get(8)?,
        passkey_count: row.get(9)?,
        backup_eligible: row.get(10)?,
        backup_state: row.get(11)?,
        totp_count: row.get(12)?,
        recovery_count: row.get(13)?,
        remaining_recovery_count: row.get(14)?,
        api_key_count: row.get(15)?,
        api_key_id: row.get(16)?,
        api_key_scopes: row.get(17)?,
        api_key_valid_from: row.get(18)?,
    })
}

fn parse_record(
    principal_id: PrincipalId,
    row: StoredRow,
) -> Result<AuthenticationMethodRecord, RepositoryError> {
    let method_id = AuthenticationMethodId::from_bytes(fixed(&row.method_id)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let kind = parse_kind(row.method_kind)?;
    let service_scope = parse_service_scope(row.service_scope)?;
    let state = u8::try_from(row.state).map_err(|_| RepositoryError::CorruptState)?;
    let created_at = valid_instant(row.created_at)?;
    let last_used_at = row.last_used_at.map(valid_instant).transpose()?;
    let expires_at = row.expires_at.map(valid_instant).transpose()?;
    let revision = Revision::new(parse_positive_u64(row.revision)?);
    if !(1..=3).contains(&state)
        || row.label.is_empty()
        || row.label.chars().count() > 128
        || row.label.chars().any(char::is_control)
        || last_used_at.is_some_and(|last| last < created_at)
        || expires_at.is_some_and(|expiry| expiry <= created_at)
        || last_used_at.is_some_and(|last| expires_at.is_some_and(|expiry| last >= expiry))
    {
        return Err(RepositoryError::CorruptState);
    }
    let details = parse_details(kind, service_scope, &row)?;
    Ok(AuthenticationMethodRecord {
        principal_id,
        method_id,
        kind,
        label: row.label,
        service_scope,
        state,
        created_at,
        last_used_at,
        expires_at,
        revision,
        details,
    })
}

fn parse_details(
    kind: AuthenticationMethodKind,
    service_scope: u8,
    row: &StoredRow,
) -> Result<AuthenticationMethodRecordDetails, RepositoryError> {
    match kind {
        AuthenticationMethodKind::Passkey
            if row.passkey_count == 1
                && row.totp_count == 0
                && row.recovery_count == 0
                && row.api_key_count == 0
                && service_scope & 4 == 0 =>
        {
            Ok(AuthenticationMethodRecordDetails::Passkey {
                backup_eligible: parse_bool(row.backup_eligible)?,
                backup_state: parse_bool(row.backup_state)?,
            })
        }
        AuthenticationMethodKind::Totp
            if row.passkey_count == 0
                && row.totp_count == 1
                && row.recovery_count == 0
                && row.api_key_count == 0
                && service_scope & 4 == 0 =>
        {
            Ok(AuthenticationMethodRecordDetails::Totp)
        }
        AuthenticationMethodKind::RecoveryCode
            if row.passkey_count == 0
                && row.totp_count == 0
                && (1..=64).contains(&row.recovery_count)
                && (0..=row.recovery_count).contains(&row.remaining_recovery_count)
                && row.api_key_count == 0
                && service_scope & 4 == 0 =>
        {
            Ok(AuthenticationMethodRecordDetails::RecoveryCodes {
                remaining_codes: u8::try_from(row.remaining_recovery_count)
                    .map_err(|_| RepositoryError::CorruptState)?,
            })
        }
        AuthenticationMethodKind::ApiKey
            if row.passkey_count == 0
                && row.totp_count == 0
                && row.recovery_count == 0
                && row.api_key_count == 1 =>
        {
            Ok(AuthenticationMethodRecordDetails::ApiKey {
                key_id: ApiKeyId::from_bytes(fixed_option(row.api_key_id.as_deref())?)
                    .map_err(|_| RepositoryError::CorruptState)?,
                scopes: parse_scope_bits(required(row.api_key_scopes)?)?,
                valid_from: valid_instant(required(row.api_key_valid_from)?)?,
            })
        }
        _ => Err(RepositoryError::CorruptState),
    }
}

fn cursor(record: &AuthenticationMethodRecord) -> AuthenticationMethodCursor {
    AuthenticationMethodCursor::new(
        record.principal_id,
        record.state,
        record.kind,
        record.method_id,
    )
}

const fn parse_kind(value: i64) -> Result<AuthenticationMethodKind, RepositoryError> {
    match value {
        1 => Ok(AuthenticationMethodKind::Passkey),
        2 => Ok(AuthenticationMethodKind::Totp),
        3 => Ok(AuthenticationMethodKind::RecoveryCode),
        4 => Ok(AuthenticationMethodKind::ApiKey),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_service_scope(value: i64) -> Result<u8, RepositoryError> {
    let value = u8::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 || value > 7 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(value)
}

fn parse_bool(value: Option<i64>) -> Result<bool, RepositoryError> {
    match value {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn valid_instant(value: i64) -> Result<UnixMicros, RepositoryError> {
    if !(0..=9_007_199_254_740_991).contains(&value) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(UnixMicros::new(value))
}

fn parse_positive_u64(value: i64) -> Result<u64, RepositoryError> {
    let value = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 || value > 9_007_199_254_740_991 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(value)
}

fn parse_scope_bits(value: i64) -> Result<u64, RepositoryError> {
    let value = parse_positive_u64(value)?;
    if value > 7 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(value)
}

fn sql_limit(limit: PageLimit) -> Result<i64, RepositoryError> {
    i64::try_from(limit.get().saturating_add(1)).map_err(|_| RepositoryError::InvalidPageLimit)
}

fn fixed(value: &[u8]) -> Result<[u8; 16], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn fixed_option(value: Option<&[u8]>) -> Result<[u8; 16], RepositoryError> {
    fixed(value.ok_or(RepositoryError::CorruptState)?)
}

const fn required(value: Option<i64>) -> Result<i64, RepositoryError> {
    match value {
        Some(value) => Ok(value),
        None => Err(RepositoryError::CorruptState),
    }
}
