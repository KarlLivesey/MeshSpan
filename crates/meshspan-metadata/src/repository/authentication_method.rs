// SPDX-License-Identifier: GPL-2.0-only

//! Atomic authoritative lifecycle for protocol-neutral authentication methods.

use meshspan_domain::{
    ApiKeyId, AssuranceLevel, AuthenticationMethodId, AuthenticationMethodKind,
    AuthenticationService, OperationId, PrincipalId, RecoveryCodeId, Revision, UnixMicros,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, RevokeAuthenticationMethod};

const ACTIVE: i64 = 1;
const REVOKED: i64 = 3;
const MAXIMUM_REASON_CHARACTERS: usize = 1_024;
const MAXIMUM_SERVICE_SCOPE: u8 = 7;
const MAXIMUM_TOTP_METHODS_PER_USER: usize = 64;
const MAXIMUM_SMB_METHODS_PER_USER: usize = 64;

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
    /// Exclusive expiry of the key or containing method, whichever occurs first.
    pub expires_at: Option<UnixMicros>,
}

/// One active encrypted SMB verifier selected by a canonical user name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmbVerificationMaterial {
    /// User principal authenticated by the method.
    pub principal_id: PrincipalId,
    /// Common authentication-method identity.
    pub method_id: AuthenticationMethodId,
    /// Public API-key identity.
    pub key_id: ApiKeyId,
    /// Exact connector compatibility bits authenticated by the envelope.
    pub service_scope: u8,
    /// Exact API-key capability bits authenticated by the envelope.
    pub scopes: u64,
    /// Credential generation used to fence established sessions.
    pub credential_generation: u64,
    /// Current method revision used to fence established sessions.
    pub revision: Revision,
    /// Authenticated ciphertext decrypted only inside an authorised SMB gateway.
    pub verifier_ciphertext: Vec<u8>,
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

/// Current encrypted verification material for one active TOTP method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpVerificationMaterial {
    /// User account to which the method is authoritatively bound.
    pub principal_id: PrincipalId,
    /// Common authentication-method identity.
    pub method_id: AuthenticationMethodId,
    /// Credential generation used to fence older ceremonies and sessions.
    pub credential_generation: u64,
    /// Authoritative method revision included in the verification decision.
    pub revision: Revision,
    /// Authenticated-encryption envelope; never plaintext seed material.
    pub secret_ciphertext: Vec<u8>,
    /// Persisted algorithm code: SHA-1 1, SHA-256 2 or SHA-512 3.
    pub algorithm: u8,
    /// Decimal code width.
    pub digits: u8,
    /// Timestep in seconds.
    pub period_seconds: u16,
    /// Number of adjacent time steps accepted by policy.
    pub accepted_step_window: u8,
}

/// Exact digest-matched recovery-code evidence for one already-authenticated user.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryCodeVerificationMaterial {
    /// User account to which the recovery-code set belongs.
    pub principal_id: PrincipalId,
    /// Common authentication-method identity for the set.
    pub method_id: AuthenticationMethodId,
    /// Exact public identity embedded in the presented code.
    pub code_id: RecoveryCodeId,
    /// Credential generation used to fence replacement sets and sessions.
    pub credential_generation: u64,
    /// Current authoritative method revision.
    pub revision: Revision,
    /// Consumption instant, or `None` when the code remains unused.
    pub used_at: Option<UnixMicros>,
}

/// Resolves one digest-matched recovery code through current authority bounds.
pub(super) fn recovery_code_verification_material(
    connection: &rusqlite::Connection,
    principal_id: PrincipalId,
    code_id: RecoveryCodeId,
    presented_digest: [u8; 32],
    service: AuthenticationService,
    now: UnixMicros,
) -> Result<Option<RecoveryCodeVerificationMaterial>, RepositoryError> {
    if presented_digest == [0; 32] {
        return Ok(None);
    }
    let stored = connection
        .query_row(
            "SELECT method.method_id, method.user_principal_id, method.method_kind,
                    method.service_scope, method.state, method.created_at, method.expires_at,
                    method.credential_generation, method.revision, recovery.code_id,
                    recovery.created_at, recovery.used_at, recovery.revision, principal.state
             FROM recovery_codes AS recovery
             JOIN authentication_methods AS method USING(method_id)
             JOIN principals AS principal ON principal.principal_id = method.user_principal_id
             WHERE recovery.code_digest = ?1 AND recovery.code_id = ?2 LIMIT 2",
            params![presented_digest.as_slice(), code_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredRecoveryCode {
                    method_id: row.get(0)?,
                    principal_id: row.get(1)?,
                    method_kind: row.get(2)?,
                    service_scope: row.get(3)?,
                    method_state: row.get(4)?,
                    method_created_at: row.get(5)?,
                    method_expires_at: row.get(6)?,
                    credential_generation: row.get(7)?,
                    method_revision: row.get(8)?,
                    code_id: row.get(9)?,
                    code_created_at: row.get(10)?,
                    used_at: row.get(11)?,
                    code_revision: row.get(12)?,
                    principal_state: row.get(13)?,
                })
            },
        )
        .optional()?;
    stored
        .map(|stored| validate_recovery_code_material(stored, principal_id, code_id, service, now))
        .transpose()
        .map(Option::flatten)
}

struct StoredRecoveryCode {
    method_id: Vec<u8>,
    principal_id: Vec<u8>,
    method_kind: i64,
    service_scope: i64,
    method_state: i64,
    method_created_at: i64,
    method_expires_at: Option<i64>,
    credential_generation: i64,
    method_revision: i64,
    code_id: Vec<u8>,
    code_created_at: i64,
    used_at: Option<i64>,
    code_revision: i64,
    principal_state: i64,
}

fn validate_recovery_code_material(
    stored: StoredRecoveryCode,
    expected_principal: PrincipalId,
    expected_code: RecoveryCodeId,
    service: AuthenticationService,
    now: UnixMicros,
) -> Result<Option<RecoveryCodeVerificationMaterial>, RepositoryError> {
    let principal_id = PrincipalId::from_bytes(fixed(stored.principal_id)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let code_id = RecoveryCodeId::from_bytes(fixed(stored.code_id)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let service_scope = u8::try_from(stored.service_scope)
        .ok()
        .filter(|scope| (1..=MAXIMUM_SERVICE_SCOPE).contains(scope))
        .ok_or(RepositoryError::CorruptState)?;
    let credential_generation = positive_u64(stored.credential_generation)?;
    let method_revision = positive_u64(stored.method_revision)?;
    positive_u64(stored.code_revision)?;
    if code_id != expected_code
        || stored.method_kind != AuthenticationMethodKind::RecoveryCode as i64
        || !(1..=3).contains(&stored.method_state)
        || !(1..=3).contains(&stored.principal_state)
        || stored.code_created_at < stored.method_created_at
        || stored
            .method_expires_at
            .is_some_and(|end| end <= stored.method_created_at)
        || stored
            .used_at
            .is_some_and(|used_at| used_at < stored.code_created_at)
    {
        return Err(RepositoryError::CorruptState);
    }
    if principal_id != expected_principal
        || stored.method_state != ACTIVE
        || stored.principal_state != ACTIVE
        || service_scope & service.scope_bit() == 0
        || stored.method_expires_at.is_some_and(|end| now.get() >= end)
    {
        return Ok(None);
    }
    Ok(Some(RecoveryCodeVerificationMaterial {
        principal_id,
        method_id: AuthenticationMethodId::from_bytes(fixed(stored.method_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        code_id,
        credential_generation,
        revision: Revision::new(method_revision),
        used_at: stored.used_at.map(UnixMicros::new),
    }))
}

/// Resolves every bounded active TOTP method for one already-authenticated user.
pub(super) fn totp_verification_materials(
    connection: &rusqlite::Connection,
    principal_id: PrincipalId,
    service: AuthenticationService,
    now: UnixMicros,
) -> Result<Vec<TotpVerificationMaterial>, RepositoryError> {
    let mut statement = connection.prepare(
        "SELECT method.method_id, method.user_principal_id, method.method_kind,
                method.service_scope, method.state, method.created_at, method.expires_at,
                method.credential_generation, method.revision, credential.secret_ciphertext,
                credential.algorithm, credential.digits, credential.period_seconds,
                credential.accepted_step_window, credential.revision, principal.state
         FROM authentication_methods AS method INDEXED BY authentication_methods_by_user
         JOIN totp_credentials AS credential USING(method_id)
         JOIN principals AS principal ON principal.principal_id = method.user_principal_id
         WHERE method.user_principal_id = ?1 AND method.method_kind = ?2
         ORDER BY method.user_principal_id, method.state, method.method_kind, method.method_id
         LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![
            principal_id.as_bytes().as_slice(),
            AuthenticationMethodKind::Totp as u8,
            i64::try_from(MAXIMUM_TOTP_METHODS_PER_USER + 1)
                .map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        |row| {
            Ok(StoredTotp {
                method_id: row.get(0)?,
                principal_id: row.get(1)?,
                method_kind: row.get(2)?,
                service_scope: row.get(3)?,
                method_state: row.get(4)?,
                created_at: row.get(5)?,
                expires_at: row.get(6)?,
                credential_generation: row.get(7)?,
                method_revision: row.get(8)?,
                secret_ciphertext: row.get(9)?,
                algorithm: row.get(10)?,
                digits: row.get(11)?,
                period_seconds: row.get(12)?,
                accepted_step_window: row.get(13)?,
                credential_revision: row.get(14)?,
                principal_state: row.get(15)?,
            })
        },
    )?;
    let mut materials = Vec::new();
    for row in rows {
        if let Some(material) = validate_totp_material(row?, principal_id, service, now)? {
            materials.push(material);
        }
        if materials.len() > MAXIMUM_TOTP_METHODS_PER_USER {
            return Err(RepositoryError::CapacityExceeded);
        }
    }
    Ok(materials)
}

struct StoredTotp {
    method_id: Vec<u8>,
    principal_id: Vec<u8>,
    method_kind: i64,
    service_scope: i64,
    method_state: i64,
    created_at: i64,
    expires_at: Option<i64>,
    credential_generation: i64,
    method_revision: i64,
    secret_ciphertext: Vec<u8>,
    algorithm: i64,
    digits: i64,
    period_seconds: i64,
    accepted_step_window: i64,
    credential_revision: i64,
    principal_state: i64,
}

fn validate_totp_material(
    stored: StoredTotp,
    expected_principal: PrincipalId,
    service: AuthenticationService,
    now: UnixMicros,
) -> Result<Option<TotpVerificationMaterial>, RepositoryError> {
    let principal_id = PrincipalId::from_bytes(fixed(stored.principal_id)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let service_scope = u8::try_from(stored.service_scope)
        .ok()
        .filter(|scope| (1..=MAXIMUM_SERVICE_SCOPE).contains(scope))
        .ok_or(RepositoryError::CorruptState)?;
    let credential_generation = positive_u64(stored.credential_generation)?;
    let method_revision = positive_u64(stored.method_revision)?;
    positive_u64(stored.credential_revision)?;
    let algorithm = u8::try_from(stored.algorithm)
        .ok()
        .filter(|value| (1..=3).contains(value))
        .ok_or(RepositoryError::CorruptState)?;
    let digits = u8::try_from(stored.digits)
        .ok()
        .filter(|value| (6..=8).contains(value))
        .ok_or(RepositoryError::CorruptState)?;
    let period_seconds = u16::try_from(stored.period_seconds)
        .ok()
        .filter(|value| (15..=300).contains(value))
        .ok_or(RepositoryError::CorruptState)?;
    let accepted_step_window = u8::try_from(stored.accepted_step_window)
        .ok()
        .filter(|value| *value <= 10)
        .ok_or(RepositoryError::CorruptState)?;
    if principal_id != expected_principal
        || stored.method_kind != AuthenticationMethodKind::Totp as i64
        || !(1..=3).contains(&stored.method_state)
        || !(1..=3).contains(&stored.principal_state)
        || !(32..=4_096).contains(&stored.secret_ciphertext.len())
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
    Ok(Some(TotpVerificationMaterial {
        principal_id,
        method_id: AuthenticationMethodId::from_bytes(fixed(stored.method_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        credential_generation,
        revision: Revision::new(method_revision),
        secret_ciphertext: stored.secret_ciphertext,
        algorithm,
        digits,
        period_seconds,
        accepted_step_window,
    }))
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

/// Authenticates a direct API-key presentation and applies the current operation policy.
pub(super) fn authenticate_api_key_for_operation(
    connection: &rusqlite::Connection,
    presented_key_digest: [u8; 32],
    service: AuthenticationService,
    required_scopes: u64,
    required_assurance: AssuranceLevel,
    now: UnixMicros,
) -> Result<Option<ApiKeyAuthentication>, RepositoryError> {
    let Some(authentication) = authenticate_api_key(
        connection,
        presented_key_digest,
        service,
        required_scopes,
        now,
    )?
    else {
        return Ok(None);
    };
    let permitted = super::authentication_policy::permits_operation(
        connection,
        service,
        required_assurance,
        super::authentication_policy::SessionPolicyEvidence {
            assurance: AssuranceLevel::SingleFactor,
            factor_classes: AuthenticationMethodKind::ApiKey.class_bit(),
            factor_count: 1,
            issued_at: now,
            latest_authenticated_at: now,
        },
        now,
    )?;
    Ok(permitted.then_some(authentication))
}

/// Resolves a bounded set of current SMB verifier envelopes for one canonical user.
pub(super) fn smb_verification_materials(
    connection: &rusqlite::Connection,
    canonical_user_name: &str,
    now: UnixMicros,
) -> Result<Vec<SmbVerificationMaterial>, RepositoryError> {
    if canonical_user_name.is_empty() || canonical_user_name.len() > 256 {
        return Ok(Vec::new());
    }
    let mut statement = connection.prepare(
        "SELECT method.user_principal_id, method.method_id, key.key_id,
                method.service_scope, key.scopes, method.credential_generation,
                method.revision, key.smb_verifier_ciphertext
         FROM principals AS principal
         JOIN users AS user ON user.principal_id = principal.principal_id
         JOIN authentication_methods AS method
           ON method.user_principal_id = principal.principal_id
         JOIN api_keys AS key ON key.method_id = method.method_id
         WHERE principal.canonical_name = ?1
           AND principal.principal_kind = 1
           AND principal.state = 1
           AND method.method_kind = 4
           AND method.state = 1
           AND (method.service_scope & 4) = 4
           AND (key.scopes & 4) = 4
           AND key.valid_from <= ?2
           AND (key.valid_until IS NULL OR key.valid_until > ?2)
           AND (method.expires_at IS NULL OR method.expires_at > ?2)
         ORDER BY method.method_id
         LIMIT 65",
    )?;
    let rows = statement.query_map(params![canonical_user_name, now.get()], |row| {
        Ok(StoredSmbVerificationMaterial {
            principal_id: row.get(0)?,
            method_id: row.get(1)?,
            key_id: row.get(2)?,
            service_scope: row.get(3)?,
            scopes: row.get(4)?,
            credential_generation: row.get(5)?,
            revision: row.get(6)?,
            verifier_ciphertext: row.get(7)?,
        })
    })?;
    let mut materials = Vec::with_capacity(MAXIMUM_SMB_METHODS_PER_USER);
    for row in rows {
        if materials.len() == MAXIMUM_SMB_METHODS_PER_USER {
            return Err(RepositoryError::CapacityExceeded);
        }
        materials.push(row?.validated()?);
    }
    Ok(materials)
}

struct StoredSmbVerificationMaterial {
    principal_id: Vec<u8>,
    method_id: Vec<u8>,
    key_id: Vec<u8>,
    service_scope: i64,
    scopes: i64,
    credential_generation: i64,
    revision: i64,
    verifier_ciphertext: Vec<u8>,
}

impl StoredSmbVerificationMaterial {
    fn validated(self) -> Result<SmbVerificationMaterial, RepositoryError> {
        let service_scope = u8::try_from(self.service_scope)
            .ok()
            .filter(|value| *value & AuthenticationService::Smb.scope_bit() != 0)
            .ok_or(RepositoryError::CorruptState)?;
        let scopes = positive_u64(self.scopes)?;
        if scopes & AuthenticationService::Smb.api_key_login_scope() == 0
            || !(65..=256).contains(&self.verifier_ciphertext.len())
        {
            return Err(RepositoryError::CorruptState);
        }
        Ok(SmbVerificationMaterial {
            principal_id: PrincipalId::from_bytes(fixed(self.principal_id)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            method_id: AuthenticationMethodId::from_bytes(fixed(self.method_id)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            key_id: ApiKeyId::from_bytes(fixed(self.key_id)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            service_scope,
            scopes,
            credential_generation: positive_u64(self.credential_generation)?,
            revision: Revision::new(positive_u64(self.revision)?),
            verifier_ciphertext: self.verifier_ciphertext,
        })
    }
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
        expires_at: [stored.valid_until, stored.method_expires_at]
            .into_iter()
            .flatten()
            .min()
            .map(UnixMicros::new),
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
