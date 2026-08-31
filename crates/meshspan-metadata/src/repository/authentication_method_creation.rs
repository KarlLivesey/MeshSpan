// SPDX-License-Identifier: GPL-2.0-only

//! Atomic creation of every accepted typed authentication credential family.

use std::collections::BTreeSet;

use meshspan_domain::{AuthenticationMethodKind, Revision};
use rusqlite::{Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, CreateAuthenticationMethod, NewAuthenticationCredential};

const ACTIVE: i64 = 1;
const SMB_SERVICE: u8 = 4;
const MAXIMUM_SERVICE_SCOPE: u8 = 7;
const MAXIMUM_LABEL_CHARACTERS: usize = 128;
const MAXIMUM_RECOVERY_CODES: usize = 64;

pub(super) fn create(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateAuthenticationMethod,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let method_kind = validate(command, context)?;
    require_active_user(transaction, command.principal_id.as_bytes())?;
    let method_id = command.method_id.as_bytes();
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM authentication_methods WHERE method_id = ?1)",
        [method_id.as_slice()],
        |row| row.get(0),
    )?;
    if exists != 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    let revision = to_i64(revision.get())?;
    transaction.execute(
        "INSERT INTO authentication_methods(
            method_id, user_principal_id, method_kind, label, service_scope,
            state, created_at, last_used_at, expires_at,
            credential_generation, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, 1, ?9)",
        params![
            method_id.as_slice(),
            command.principal_id.as_bytes().as_slice(),
            method_kind,
            command.label,
            command.service_scope,
            ACTIVE,
            context.occurred_at.get(),
            command.expires_at.map(meshspan_domain::UnixMicros::get),
            revision,
        ],
    )?;
    insert_credential(transaction, command, revision, context.occurred_at.get())?;
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

fn insert_credential(
    transaction: &Transaction<'_>,
    command: &CreateAuthenticationMethod,
    revision: i64,
    created_at: i64,
) -> Result<(), RepositoryError> {
    match &command.credential {
        NewAuthenticationCredential::Passkey {
            credential_id,
            public_key_algorithm,
            public_key,
            signature_counter,
            authenticator_guid,
            transports,
            backup_eligible,
            backup_state,
        } => insert_passkey(
            transaction,
            command,
            credential_id,
            *public_key_algorithm,
            public_key,
            *signature_counter,
            *authenticator_guid,
            *transports,
            *backup_eligible,
            *backup_state,
            revision,
        )?,
        NewAuthenticationCredential::Totp {
            secret_ciphertext,
            algorithm,
            digits,
            period_seconds,
            accepted_step_window,
        } => insert_totp(
            transaction,
            command,
            secret_ciphertext,
            *algorithm as u8,
            *digits,
            *period_seconds,
            *accepted_step_window,
            revision,
        )?,
        NewAuthenticationCredential::RecoveryCodes { codes } => {
            insert_recovery_codes(transaction, command, codes, created_at, revision)?;
        }
        NewAuthenticationCredential::ApiKey {
            key_id,
            key_digest,
            scopes,
            valid_from,
        } => insert_api_key(
            transaction,
            command,
            *key_id,
            *key_digest,
            *scopes,
            *valid_from,
            revision,
        )?,
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, reason = "one exact typed passkey row")]
fn insert_passkey(
    transaction: &Transaction<'_>,
    command: &CreateAuthenticationMethod,
    credential_id: &[u8],
    public_key_algorithm: i32,
    public_key: &[u8],
    signature_counter: u64,
    authenticator_guid: Option<[u8; 16]>,
    transports: u8,
    backup_eligible: bool,
    backup_state: bool,
    revision: i64,
) -> Result<(), RepositoryError> {
    if public_key_algorithm != -7 || public_key.len() != 65 {
        return Err(RepositoryError::InvalidCommand);
    }
    reject_existing_blob(
        transaction,
        "SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE credential_id = ?1)",
        credential_id,
    )?;
    transaction.execute(
        "INSERT INTO webauthn_credentials(
            method_id, credential_id, public_key_algorithm, public_key,
            signature_counter, authenticator_guid, transports,
            backup_eligible, backup_state, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            command.method_id.as_bytes().as_slice(),
            credential_id,
            public_key_algorithm,
            public_key,
            to_i64(signature_counter)?,
            authenticator_guid.map(|value| value.to_vec()),
            transports,
            backup_eligible,
            backup_state,
            revision,
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments, reason = "one exact typed TOTP row")]
fn insert_totp(
    transaction: &Transaction<'_>,
    command: &CreateAuthenticationMethod,
    secret_ciphertext: &[u8],
    algorithm: u8,
    digits: u8,
    period_seconds: u16,
    accepted_step_window: u8,
    revision: i64,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO totp_credentials(
            method_id, secret_ciphertext, algorithm, digits,
            period_seconds, accepted_step_window, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            command.method_id.as_bytes().as_slice(),
            secret_ciphertext,
            algorithm,
            digits,
            period_seconds,
            accepted_step_window,
            revision,
        ],
    )?;
    Ok(())
}

fn insert_recovery_codes(
    transaction: &Transaction<'_>,
    command: &CreateAuthenticationMethod,
    codes: &meshspan_contracts::BoundedItems<crate::NewRecoveryCode>,
    created_at: i64,
    revision: i64,
) -> Result<(), RepositoryError> {
    for code in codes.as_slice() {
        reject_existing_blob(
            transaction,
            "SELECT EXISTS(SELECT 1 FROM recovery_codes WHERE code_digest = ?1)",
            &code.code_digest,
        )?;
        transaction.execute(
            "INSERT INTO recovery_codes(
                method_id, code_id, code_digest, created_at, used_at, revision
             ) VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
            params![
                command.method_id.as_bytes().as_slice(),
                code.code_id.as_bytes().as_slice(),
                code.code_digest.as_slice(),
                created_at,
                revision,
            ],
        )?;
    }
    Ok(())
}

fn insert_api_key(
    transaction: &Transaction<'_>,
    command: &CreateAuthenticationMethod,
    key_id: meshspan_domain::ApiKeyId,
    key_digest: [u8; 32],
    scopes: u64,
    valid_from: meshspan_domain::UnixMicros,
    revision: i64,
) -> Result<(), RepositoryError> {
    reject_existing_blob(
        transaction,
        "SELECT EXISTS(SELECT 1 FROM api_keys WHERE key_id = ?1)",
        &key_id.as_bytes(),
    )?;
    reject_existing_blob(
        transaction,
        "SELECT EXISTS(SELECT 1 FROM api_keys WHERE key_digest = ?1)",
        &key_digest,
    )?;
    transaction.execute(
        "INSERT INTO api_keys(
            method_id, key_id, key_digest, scopes,
            valid_from, valid_until, last_used_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
        params![
            command.method_id.as_bytes().as_slice(),
            key_id.as_bytes().as_slice(),
            key_digest.as_slice(),
            to_i64(scopes)?,
            valid_from.get(),
            command.expires_at.map(meshspan_domain::UnixMicros::get),
            revision,
        ],
    )?;
    Ok(())
}

fn validate(
    command: &CreateAuthenticationMethod,
    context: CommandContext,
) -> Result<i64, RepositoryError> {
    validate_text(&command.label, MAXIMUM_LABEL_CHARACTERS)?;
    if command.service_scope == 0
        || command.service_scope > MAXIMUM_SERVICE_SCOPE
        || command
            .expires_at
            .is_some_and(|expiry| expiry <= context.occurred_at)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    match &command.credential {
        NewAuthenticationCredential::Passkey {
            credential_id,
            public_key_algorithm,
            public_key,
            signature_counter,
            backup_eligible,
            backup_state,
            ..
        } => {
            if credential_id.is_empty()
                || credential_id.len() > 1_024
                || *public_key_algorithm == 0
                || !(-65_535..=65_535).contains(public_key_algorithm)
                || public_key.is_empty()
                || public_key.len() > 4_096
                || i64::try_from(*signature_counter).is_err()
                || (*backup_state && !*backup_eligible)
                || command.service_scope & SMB_SERVICE != 0
            {
                return Err(RepositoryError::InvalidCommand);
            }
            Ok(AuthenticationMethodKind::Passkey as i64)
        }
        NewAuthenticationCredential::Totp {
            secret_ciphertext,
            digits,
            period_seconds,
            accepted_step_window,
            ..
        } => {
            if !(32..=4_096).contains(&secret_ciphertext.len())
                || !(6..=10).contains(digits)
                || !(15..=300).contains(period_seconds)
                || *accepted_step_window > 10
                || command.service_scope & SMB_SERVICE != 0
            {
                return Err(RepositoryError::InvalidCommand);
            }
            Ok(AuthenticationMethodKind::Totp as i64)
        }
        NewAuthenticationCredential::RecoveryCodes { codes } => {
            validate_recovery_codes(codes)?;
            if command.service_scope & SMB_SERVICE != 0 {
                return Err(RepositoryError::InvalidCommand);
            }
            Ok(AuthenticationMethodKind::RecoveryCode as i64)
        }
        NewAuthenticationCredential::ApiKey {
            key_digest,
            scopes,
            valid_from,
            ..
        } => {
            if *key_digest == [0; 32]
                || *scopes == 0
                || i64::try_from(*scopes).is_err()
                || command.expires_at.is_some_and(|end| end <= *valid_from)
            {
                return Err(RepositoryError::InvalidCommand);
            }
            Ok(AuthenticationMethodKind::ApiKey as i64)
        }
    }
}

fn validate_recovery_codes(
    codes: &meshspan_contracts::BoundedItems<crate::NewRecoveryCode>,
) -> Result<(), RepositoryError> {
    if codes.is_empty() || codes.len() > MAXIMUM_RECOVERY_CODES {
        return Err(RepositoryError::InvalidCommand);
    }
    let mut identities = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for code in codes.as_slice() {
        if code.code_digest == [0; 32]
            || !identities.insert(code.code_id)
            || !digests.insert(code.code_digest)
        {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    Ok(())
}

fn reject_existing_blob(
    transaction: &Transaction<'_>,
    query: &'static str,
    value: &[u8],
) -> Result<(), RepositoryError> {
    let exists: i64 = transaction.query_row(query, [value], |row| row.get(0))?;
    if exists == 0 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
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
