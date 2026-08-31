// SPDX-License-Identifier: GPL-2.0-only

//! Current-user identity and bounded credential hints for passkey registration.

use meshspan_domain::{AuthenticationMethodId, OperationId, PrincipalId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, params};

use super::query::PrincipalKind;
use super::{EntityKind, RepositoryError, query};
use crate::PartitionDatabase;

const ACTIVE: u8 = 1;
const PASSKEY: i64 = 1;
const MAXIMUM_EXCLUDED_CREDENTIALS: usize = 64;
const MAXIMUM_CREDENTIAL_ID_BYTES: usize = 1_024;

/// Current authoritative user details needed to create browser registration options.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyRegistrationProfile {
    /// Exact active user owning the future method.
    pub principal_id: PrincipalId,
    /// Stable canonical account name shown to the authenticator.
    pub user_name: String,
    /// Current human-readable display name shown to the authenticator.
    pub display_name: String,
    /// Identity revision bound into the registration challenge.
    pub identity_revision: Revision,
    /// Bounded existing credential identities supplied only as browser exclusion hints.
    pub exclude_credential_ids: Vec<Vec<u8>>,
}

/// Exact durable facts needed to reproduce one passkey-registration result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasskeyRegistrationReplay {
    /// Original semantic request digest used to reject changed operation reuse.
    pub request_digest: [u8; 32],
    /// Digest of the durable command result.
    pub result_digest: [u8; 32],
    /// Newly created independently revocable method.
    pub method_id: AuthenticationMethodId,
    /// User who owns the method and performed the operation.
    pub principal_id: PrincipalId,
    /// Authoritative creation instant returned to the client.
    pub created_at: UnixMicros,
}

pub(super) fn profile(
    database: &PartitionDatabase,
    principal_id: PrincipalId,
) -> Result<Option<PasskeyRegistrationProfile>, RepositoryError> {
    let Some(principal) = query::principal(database, principal_id)? else {
        return Ok(None);
    };
    if principal.kind != PrincipalKind::User || principal.state != ACTIVE {
        return Ok(None);
    }
    let principal_bytes = principal_id.as_bytes();
    let mut statement = database.connection().prepare(
        "SELECT credential.credential_id
         FROM authentication_methods AS method INDEXED BY authentication_methods_by_user
         JOIN webauthn_credentials AS credential USING(method_id)
         WHERE method.user_principal_id = ?1 AND method.state = 1 AND method.method_kind = ?2
         ORDER BY method.user_principal_id, method.state, method.method_kind,
                  method.method_id, credential.credential_id
         LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![
            principal_bytes.as_slice(),
            PASSKEY,
            i64::try_from(MAXIMUM_EXCLUDED_CREDENTIALS)
                .map_err(|_| RepositoryError::CorruptState)?
        ],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let mut exclude_credential_ids = Vec::with_capacity(MAXIMUM_EXCLUDED_CREDENTIALS);
    for row in rows {
        let credential_id = row?;
        if credential_id.is_empty() || credential_id.len() > MAXIMUM_CREDENTIAL_ID_BYTES {
            return Err(RepositoryError::CorruptState);
        }
        exclude_credential_ids.push(credential_id);
    }
    Ok(Some(PasskeyRegistrationProfile {
        principal_id,
        user_name: principal.canonical_name,
        display_name: principal.display_name,
        identity_revision: principal.revision,
        exclude_credential_ids,
    }))
}

pub(super) fn resolve_replay(
    database: &PartitionDatabase,
    operation_id: OperationId,
) -> Result<Option<PasskeyRegistrationReplay>, RepositoryError> {
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
                    operation.started_at, method.user_principal_id, method.method_kind,
                    method.created_at, method.revision
             FROM operations AS operation
             JOIN authentication_methods AS method ON method.method_id = ?2
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
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    let (actor, operation_kind, started_at, principal, method_kind, created_at, revision) = stored;
    if operation_kind != 74
        || method_kind != PASSKEY
        || actor != principal
        || started_at != created_at
        || u64::try_from(revision).ok() != Some(receipt.committed_revision.get())
    {
        return Err(RepositoryError::OperationConflict);
    }
    Ok(Some(PasskeyRegistrationReplay {
        request_digest: receipt.request_digest,
        result_digest: receipt.result_digest,
        method_id: AuthenticationMethodId::from_bytes(method)
            .map_err(|_| RepositoryError::CorruptState)?,
        principal_id: PrincipalId::from_bytes(
            principal
                .try_into()
                .map_err(|_| RepositoryError::CorruptState)?,
        )
        .map_err(|_| RepositoryError::CorruptState)?,
        created_at: UnixMicros::new(created_at),
    }))
}
