// SPDX-License-Identifier: GPL-2.0-only

//! Validated durable operation projection for public polling and administration.

use meshspan_domain::{OperationId, PrincipalId, Revision, UnixMicros};
use rusqlite::OptionalExtension;

use super::{EntityReference, RepositoryError, receipt};
use crate::PartitionDatabase;

/// Closed lifecycle state represented by the authoritative operation receipt table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthoritativeOperationState {
    /// Accepted committed operation whose terminal result is not yet present.
    Running,
    /// Terminal committed success with a validated typed result.
    Succeeded,
    /// Terminal committed typed failure.
    Failed,
}

/// Validated status fields for one exact authoritative operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthoritativeOperationStatus {
    /// Exact operation identity.
    pub operation_id: OperationId,
    /// Principal that initiated the operation, or none for internal node work.
    pub actor_principal_id: Option<PrincipalId>,
    /// Stable internal command family code.
    pub operation_kind: u8,
    /// Current closed lifecycle state.
    pub state: AuthoritativeOperationState,
    /// Original accepted instant.
    pub started_at: UnixMicros,
    /// Terminal instant when complete.
    pub completed_at: Option<UnixMicros>,
    /// Typed result entity for successful metadata mutations.
    pub result: Option<EntityReference>,
    /// Stable internal failure code for failed work.
    pub error_kind: Option<u32>,
    /// Current authoritative record revision.
    pub revision: Revision,
}

pub(super) fn read(
    database: &PartitionDatabase,
    operation_id: OperationId,
) -> Result<Option<AuthoritativeOperationStatus>, RepositoryError> {
    let operation = operation_id.as_bytes();
    let row = database
        .connection()
        .query_row(
            "SELECT actor_principal_id, operation_kind, outcome, started_at,
                    completed_at, error_kind, revision
             FROM operations WHERE operation_id = ?1",
            [operation.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((actor, kind, outcome, started, completed, error, revision)) = row else {
        return Ok(None);
    };
    let actor_principal_id = actor
        .map(|value| exact_identifier(&value, PrincipalId::from_bytes))
        .transpose()?;
    let operation_kind = u8::try_from(kind).map_err(|_| RepositoryError::CorruptState)?;
    let revision = u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?;
    let error_kind = error
        .map(|value| u32::try_from(value).map_err(|_| RepositoryError::CorruptState))
        .transpose()?;
    let state = match (completed, error_kind) {
        (None, None) => AuthoritativeOperationState::Running,
        (Some(_), None) => AuthoritativeOperationState::Succeeded,
        (Some(_), Some(_)) => AuthoritativeOperationState::Failed,
        (None, Some(_)) => return Err(RepositoryError::CorruptState),
    };
    if !(1..=8).contains(&outcome) || operation_kind == 0 || revision == 0 {
        return Err(RepositoryError::CorruptState);
    }
    let result = if state == AuthoritativeOperationState::Succeeded {
        Some(
            receipt::resolve_operation(database, operation_id)?
                .ok_or(RepositoryError::CorruptState)?
                .entity,
        )
    } else {
        None
    };
    Ok(Some(AuthoritativeOperationStatus {
        operation_id,
        actor_principal_id,
        operation_kind,
        state,
        started_at: UnixMicros::new(started),
        completed_at: completed.map(UnixMicros::new),
        result,
        error_kind,
        revision: Revision::new(revision),
    }))
}

fn exact_identifier<T>(
    value: &[u8],
    parse: impl FnOnce([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, RepositoryError> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    parse(bytes).map_err(|_| RepositoryError::CorruptState)
}
