// SPDX-License-Identifier: GPL-2.0-only

//! Validated durable operation projection for public polling and administration.

use meshspan_domain::{OperationId, PrincipalId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, params};

use super::{EntityReference, Page, PageLimit, RepositoryError, receipt};
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

/// Stable reverse-chronological seek position for operation administration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthoritativeOperationCursor {
    revision: Revision,
    operation_id: OperationId,
}

impl AuthoritativeOperationCursor {
    /// Reconstructs a cursor after the public boundary validates both fields.
    #[must_use]
    pub const fn new(revision: Revision, operation_id: OperationId) -> Self {
        Self {
            revision,
            operation_id,
        }
    }

    /// Returns the authoritative revision seek key.
    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }

    /// Returns the stable operation identity tie-breaker.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.operation_id
    }
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
    let Some(row) = row else {
        return Ok(None);
    };
    parse_status(database, operation_id, row).map(Some)
}

pub(super) fn list(
    database: &PartitionDatabase,
    after: Option<AuthoritativeOperationCursor>,
    limit: PageLimit,
) -> Result<Page<AuthoritativeOperationStatus, AuthoritativeOperationCursor>, RepositoryError> {
    let upper_revision = after.map_or(i64::MAX, |cursor| {
        i64::try_from(cursor.revision().get()).unwrap_or(i64::MAX)
    });
    let lower_operation = after.map_or([0; 16], |cursor| cursor.operation_id().as_bytes());
    let sql_limit = i64::try_from(limit.get().saturating_add(1))
        .map_err(|_| RepositoryError::InvalidPageLimit)?;
    let mut statement = database.connection().prepare(
        "SELECT operation_id, actor_principal_id, operation_kind, outcome, started_at,
                completed_at, error_kind, revision
         FROM operations
         WHERE revision < ?1 OR (revision = ?1 AND operation_id > ?2)
         ORDER BY revision DESC, operation_id
         LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![upper_revision, lower_operation.as_slice(), sql_limit],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                (
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, i64>(7)?,
                ),
            ))
        },
    )?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        let (operation, stored) = row?;
        let operation_id = exact_identifier(&operation, OperationId::from_bytes)?;
        items.push(parse_status(database, operation_id, stored)?);
    }
    let next = (items.len() > limit.get()).then(|| cursor(items[limit.get() - 1]));
    items.truncate(limit.get());
    Ok(Page { items, next })
}

type StoredStatus = (
    Option<Vec<u8>>,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    i64,
);

fn parse_status(
    database: &PartitionDatabase,
    operation_id: OperationId,
    stored: StoredStatus,
) -> Result<AuthoritativeOperationStatus, RepositoryError> {
    let (actor, kind, outcome, started, completed, error, revision) = stored;
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
    Ok(AuthoritativeOperationStatus {
        operation_id,
        actor_principal_id,
        operation_kind,
        state,
        started_at: UnixMicros::new(started),
        completed_at: completed.map(UnixMicros::new),
        result,
        error_kind,
        revision: Revision::new(revision),
    })
}

const fn cursor(record: AuthoritativeOperationStatus) -> AuthoritativeOperationCursor {
    AuthoritativeOperationCursor::new(record.revision, record.operation_id)
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
