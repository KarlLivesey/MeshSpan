// SPDX-License-Identifier: GPL-2.0-only

//! Typed point reads and index-aligned bounded pagination.

use meshspan_domain::{GroupId, ObjectId, OwnerSetId, PrincipalId, Revision, VolumeId};
use rusqlite::{OptionalExtension, params};

use super::RepositoryError;
use crate::PartitionDatabase;

const MAXIMUM_PAGE_ITEMS: usize = 1_000;

/// Validated non-zero item limit for one repository page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageLimit(usize);

impl PageLimit {
    /// Validates one caller-supplied page size.
    ///
    /// # Errors
    ///
    /// Rejects zero and values above the repository allocation bound.
    pub const fn new(value: usize) -> Result<Self, RepositoryError> {
        if value == 0 || value > MAXIMUM_PAGE_ITEMS {
            Err(RepositoryError::InvalidPageLimit)
        } else {
            Ok(Self(value))
        }
    }

    pub(super) const fn get(self) -> usize {
        self.0
    }
}

/// Closed persisted principal families exposed by Stage 2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    /// Interactive or service user.
    User,
    /// Nested identity group.
    Group,
    /// Reserved non-user service principal.
    Service,
}

/// Typed principal point-read result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalRecord {
    /// Stable identity.
    pub principal_id: PrincipalId,
    /// Persisted principal family.
    pub kind: PrincipalKind,
    /// NFC display name.
    pub display_name: String,
    /// Canonical uniqueness name.
    pub canonical_name: String,
    /// Whether the principal is active, suspended or retired.
    pub state: u8,
    /// Last authoritative record revision.
    pub revision: Revision,
}

/// Stable namespace seek cursor, opaque to higher-level public APIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceCursor {
    canonical_name: String,
    object_id: ObjectId,
}

/// Stable direct-membership seek cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupMemberCursor(PrincipalId);

/// One active namespace child returned by an indexed page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceRecord {
    /// Object identity.
    pub object_id: ObjectId,
    /// Volume identity.
    pub volume_id: VolumeId,
    /// Exact parent folder.
    pub parent_object_id: ObjectId,
    /// Persisted object-kind code: folder 1 or file 2.
    pub object_kind: u8,
    /// NFC display name.
    pub display_name: String,
    /// Canonical seek/uniqueness name.
    pub canonical_name: String,
    /// Immutable owner-set identity.
    pub owner_set_id: OwnerSetId,
    /// Last authoritative record revision.
    pub revision: Revision,
}

/// Bounded items plus an optional cursor only when another page exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T, C> {
    /// Returned records in stable order.
    pub items: Vec<T>,
    /// Cursor to request the next page, or no cursor at the end.
    pub next: Option<C>,
}

pub(super) fn principal(
    database: &PartitionDatabase,
    principal_id: PrincipalId,
) -> Result<Option<PrincipalRecord>, RepositoryError> {
    let identifier = principal_id.as_bytes();
    database
        .connection()
        .query_row(
            "SELECT principal_kind, display_name, canonical_name, state, revision
             FROM principals WHERE principal_id = ?1",
            [identifier.as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(PrincipalRecord {
                principal_id,
                kind: parse_principal_kind(row.0)?,
                display_name: row.1,
                canonical_name: row.2,
                state: u8::try_from(row.3).map_err(|_| RepositoryError::CorruptState)?,
                revision: Revision::new(parse_u64(row.4)?),
            })
        })
        .transpose()
}

pub(super) fn namespace_children(
    database: &PartitionDatabase,
    volume_id: VolumeId,
    parent_object_id: ObjectId,
    after: Option<&NamespaceCursor>,
    limit: PageLimit,
) -> Result<Page<NamespaceRecord, NamespaceCursor>, RepositoryError> {
    let volume = volume_id.as_bytes();
    let parent = parent_object_id.as_bytes();
    let after_name = after.map_or("", |cursor| cursor.canonical_name.as_str());
    let after_id = after.map(|cursor| cursor.object_id.as_bytes());
    let lower_id = after_id.unwrap_or([0; 16]);
    let row_limit = sql_limit(limit)?;
    let mut statement = database.connection().prepare(
        "SELECT object_id, object_kind, display_name, canonical_name, owner_set_id, revision
         FROM namespace_objects INDEXED BY namespace_objects_by_parent
         WHERE volume_id = ?1 AND parent_object_id = ?2 AND state = 1
           AND (canonical_name, object_id) > (?3, ?4)
         ORDER BY canonical_name, object_id LIMIT ?5",
    )?;
    let rows = statement.query_map(
        params![
            volume.as_slice(),
            parent.as_slice(),
            after_name,
            lower_id.as_slice(),
            row_limit
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        let row = row?;
        items.push(NamespaceRecord {
            object_id: parse_object(&row.0)?,
            volume_id,
            parent_object_id,
            object_kind: parse_object_kind(row.1)?,
            display_name: row.2,
            canonical_name: row.3,
            owner_set_id: parse_owner_set(&row.4)?,
            revision: Revision::new(parse_u64(row.5)?),
        });
    }
    let next = (items.len() > limit.get()).then(|| {
        let last = &items[limit.get() - 1];
        NamespaceCursor {
            canonical_name: last.canonical_name.clone(),
            object_id: last.object_id,
        }
    });
    items.truncate(limit.get());
    Ok(Page { items, next })
}

pub(super) fn direct_group_members(
    database: &PartitionDatabase,
    group_id: GroupId,
    after: Option<GroupMemberCursor>,
    limit: PageLimit,
) -> Result<Page<PrincipalId, GroupMemberCursor>, RepositoryError> {
    let group = group_id.as_bytes();
    let lower = after.map_or([0; 16], |cursor| cursor.0.as_bytes());
    let mut statement = database.connection().prepare(
        "SELECT member_principal_id FROM group_memberships
         WHERE containing_group_id = ?1 AND state = 1 AND member_principal_id > ?2
         ORDER BY member_principal_id LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![group.as_slice(), lower.as_slice(), sql_limit(limit)?],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        items.push(parse_principal(&row?)?);
    }
    let next = (items.len() > limit.get()).then(|| GroupMemberCursor(items[limit.get() - 1]));
    items.truncate(limit.get());
    Ok(Page { items, next })
}

fn sql_limit(limit: PageLimit) -> Result<i64, RepositoryError> {
    let value = limit
        .get()
        .checked_add(1)
        .ok_or(RepositoryError::InvalidPageLimit)?;
    i64::try_from(value).map_err(|_| RepositoryError::InvalidPageLimit)
}

fn parse_principal_kind(value: i64) -> Result<PrincipalKind, RepositoryError> {
    match value {
        1 => Ok(PrincipalKind::User),
        2 => Ok(PrincipalKind::Group),
        3 => Ok(PrincipalKind::Service),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_object_kind(value: i64) -> Result<u8, RepositoryError> {
    match value {
        1 => Ok(1),
        2 => Ok(2),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn parse_principal(value: &[u8]) -> Result<PrincipalId, RepositoryError> {
    PrincipalId::from_bytes(parse_identifier(value)?).map_err(|_| RepositoryError::CorruptState)
}

fn parse_object(value: &[u8]) -> Result<ObjectId, RepositoryError> {
    ObjectId::from_bytes(parse_identifier(value)?).map_err(|_| RepositoryError::CorruptState)
}

fn parse_owner_set(value: &[u8]) -> Result<OwnerSetId, RepositoryError> {
    OwnerSetId::from_bytes(parse_identifier(value)?).map_err(|_| RepositoryError::CorruptState)
}

fn parse_identifier(value: &[u8]) -> Result<[u8; 16], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}
