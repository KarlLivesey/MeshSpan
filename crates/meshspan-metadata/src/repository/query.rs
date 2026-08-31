// SPDX-License-Identifier: GPL-2.0-only

//! Typed point reads and index-aligned bounded pagination.

use meshspan_domain::{GroupId, ObjectId, OwnerSetId, PrincipalId, Revision, UnixMicros, VolumeId};
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
    /// Original authoritative creation instant.
    pub created_at: UnixMicros,
    /// Last authoritative record revision.
    pub revision: Revision,
}

/// Stable principal seek cursor bound to one principal family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrincipalCursor {
    kind: PrincipalKind,
    canonical_name: String,
    principal_id: PrincipalId,
}

impl PrincipalCursor {
    /// Reconstructs a cursor after a public boundary has validated its fields.
    #[must_use]
    pub fn new(kind: PrincipalKind, canonical_name: String, principal_id: PrincipalId) -> Self {
        Self {
            kind,
            canonical_name,
            principal_id,
        }
    }

    /// Returns the principal family to which this continuation is bound.
    #[must_use]
    pub const fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// Returns the exact canonical seek name.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    /// Returns the exact seek identity.
    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }
}

/// Stable namespace seek cursor, opaque to higher-level public APIs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceCursor {
    canonical_name: String,
    object_id: ObjectId,
}

/// Stable direct-membership seek cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupMemberCursor {
    group_id: GroupId,
    member_principal_id: PrincipalId,
}

impl GroupMemberCursor {
    /// Reconstructs a cursor after a public boundary has validated its fields.
    #[must_use]
    pub const fn new(group_id: GroupId, member_principal_id: PrincipalId) -> Self {
        Self {
            group_id,
            member_principal_id,
        }
    }

    /// Returns the group to which this continuation is bound.
    #[must_use]
    pub const fn group_id(self) -> GroupId {
        self.group_id
    }

    /// Returns the exact last member identity.
    #[must_use]
    pub const fn member_principal_id(self) -> PrincipalId {
        self.member_principal_id
    }
}

/// One current direct-group-membership edge and its member projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMembershipRecord {
    /// Structurally containing group.
    pub group_id: GroupId,
    /// Direct user or nested-group member.
    pub member: PrincipalRecord,
    /// Inclusive validity start, or no lower bound.
    pub valid_from: Option<UnixMicros>,
    /// Exclusive validity end, or no upper bound.
    pub valid_until: Option<UnixMicros>,
    /// Whether a current user activation is required before this edge contributes rights.
    pub activation_required: bool,
    /// Principal that created the current edge.
    pub created_by: PrincipalId,
    /// Original creation instant of the current edge.
    pub created_at: UnixMicros,
    /// Last authoritative edge revision.
    pub revision: Revision,
}

/// Closed mutation families retained in immutable direct-membership history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupMembershipEventKind {
    /// A direct edge was created or recreated.
    Added,
    /// An active direct edge was removed.
    Removed,
}

/// Immutable evidence for one direct-membership mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMembershipEventRecord {
    /// Structurally containing group.
    pub group_id: GroupId,
    /// Direct user or nested-group member affected by the mutation.
    pub member_principal_id: PrincipalId,
    /// Mutation family committed at this revision.
    pub kind: GroupMembershipEventKind,
    /// Principal that authorised the mutation.
    pub actor_principal_id: PrincipalId,
    /// Original authoritative mutation instant.
    pub occurred_at: UnixMicros,
    /// Exact authoritative mutation revision.
    pub revision: Revision,
}

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
            "SELECT principal_kind, display_name, canonical_name, state, created_at, revision
             FROM principals WHERE principal_id = ?1",
            [identifier.as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
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
                created_at: UnixMicros::new(row.4),
                revision: Revision::new(parse_u64(row.5)?),
            })
        })
        .transpose()
}

pub(super) fn principals(
    database: &PartitionDatabase,
    kind: PrincipalKind,
    after: Option<&PrincipalCursor>,
    limit: PageLimit,
) -> Result<Page<PrincipalRecord, PrincipalCursor>, RepositoryError> {
    if after.is_some_and(|cursor| cursor.kind != kind) {
        return Err(RepositoryError::StaleRevision);
    }
    let kind_code = principal_kind_code(kind);
    let after_name = after.map_or("", |cursor| cursor.canonical_name.as_str());
    let after_id = after.map_or([0; 16], |cursor| cursor.principal_id.as_bytes());
    let row_limit = sql_limit(limit)?;
    let mut statement = database.connection().prepare(
        "SELECT principal_id, display_name, canonical_name, state, created_at, revision
         FROM principals INDEXED BY principals_by_kind_and_name
         WHERE principal_kind = ?1
           AND (canonical_name, principal_id) > (?2, ?3)
         ORDER BY canonical_name, principal_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![kind_code, after_name, after_id.as_slice(), row_limit],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        let row = row?;
        items.push(PrincipalRecord {
            principal_id: parse_principal(&row.0)?,
            kind,
            display_name: row.1,
            canonical_name: row.2,
            state: u8::try_from(row.3).map_err(|_| RepositoryError::CorruptState)?,
            created_at: UnixMicros::new(row.4),
            revision: Revision::new(parse_u64(row.5)?),
        });
    }
    let next = (items.len() > limit.get()).then(|| {
        let last = &items[limit.get() - 1];
        PrincipalCursor::new(kind, last.canonical_name.clone(), last.principal_id)
    });
    items.truncate(limit.get());
    Ok(Page { items, next })
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
    let lower = match after {
        Some(cursor) if cursor.group_id == group_id => cursor.member_principal_id.as_bytes(),
        Some(_) => return Err(RepositoryError::StaleRevision),
        None => [0; 16],
    };
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
    let next = (items.len() > limit.get()).then(|| GroupMemberCursor {
        group_id,
        member_principal_id: items[limit.get() - 1],
    });
    items.truncate(limit.get());
    Ok(Page { items, next })
}

pub(super) fn direct_group_memberships(
    database: &PartitionDatabase,
    group_id: GroupId,
    after: Option<GroupMemberCursor>,
    limit: PageLimit,
) -> Result<Page<GroupMembershipRecord, GroupMemberCursor>, RepositoryError> {
    let group = group_id.as_bytes();
    let lower = membership_lower_bound(group_id, after)?;
    let mut statement = database.connection().prepare(
        "SELECT gm.member_principal_id, gm.valid_from, gm.valid_until,
                gm.activation_required, gm.created_by, gm.created_at, gm.revision,
                p.principal_kind, p.display_name, p.canonical_name, p.state,
                p.created_at, p.revision
         FROM group_memberships gm
         JOIN principals p ON p.principal_id = gm.member_principal_id
         WHERE gm.containing_group_id = ?1 AND gm.state = 1
           AND gm.member_principal_id > ?2
         ORDER BY gm.member_principal_id LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![group.as_slice(), lower.as_slice(), sql_limit(limit)?],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, i64>(12)?,
            ))
        },
    )?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        items.push(parse_group_membership(group_id, row?)?);
    }
    let next = (items.len() > limit.get())
        .then(|| GroupMemberCursor::new(group_id, items[limit.get() - 1].member.principal_id));
    items.truncate(limit.get());
    Ok(Page { items, next })
}

pub(super) fn direct_group_membership(
    database: &PartitionDatabase,
    group_id: GroupId,
    member_principal_id: PrincipalId,
) -> Result<Option<GroupMembershipRecord>, RepositoryError> {
    let group = group_id.as_bytes();
    let member = member_principal_id.as_bytes();
    database
        .connection()
        .query_row(
            "SELECT gm.member_principal_id, gm.valid_from, gm.valid_until,
                    gm.activation_required, gm.created_by, gm.created_at, gm.revision,
                    p.principal_kind, p.display_name, p.canonical_name, p.state,
                    p.created_at, p.revision
             FROM group_memberships gm
             JOIN principals p ON p.principal_id = gm.member_principal_id
             WHERE gm.containing_group_id = ?1 AND gm.member_principal_id = ?2
               AND gm.state = 1",
            params![group.as_slice(), member.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            },
        )
        .optional()?
        .map(|row| parse_group_membership(group_id, row))
        .transpose()
}

pub(super) fn group_membership_event(
    database: &PartitionDatabase,
    group_id: GroupId,
    revision: Revision,
) -> Result<Option<GroupMembershipEventRecord>, RepositoryError> {
    if revision == Revision::ZERO {
        return Err(RepositoryError::CorruptState);
    }
    let group = group_id.as_bytes();
    let mut statement = database.connection().prepare(
        "SELECT member_principal_id, event_kind, reason, actor_principal_id, occurred_at
         FROM group_membership_events INDEXED BY group_membership_events_by_revision
         WHERE revision = ?1 AND containing_group_id = ?2
         ORDER BY member_principal_id LIMIT 2",
    )?;
    let stored_revision =
        i64::try_from(revision.get()).map_err(|_| RepositoryError::CorruptState)?;
    let rows = statement.query_map(params![stored_revision, group.as_slice()], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    let mut events = rows.collect::<Result<Vec<_>, _>>()?;
    if events.len() > 1 {
        return Err(RepositoryError::CorruptState);
    }
    events
        .pop()
        .map(|row| parse_group_membership_event(group_id, revision, &row))
        .transpose()
}

type GroupMembershipRow = (
    Vec<u8>,
    Option<i64>,
    Option<i64>,
    i64,
    Vec<u8>,
    i64,
    i64,
    i64,
    String,
    String,
    i64,
    i64,
    i64,
);

type GroupMembershipEventRow = (Vec<u8>, i64, Option<String>, Vec<u8>, i64);

fn membership_lower_bound(
    group_id: GroupId,
    after: Option<GroupMemberCursor>,
) -> Result<[u8; 16], RepositoryError> {
    match after {
        Some(cursor) if cursor.group_id == group_id => Ok(cursor.member_principal_id.as_bytes()),
        Some(_) => Err(RepositoryError::StaleRevision),
        None => Ok([0; 16]),
    }
}

fn parse_group_membership(
    group_id: GroupId,
    row: GroupMembershipRow,
) -> Result<GroupMembershipRecord, RepositoryError> {
    let member_id = parse_principal(&row.0)?;
    let valid_from = row.1.map(UnixMicros::new);
    let valid_until = row.2.map(UnixMicros::new);
    if valid_until
        .zip(valid_from)
        .is_some_and(|(until, from)| until <= from)
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(GroupMembershipRecord {
        group_id,
        member: PrincipalRecord {
            principal_id: member_id,
            kind: parse_principal_kind(row.7)?,
            display_name: row.8,
            canonical_name: row.9,
            state: u8::try_from(row.10).map_err(|_| RepositoryError::CorruptState)?,
            created_at: UnixMicros::new(row.11),
            revision: Revision::new(parse_u64(row.12)?),
        },
        valid_from,
        valid_until,
        activation_required: match row.3 {
            0 => false,
            1 => true,
            _ => return Err(RepositoryError::CorruptState),
        },
        created_by: parse_principal(&row.4)?,
        created_at: UnixMicros::new(row.5),
        revision: Revision::new(parse_u64(row.6)?),
    })
}

fn parse_group_membership_event(
    group_id: GroupId,
    revision: Revision,
    row: &GroupMembershipEventRow,
) -> Result<GroupMembershipEventRecord, RepositoryError> {
    let kind = match (row.1, row.2.as_deref()) {
        (1, None) => GroupMembershipEventKind::Added,
        (2, Some(reason)) if !reason.is_empty() && reason.len() <= 512 => {
            GroupMembershipEventKind::Removed
        }
        _ => return Err(RepositoryError::CorruptState),
    };
    Ok(GroupMembershipEventRecord {
        group_id,
        member_principal_id: parse_principal(&row.0)?,
        kind,
        actor_principal_id: parse_principal(&row.3)?,
        occurred_at: UnixMicros::new(row.4),
        revision,
    })
}

pub(super) fn sql_limit(limit: PageLimit) -> Result<i64, RepositoryError> {
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

const fn principal_kind_code(kind: PrincipalKind) -> i64 {
    match kind {
        PrincipalKind::User => 1,
        PrincipalKind::Group => 2,
        PrincipalKind::Service => 3,
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

pub(super) fn parse_identifier(value: &[u8]) -> Result<[u8; 16], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}
