// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, index-aligned current access-administration projections.

use meshspan_domain::{
    ActivationId, ActivationPolicyId, ActivationSubject, GrantId, GroupId, ObjectId, OwnerSetId,
    PrincipalId, Revision, Rights, UnixMicros,
};
use rusqlite::{OptionalExtension, Row, params};

use super::RepositoryError;
use super::query::{Page, PageLimit, parse_identifier, sql_limit};
use crate::{GrantInheritance, PartitionDatabase, PermissionScope};

/// Seek cursor bound to one exact object owner-set revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectOwnerCursor {
    object_id: ObjectId,
    owner_set_id: OwnerSetId,
    object_revision: Revision,
    owner_principal_id: PrincipalId,
}

/// One directly assigned owner of the object's current immutable owner set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectOwnerRecord {
    /// Stable object whose current owner set was queried.
    pub object_id: ObjectId,
    /// Immutable owner-set identity selected by the object.
    pub owner_set_id: OwnerSetId,
    /// User or group directly named as an owner.
    pub owner_principal_id: PrincipalId,
    /// Principal that assigned this owner set.
    pub assigned_by: PrincipalId,
    /// Authoritative assignment instant.
    pub assigned_at: UnixMicros,
    /// Revision of this owner assignment.
    pub revision: Revision,
}

/// Seek cursor bound to one exact permission scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopedGrantCursor {
    scope: PermissionScope,
    grant_id: GrantId,
}

/// Seek cursor bound to one exact permission subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubjectGrantCursor {
    subject_principal_id: PrincipalId,
    grant_id: GrantId,
}

/// One current allow-only permission grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionGrantRecord {
    /// Stable grant identity.
    pub grant_id: GrantId,
    /// User or group receiving the rights.
    pub subject_principal_id: PrincipalId,
    /// Exact global, volume or object scope.
    pub scope: PermissionScope,
    /// Non-empty protocol-neutral rights.
    pub rights: Rights,
    /// Explicit descendant behaviour.
    pub inheritance: GrantInheritance,
    /// Inclusive validity start, when bounded.
    pub valid_from: Option<UnixMicros>,
    /// Exclusive validity end, when bounded.
    pub valid_until: Option<UnixMicros>,
    /// Optional policy requiring self-activation.
    pub activation_policy_id: Option<ActivationPolicyId>,
    /// Principal that created the grant.
    pub created_by: PrincipalId,
    /// Authoritative creation instant.
    pub created_at: UnixMicros,
    /// Current authoritative grant revision.
    pub revision: Revision,
}

/// Seek cursor bound to one principal and one authoritative observation instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessActivationCursor {
    principal_id: PrincipalId,
    observed_at: UnixMicros,
    activation_id: ActivationId,
}

/// One non-revoked, non-expired activation record current at the query instant.
///
/// This is an administration projection, not an authority decision. The source grant, group,
/// membership, policy and session are revalidated independently when access is evaluated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessActivationRecord {
    /// Stable activation identity.
    pub activation_id: ActivationId,
    /// User receiving the temporarily active authority.
    pub principal_id: PrincipalId,
    /// Exact group or grant activated by the user.
    pub subject: ActivationSubject,
    /// Policy that bounded the activation.
    pub policy_id: ActivationPolicyId,
    /// Bounded audit reason supplied during activation.
    pub reason: String,
    /// Authoritative activation instant.
    pub activated_at: UnixMicros,
    /// Exclusive expiry instant.
    pub expires_at: UnixMicros,
    /// Current activation revision.
    pub revision: Revision,
}

pub(super) fn object_owners(
    database: &PartitionDatabase,
    object_id: ObjectId,
    after: Option<ObjectOwnerCursor>,
    limit: PageLimit,
) -> Result<Option<Page<ObjectOwnerRecord, ObjectOwnerCursor>>, RepositoryError> {
    let object = object_id.as_bytes();
    let source = database
        .connection()
        .query_row(
            "SELECT owner_set_id, revision FROM namespace_objects
             WHERE object_id = ?1 AND state = 1",
            [object.as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((owner_set, object_revision)) = source else {
        return if after.is_some() {
            Err(RepositoryError::StaleRevision)
        } else {
            Ok(None)
        };
    };
    let owner_set_id = owner_set_id(&owner_set)?;
    let object_revision = revision(object_revision)?;
    let lower = validate_owner_cursor(after, object_id, owner_set_id, object_revision)?;
    let mut statement = database.connection().prepare(
        "SELECT owner_principal_id, assigned_by, assigned_at, revision
         FROM object_owners
         WHERE owner_set_id = ?1 AND owner_principal_id > ?2
         ORDER BY owner_principal_id LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![owner_set.as_slice(), lower.as_slice(), sql_limit(limit)?],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        let row = row?;
        items.push(ObjectOwnerRecord {
            object_id,
            owner_set_id,
            owner_principal_id: principal_id(&row.0)?,
            assigned_by: principal_id(&row.1)?,
            assigned_at: UnixMicros::new(row.2),
            revision: revision(row.3)?,
        });
    }
    let next = page_next(&mut items, limit).map(|last| ObjectOwnerCursor {
        object_id,
        owner_set_id,
        object_revision,
        owner_principal_id: last.owner_principal_id,
    });
    Ok(Some(Page { items, next }))
}

pub(super) fn permission_grants_for_scope(
    database: &PartitionDatabase,
    scope: PermissionScope,
    after: Option<ScopedGrantCursor>,
    limit: PageLimit,
) -> Result<Page<PermissionGrantRecord, ScopedGrantCursor>, RepositoryError> {
    let lower = validate_scope_cursor(after, scope)?;
    let (kind, volume, object) = scope_columns(scope);
    let mut statement = database.connection().prepare(
        "SELECT grant_id, subject_principal_id, scope_kind, volume_id, object_id, rights,
                inheritance, valid_from, valid_until, activation_policy_id, created_by,
                created_at, revision
         FROM permission_grants INDEXED BY permission_grants_active_by_scope_seek
         WHERE state = 1 AND scope_kind = ?1 AND volume_id IS ?2 AND object_id IS ?3
           AND grant_id > ?4
         ORDER BY grant_id LIMIT ?5",
    )?;
    let rows = statement.query_map(
        params![
            kind,
            volume.as_ref().map(<[u8; 16]>::as_slice),
            object.as_ref().map(<[u8; 16]>::as_slice),
            lower.as_slice(),
            sql_limit(limit)?
        ],
        read_grant_row,
    )?;
    let mut items = collect_grants(rows, limit)?;
    let next = page_next(&mut items, limit).map(|last| ScopedGrantCursor {
        scope,
        grant_id: last.grant_id,
    });
    Ok(Page { items, next })
}

pub(super) fn permission_grants_for_subject(
    database: &PartitionDatabase,
    subject_principal_id: PrincipalId,
    after: Option<SubjectGrantCursor>,
    limit: PageLimit,
) -> Result<Page<PermissionGrantRecord, SubjectGrantCursor>, RepositoryError> {
    let lower = validate_subject_cursor(after, subject_principal_id)?;
    let subject = subject_principal_id.as_bytes();
    let mut statement = database.connection().prepare(
        "SELECT grant_id, subject_principal_id, scope_kind, volume_id, object_id, rights,
                inheritance, valid_from, valid_until, activation_policy_id, created_by,
                created_at, revision
         FROM permission_grants INDEXED BY permission_grants_active_by_subject_seek
         WHERE state = 1 AND subject_principal_id = ?1 AND grant_id > ?2
         ORDER BY grant_id LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![subject.as_slice(), lower.as_slice(), sql_limit(limit)?],
        read_grant_row,
    )?;
    let mut items = collect_grants(rows, limit)?;
    let next = page_next(&mut items, limit).map(|last| SubjectGrantCursor {
        subject_principal_id,
        grant_id: last.grant_id,
    });
    Ok(Page { items, next })
}

pub(super) fn unrevoked_access_activations(
    database: &PartitionDatabase,
    principal_id: PrincipalId,
    observed_at: UnixMicros,
    after: Option<AccessActivationCursor>,
    limit: PageLimit,
) -> Result<Page<AccessActivationRecord, AccessActivationCursor>, RepositoryError> {
    let lower = validate_activation_cursor(after, principal_id, observed_at)?;
    let principal = principal_id.as_bytes();
    let mut statement = database.connection().prepare(
        "SELECT activation_id, group_id, grant_id, policy_id, reason,
                activated_at, expires_at, revision
         FROM access_activations INDEXED BY access_activations_live_by_principal_seek
         WHERE principal_id = ?1 AND revoked_at IS NULL AND expires_at > ?2
           AND activation_id > ?3
         ORDER BY activation_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            principal.as_slice(),
            observed_at.get(),
            lower.as_slice(),
            sql_limit(limit)?
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
            ))
        },
    )?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        let row = row?;
        items.push(AccessActivationRecord {
            activation_id: activation_id(&row.0)?,
            principal_id,
            subject: activation_subject(row.1.as_deref(), row.2.as_deref())?,
            policy_id: activation_policy_id(&row.3)?,
            reason: row.4,
            activated_at: UnixMicros::new(row.5),
            expires_at: UnixMicros::new(row.6),
            revision: revision(row.7)?,
        });
    }
    let next = page_next(&mut items, limit).map(|last| AccessActivationCursor {
        principal_id,
        observed_at,
        activation_id: last.activation_id,
    });
    Ok(Page { items, next })
}

fn read_grant_row(row: &Row<'_>) -> rusqlite::Result<GrantRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
    ))
}

type GrantRow = (
    Vec<u8>,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    Option<Vec<u8>>,
    Vec<u8>,
    i64,
    i64,
);

fn collect_grants(
    rows: rusqlite::MappedRows<'_, impl FnMut(&Row<'_>) -> rusqlite::Result<GrantRow>>,
    limit: PageLimit,
) -> Result<Vec<PermissionGrantRecord>, RepositoryError> {
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        let row = row?;
        items.push(PermissionGrantRecord {
            grant_id: grant_id(&row.0)?,
            subject_principal_id: principal_id(&row.1)?,
            scope: permission_scope(row.2, row.3.as_deref(), row.4.as_deref())?,
            rights: rights(row.5)?,
            inheritance: inheritance(row.6)?,
            valid_from: row.7.map(UnixMicros::new),
            valid_until: row.8.map(UnixMicros::new),
            activation_policy_id: row.9.as_deref().map(activation_policy_id).transpose()?,
            created_by: principal_id(&row.10)?,
            created_at: UnixMicros::new(row.11),
            revision: revision(row.12)?,
        });
    }
    Ok(items)
}

fn page_next<T>(items: &mut Vec<T>, limit: PageLimit) -> Option<&T> {
    (items.len() > limit.get()).then(|| {
        items.truncate(limit.get());
        &items[limit.get() - 1]
    })
}

fn validate_owner_cursor(
    after: Option<ObjectOwnerCursor>,
    object_id: ObjectId,
    owner_set_id: OwnerSetId,
    object_revision: Revision,
) -> Result<[u8; 16], RepositoryError> {
    match after {
        Some(cursor)
            if cursor.object_id == object_id
                && cursor.owner_set_id == owner_set_id
                && cursor.object_revision == object_revision =>
        {
            Ok(cursor.owner_principal_id.as_bytes())
        }
        Some(_) => Err(RepositoryError::StaleRevision),
        None => Ok([0; 16]),
    }
}

fn validate_scope_cursor(
    after: Option<ScopedGrantCursor>,
    scope: PermissionScope,
) -> Result<[u8; 16], RepositoryError> {
    match after {
        Some(cursor) if cursor.scope == scope => Ok(cursor.grant_id.as_bytes()),
        Some(_) => Err(RepositoryError::StaleRevision),
        None => Ok([0; 16]),
    }
}

fn validate_subject_cursor(
    after: Option<SubjectGrantCursor>,
    subject_principal_id: PrincipalId,
) -> Result<[u8; 16], RepositoryError> {
    match after {
        Some(cursor) if cursor.subject_principal_id == subject_principal_id => {
            Ok(cursor.grant_id.as_bytes())
        }
        Some(_) => Err(RepositoryError::StaleRevision),
        None => Ok([0; 16]),
    }
}

fn validate_activation_cursor(
    after: Option<AccessActivationCursor>,
    principal_id: PrincipalId,
    observed_at: UnixMicros,
) -> Result<[u8; 16], RepositoryError> {
    match after {
        Some(cursor)
            if cursor.principal_id == principal_id && cursor.observed_at == observed_at =>
        {
            Ok(cursor.activation_id.as_bytes())
        }
        Some(_) => Err(RepositoryError::StaleRevision),
        None => Ok([0; 16]),
    }
}

fn scope_columns(scope: PermissionScope) -> (i64, Option<[u8; 16]>, Option<[u8; 16]>) {
    match scope {
        PermissionScope::Global => (1, None, None),
        PermissionScope::Volume(volume_id) => (2, Some(volume_id.as_bytes()), None),
        PermissionScope::Object {
            volume_id,
            object_id,
        } => (3, Some(volume_id.as_bytes()), Some(object_id.as_bytes())),
    }
}

fn permission_scope(
    kind: i64,
    volume: Option<&[u8]>,
    object: Option<&[u8]>,
) -> Result<PermissionScope, RepositoryError> {
    match (kind, volume, object) {
        (1, None, None) => Ok(PermissionScope::Global),
        (2, Some(volume), None) => Ok(PermissionScope::Volume(volume_id(volume)?)),
        (3, Some(volume), Some(object)) => Ok(PermissionScope::Object {
            volume_id: volume_id(volume)?,
            object_id: object_id(object)?,
        }),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn activation_subject(
    group: Option<&[u8]>,
    grant: Option<&[u8]>,
) -> Result<ActivationSubject, RepositoryError> {
    match (group, grant) {
        (Some(group), None) => Ok(ActivationSubject::Group(group_id(group)?)),
        (None, Some(grant)) => Ok(ActivationSubject::Grant(grant_id(grant)?)),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn inheritance(value: i64) -> Result<GrantInheritance, RepositoryError> {
    match value {
        1 => Ok(GrantInheritance::Object),
        2 => Ok(GrantInheritance::Descendants),
        3 => Ok(GrantInheritance::ObjectAndDescendants),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn rights(value: i64) -> Result<Rights, RepositoryError> {
    u32::try_from(value)
        .map_err(|_| RepositoryError::CorruptState)
        .and_then(|bits| Rights::from_bits(bits).map_err(|_| RepositoryError::CorruptState))
        .and_then(|rights| {
            (rights != Rights::default())
                .then_some(rights)
                .ok_or(RepositoryError::CorruptState)
        })
}

fn revision(value: i64) -> Result<Revision, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .map(Revision::new)
        .ok_or(RepositoryError::CorruptState)
}

fn principal_id(value: &[u8]) -> Result<PrincipalId, RepositoryError> {
    PrincipalId::from_bytes(parse_identifier(value)?).map_err(|_| RepositoryError::CorruptState)
}

fn group_id(value: &[u8]) -> Result<GroupId, RepositoryError> {
    GroupId::from_bytes(parse_identifier(value)?).map_err(|_| RepositoryError::CorruptState)
}

fn object_id(value: &[u8]) -> Result<ObjectId, RepositoryError> {
    ObjectId::from_bytes(parse_identifier(value)?).map_err(|_| RepositoryError::CorruptState)
}

fn owner_set_id(value: &[u8]) -> Result<OwnerSetId, RepositoryError> {
    OwnerSetId::from_bytes(parse_identifier(value)?).map_err(|_| RepositoryError::CorruptState)
}

fn volume_id(value: &[u8]) -> Result<meshspan_domain::VolumeId, RepositoryError> {
    meshspan_domain::VolumeId::from_bytes(parse_identifier(value)?)
        .map_err(|_| RepositoryError::CorruptState)
}

fn grant_id(value: &[u8]) -> Result<GrantId, RepositoryError> {
    GrantId::from_bytes(parse_identifier(value)?).map_err(|_| RepositoryError::CorruptState)
}

fn activation_id(value: &[u8]) -> Result<ActivationId, RepositoryError> {
    ActivationId::from_bytes(parse_identifier(value)?).map_err(|_| RepositoryError::CorruptState)
}

fn activation_policy_id(value: &[u8]) -> Result<ActivationPolicyId, RepositoryError> {
    ActivationPolicyId::from_bytes(parse_identifier(value)?)
        .map_err(|_| RepositoryError::CorruptState)
}
