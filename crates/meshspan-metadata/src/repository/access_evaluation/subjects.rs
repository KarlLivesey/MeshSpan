// SPDX-License-Identifier: GPL-2.0-only

//! Active nested-group and group-activation projection for one user.

use std::collections::{BTreeMap, VecDeque};

use meshspan_domain::{PrincipalId, UnixMicros};
use rusqlite::params;

use super::AuthenticatedPrincipal;
use super::authority::{parse_principal, to_i64};
use crate::PartitionDatabase;
use crate::repository::RepositoryError;

const MAXIMUM_MEMBERSHIPS: usize = 65_536;

#[derive(Clone, Copy)]
struct MembershipEdge {
    containing_group: PrincipalId,
    member: PrincipalId,
    expires_at: Option<UnixMicros>,
    requires_activation: bool,
}

pub(super) fn load_group_activations(
    database: &PartitionDatabase,
    authentication: AuthenticatedPrincipal,
    now: UnixMicros,
) -> Result<BTreeMap<PrincipalId, UnixMicros>, RepositoryError> {
    load_group_activations_for_principal(
        database,
        authentication.principal_id,
        authentication.identity_revision,
        now,
    )
}

pub(crate) fn load_effective_subjects_for_principal(
    database: &PartitionDatabase,
    principal_id: PrincipalId,
    identity_revision: meshspan_domain::Revision,
    now: UnixMicros,
) -> Result<BTreeMap<PrincipalId, Option<UnixMicros>>, RepositoryError> {
    let activations =
        load_group_activations_for_principal(database, principal_id, identity_revision, now)?;
    load_effective_subjects_inner(database, principal_id, now, &activations)
}

pub(super) fn load_effective_subjects(
    database: &PartitionDatabase,
    authentication: AuthenticatedPrincipal,
    now: UnixMicros,
    activations: &BTreeMap<PrincipalId, UnixMicros>,
) -> Result<BTreeMap<PrincipalId, Option<UnixMicros>>, RepositoryError> {
    load_effective_subjects_inner(database, authentication.principal_id, now, activations)
}

fn load_effective_subjects_inner(
    database: &PartitionDatabase,
    principal_id: PrincipalId,
    now: UnixMicros,
    activations: &BTreeMap<PrincipalId, UnixMicros>,
) -> Result<BTreeMap<PrincipalId, Option<UnixMicros>>, RepositoryError> {
    let edges = load_active_memberships(database, principal_id, now)?;
    let mut by_member = BTreeMap::<PrincipalId, Vec<MembershipEdge>>::new();
    for edge in edges {
        by_member.entry(edge.member).or_default().push(edge);
    }
    let mut subjects = BTreeMap::from([(principal_id, None)]);
    let mut pending = VecDeque::from([principal_id]);
    while let Some(member) = pending.pop_front() {
        let member_expiry = subjects.get(&member).copied().flatten();
        for edge in by_member.get(&member).cloned().unwrap_or_default() {
            let activation_expiry = if edge.requires_activation {
                let Some(expires_at) = activations.get(&edge.containing_group) else {
                    continue;
                };
                Some(*expires_at)
            } else {
                None
            };
            let expiry = earliest([member_expiry, edge.expires_at, activation_expiry]);
            if extends_subject(subjects.get(&edge.containing_group), expiry) {
                subjects.insert(edge.containing_group, expiry);
                pending.push_back(edge.containing_group);
            }
        }
        if subjects.len() > MAXIMUM_MEMBERSHIPS {
            return Err(RepositoryError::CapacityExceeded);
        }
    }
    Ok(subjects)
}

fn load_group_activations_for_principal(
    database: &PartitionDatabase,
    principal_id: PrincipalId,
    identity_revision: meshspan_domain::Revision,
    now: UnixMicros,
) -> Result<BTreeMap<PrincipalId, UnixMicros>, RepositoryError> {
    let principal = principal_id.as_bytes();
    let mut statement = database.connection().prepare(
        "SELECT a.group_id, MAX(a.expires_at)
         FROM access_activations a
         JOIN groups g ON g.principal_id = a.group_id
         JOIN principals p ON p.principal_id = g.principal_id
         JOIN access_activation_policies ap ON ap.policy_id = a.policy_id
         WHERE a.principal_id = ?1 AND a.group_id IS NOT NULL
           AND a.revoked_at IS NULL AND a.activated_at <= ?2 AND a.expires_at > ?2
           AND a.identity_revision = ?3 AND a.source_revision = p.revision
           AND a.policy_revision = ap.revision AND g.activation_policy_id = a.policy_id
         GROUP BY a.group_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            principal.as_slice(),
            now.get(),
            to_i64(identity_revision.get())?,
            to_i64(
                u64::try_from(MAXIMUM_MEMBERSHIPS + 1)
                    .map_err(|_| RepositoryError::CapacityExceeded)?
            )?,
        ],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let mut activations = BTreeMap::new();
    for row in rows {
        let (group, expires_at) = row?;
        if activations.len() == MAXIMUM_MEMBERSHIPS {
            return Err(RepositoryError::CapacityExceeded);
        }
        activations.insert(parse_principal(&group)?, UnixMicros::new(expires_at));
    }
    Ok(activations)
}

fn load_active_memberships(
    database: &PartitionDatabase,
    principal_id: PrincipalId,
    now: UnixMicros,
) -> Result<Vec<MembershipEdge>, RepositoryError> {
    let principal = principal_id.as_bytes();
    let mut statement = database.connection().prepare(
        "SELECT gm.containing_group_id, gm.member_principal_id, gm.valid_until,
                gm.activation_required, g.activation_policy_id
         FROM group_memberships gm
         JOIN groups g ON g.principal_id = gm.containing_group_id
         JOIN principals p ON p.principal_id = g.principal_id
         WHERE gm.state = 1 AND p.state = 1
           AND (gm.valid_from IS NULL OR gm.valid_from <= ?1)
           AND (gm.valid_until IS NULL OR gm.valid_until > ?1)
           AND (gm.member_principal_id = ?2 OR gm.member_principal_id IN (
                SELECT containing_group_id FROM group_closure WHERE member_principal_id = ?2
           ))
         ORDER BY gm.member_principal_id, gm.containing_group_id LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![
            now.get(),
            principal.as_slice(),
            to_i64(
                u64::try_from(MAXIMUM_MEMBERSHIPS + 1)
                    .map_err(|_| RepositoryError::CapacityExceeded)?
            )?
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
            ))
        },
    )?;
    let mut edges = Vec::new();
    for row in rows {
        let (group, member, valid_until, activation_required, policy) = row?;
        if edges.len() == MAXIMUM_MEMBERSHIPS {
            return Err(RepositoryError::CapacityExceeded);
        }
        if !matches!(activation_required, 0 | 1) {
            return Err(RepositoryError::CorruptState);
        }
        if activation_required == 1 && policy.is_none() {
            return Err(RepositoryError::CorruptState);
        }
        edges.push(MembershipEdge {
            containing_group: parse_principal(&group)?,
            member: parse_principal(&member)?,
            expires_at: valid_until.map(UnixMicros::new),
            requires_activation: activation_required == 1 || policy.is_some(),
        });
    }
    Ok(edges)
}

fn extends_subject(current: Option<&Option<UnixMicros>>, candidate: Option<UnixMicros>) -> bool {
    match current {
        None => true,
        Some(existing) => extends_expiry(*existing, candidate),
    }
}

fn extends_expiry(current: Option<UnixMicros>, candidate: Option<UnixMicros>) -> bool {
    match (current, candidate) {
        (Some(old), Some(new)) => new > old,
        (Some(_), None) => true,
        _ => false,
    }
}

pub(super) fn earliest<const N: usize>(values: [Option<UnixMicros>; N]) -> Option<UnixMicros> {
    values.into_iter().flatten().min()
}
