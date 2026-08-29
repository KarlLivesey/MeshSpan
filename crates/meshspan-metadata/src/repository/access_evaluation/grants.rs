// SPDX-License-Identifier: GPL-2.0-only

//! Owner and allow-grant contributions to a namespace access decision.

use std::collections::BTreeMap;

use meshspan_domain::{GrantId, PrincipalId, Rights, UnixMicros};
use rusqlite::params;

use super::authority::{parse_grant, parse_object, parse_principal, to_i64};
use super::subjects::earliest;
use super::{GrantEvaluation, RightLifetime, Session};
use crate::PartitionDatabase;
use crate::repository::RepositoryError;

const MAXIMUM_GRANTS: usize = 65_536;
const MAXIMUM_OWNERS: usize = 1_024;

pub(super) fn load_grant_activations(
    database: &PartitionDatabase,
    session: Session,
    now: UnixMicros,
) -> Result<BTreeMap<GrantId, UnixMicros>, RepositoryError> {
    let principal = session.principal_id.as_bytes();
    let mut statement = database.connection().prepare(
        "SELECT a.grant_id, MAX(a.expires_at)
         FROM access_activations a
         JOIN permission_grants pg ON pg.grant_id = a.grant_id
         JOIN access_activation_policies ap ON ap.policy_id = a.policy_id
         WHERE a.principal_id = ?1 AND a.grant_id IS NOT NULL
           AND a.revoked_at IS NULL AND a.activated_at <= ?2 AND a.expires_at > ?2
           AND a.identity_revision = ?3 AND a.source_revision = pg.revision
           AND a.policy_revision = ap.revision AND pg.activation_policy_id = a.policy_id
         GROUP BY a.grant_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            principal.as_slice(),
            now.get(),
            to_i64(session.identity_revision.get())?,
            to_i64(
                u64::try_from(MAXIMUM_GRANTS + 1).map_err(|_| RepositoryError::CapacityExceeded)?
            )?
        ],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let mut activations = BTreeMap::new();
    for row in rows {
        let (grant, expires_at) = row?;
        if activations.len() == MAXIMUM_GRANTS {
            return Err(RepositoryError::CapacityExceeded);
        }
        activations.insert(parse_grant(&grant)?, UnixMicros::new(expires_at));
    }
    Ok(activations)
}

pub(super) fn apply_ownership(
    database: &PartitionDatabase,
    owner_set_id: [u8; 16],
    subjects: &BTreeMap<PrincipalId, Option<UnixMicros>>,
    rights: &mut [RightLifetime; super::DEFINED_RIGHTS],
) -> Result<(), RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT owner_principal_id FROM object_owners
         WHERE owner_set_id = ?1 ORDER BY owner_principal_id LIMIT 1025",
    )?;
    let rows = statement.query_map([owner_set_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))?;
    let mut count = 0_usize;
    for row in rows {
        count += 1;
        if count > MAXIMUM_OWNERS {
            return Err(RepositoryError::CapacityExceeded);
        }
        if let Some(expiry) = subjects.get(&parse_principal(&row?)?) {
            super::contribute(rights, Rights::ALL, *expiry);
        }
    }
    if count == 0 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(())
}

pub(super) fn apply_grants(
    database: &PartitionDatabase,
    evaluation: GrantEvaluation<'_>,
    rights: &mut [RightLifetime; super::DEFINED_RIGHTS],
) -> Result<(), RepositoryError> {
    let user = evaluation.principal_id.as_bytes();
    let mut statement = database.connection().prepare(
        "SELECT grant_id, subject_principal_id, scope_kind, volume_id, object_id, rights,
                inheritance, valid_until, activation_policy_id
         FROM permission_grants
         WHERE state = 1 AND (valid_from IS NULL OR valid_from <= ?1)
           AND (valid_until IS NULL OR valid_until > ?1)
           AND (scope_kind = 1 OR volume_id = ?2)
           AND (subject_principal_id = ?3 OR subject_principal_id IN (
                SELECT containing_group_id FROM group_closure WHERE member_principal_id = ?3
           ))
         ORDER BY grant_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            evaluation.request.now.get(),
            evaluation.request.volume_id.as_bytes().as_slice(),
            user.as_slice(),
            to_i64(
                u64::try_from(MAXIMUM_GRANTS + 1).map_err(|_| RepositoryError::CapacityExceeded)?
            )?
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<Vec<u8>>>(8)?,
            ))
        },
    )?;
    let mut count = 0_usize;
    for row in rows {
        count += 1;
        if count > MAXIMUM_GRANTS {
            return Err(RepositoryError::CapacityExceeded);
        }
        let (grant, subject, scope, volume, object, stored_rights, inheritance, until, policy) =
            row?;
        let subject = parse_principal(&subject)?;
        let Some(subject_expiry) = evaluation.subjects.get(&subject).copied() else {
            continue;
        };
        if !grant_applies(
            evaluation,
            scope,
            volume.as_deref(),
            object.as_deref(),
            inheritance,
        )? {
            continue;
        }
        let grant_id = parse_grant(&grant)?;
        let activation_expiry = if policy.is_some() {
            let Some(expiry) = evaluation.activations.get(&grant_id) else {
                continue;
            };
            Some(*expiry)
        } else {
            None
        };
        let expiry = earliest([
            subject_expiry,
            until.map(UnixMicros::new),
            activation_expiry,
        ]);
        let bits = u32::try_from(stored_rights).map_err(|_| RepositoryError::CorruptState)?;
        let grant_rights = Rights::from_bits(bits).map_err(|_| RepositoryError::CorruptState)?;
        if grant_rights == Rights::default() {
            return Err(RepositoryError::CorruptState);
        }
        super::contribute(rights, grant_rights, expiry);
    }
    Ok(())
}

fn grant_applies(
    evaluation: GrantEvaluation<'_>,
    scope: i64,
    volume: Option<&[u8]>,
    object: Option<&[u8]>,
    inheritance: i64,
) -> Result<bool, RepositoryError> {
    if !matches!(inheritance, 1..=3) {
        return Err(RepositoryError::CorruptState);
    }
    let exact = inheritance != 2;
    let descendants = inheritance != 1;
    match scope {
        1 if volume.is_none() && object.is_none() => {
            Ok(evaluation.inherits_volume_grants && descendants)
        }
        2 if volume == Some(evaluation.request.volume_id.as_bytes().as_slice())
            && object.is_none() =>
        {
            Ok(evaluation.inherits_volume_grants
                && ((evaluation.target_is_root && exact)
                    || (!evaluation.target_is_root && descendants)))
        }
        3 if volume == Some(evaluation.request.volume_id.as_bytes().as_slice()) => {
            let scoped = parse_object(object.ok_or(RepositoryError::CorruptState)?)?;
            Ok((scoped == evaluation.request.object_id && exact)
                || (evaluation.ancestors.contains(&scoped) && descendants))
        }
        _ => Err(RepositoryError::CorruptState),
    }
}
