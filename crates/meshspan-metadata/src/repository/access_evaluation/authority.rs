// SPDX-License-Identifier: GPL-2.0-only

//! Session, gateway and namespace authority projections used by access evaluation.

use std::collections::BTreeSet;

use meshspan_domain::{
    AssuranceLevel, GrantId, ObjectId, PrincipalId, Revision, SessionId, UnixMicros,
};
use rusqlite::{OptionalExtension, params};

use super::{AccessRequest, AuthorityRevisions, Session, Target};
use crate::PartitionDatabase;
use crate::repository::RepositoryError;

const MAXIMUM_ANCESTORS: usize = 1_024;

type TargetRow = (Vec<u8>, Option<Vec<u8>>, Vec<u8>, i64, i64);

pub(super) fn load_session(
    database: &PartitionDatabase,
    token_digest: [u8; 32],
    now: UnixMicros,
) -> Result<Option<Session>, RepositoryError> {
    let row = database
        .connection()
        .query_row(
            "SELECT s.session_id, s.user_principal_id, s.assurance, s.identity_revision,
                    s.expires_at
             FROM authentication_sessions s
             JOIN principals p ON p.principal_id = s.user_principal_id
             WHERE s.token_digest = ?1 AND s.revoked_at IS NULL AND s.issued_at <= ?2
               AND s.expires_at > ?2 AND p.state = 1",
            params![token_digest.as_slice(), now.get()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some(value) = row else {
        return Ok(None);
    };
    let session_id = parse_session(&value.0)?;
    let Some(factors) = super::super::session::active_factor_state(
        database.connection(),
        &session_id.as_bytes(),
        now,
    )?
    else {
        return Ok(None);
    };
    if factors.assurance != parse_assurance(value.2)? {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(Session {
        id: session_id,
        principal_id: parse_principal(&value.1)?,
        assurance: factors.assurance,
        latest_authenticated_at: factors.latest_authenticated_at,
        identity_revision: parse_revision(value.3)?,
        expires_at: UnixMicros::new(value.4),
    }))
}

pub(super) fn load_authority_revisions(
    database: &PartitionDatabase,
    request: AccessRequest,
) -> Result<AuthorityRevisions, RepositoryError> {
    let (identity, namespace) = database.connection().query_row(
        "SELECT identity_revision, namespace_revision FROM meshes LIMIT 2",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let node = request.gateway_node_id.as_bytes();
    let gateway: Option<i64> = database
        .connection()
        .query_row(
            "SELECT revision FROM nodes
             WHERE node_id = ?1 AND current_incarnation = ?2 AND state = 2",
            params![node.as_slice(), to_i64(request.gateway_incarnation)?],
            |row| row.get(0),
        )
        .optional()?;
    Ok(AuthorityRevisions {
        identity: parse_revision(identity)?,
        namespace: parse_revision(namespace)?,
        gateway: gateway.map_or(Ok(Revision::ZERO), parse_revision)?,
    })
}

pub(super) fn load_target_and_ancestors(
    database: &PartitionDatabase,
    request: AccessRequest,
) -> Result<Option<(Target, BTreeSet<ObjectId>)>, RepositoryError> {
    let mut ancestors = BTreeSet::new();
    let mut visited = BTreeSet::from([request.object_id]);
    let expected_volume = request.volume_id.as_bytes();
    let object = request.object_id.as_bytes();
    let row: Option<TargetRow> = database
        .connection()
        .query_row(
            "SELECT volume_id, parent_object_id, owner_set_id, revision,
                    stop_parent_grant_inheritance
             FROM namespace_objects WHERE object_id = ?1 AND state = 1",
            [object.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let Some((volume, parent, owners, revision, stop_parent)) = row else {
        return Ok(None);
    };
    if volume.as_slice() != expected_volume {
        return Ok(None);
    }
    let target_stops_inheritance = parse_boolean(stop_parent)?;
    let target = Target {
        object_revision: parse_revision(revision)?,
        owner_set_id: parse_identifier(&owners)?,
        is_root: parent.is_none(),
        inherits_volume_grants: !target_stops_inheritance,
    };
    let Some(parent) = parent else {
        return Ok(Some((target, ancestors)));
    };
    if target_stops_inheritance {
        return Ok(Some((target, ancestors)));
    }
    let mut parent_id = parse_object(&parent)?;
    ancestors.insert(parent_id);
    let inherits_volume_grants = load_remaining_ancestors(
        database,
        expected_volume,
        &mut ancestors,
        &mut visited,
        &mut parent_id,
    )?;
    let target = Target {
        inherits_volume_grants,
        ..target
    };
    Ok(Some((target, ancestors)))
}

fn load_remaining_ancestors(
    database: &PartitionDatabase,
    expected_volume: [u8; 16],
    ancestors: &mut BTreeSet<ObjectId>,
    visited: &mut BTreeSet<ObjectId>,
    current: &mut ObjectId,
) -> Result<bool, RepositoryError> {
    for _ in 0..MAXIMUM_ANCESTORS {
        if !visited.insert(*current) {
            return Err(RepositoryError::CorruptState);
        }
        let object = current.as_bytes();
        let row: (Vec<u8>, Option<Vec<u8>>, i64) = database.connection().query_row(
            "SELECT volume_id, parent_object_id, stop_parent_grant_inheritance
             FROM namespace_objects
             WHERE object_id = ?1 AND state = 1",
            [object.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if row.0.as_slice() != expected_volume {
            return Err(RepositoryError::CorruptState);
        }
        if parse_boolean(row.2)? {
            return Ok(false);
        }
        let Some(parent) = row.1 else {
            return Ok(true);
        };
        *current = parse_object(&parent)?;
        ancestors.insert(*current);
    }
    Err(RepositoryError::CapacityExceeded)
}

fn parse_boolean(value: i64) -> Result<bool, RepositoryError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RepositoryError::CorruptState),
    }
}

pub(super) fn parse_identifier(bytes: &[u8]) -> Result<[u8; 16], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
}

pub(super) fn parse_principal(bytes: &[u8]) -> Result<PrincipalId, RepositoryError> {
    PrincipalId::from_bytes(parse_identifier(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

pub(super) fn parse_object(bytes: &[u8]) -> Result<ObjectId, RepositoryError> {
    ObjectId::from_bytes(parse_identifier(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

pub(super) fn parse_grant(bytes: &[u8]) -> Result<GrantId, RepositoryError> {
    GrantId::from_bytes(parse_identifier(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

fn parse_session(bytes: &[u8]) -> Result<SessionId, RepositoryError> {
    SessionId::from_bytes(parse_identifier(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

pub(super) fn parse_revision(value: i64) -> Result<Revision, RepositoryError> {
    let revision = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if revision == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(Revision::new(revision))
    }
}

fn parse_assurance(value: i64) -> Result<AssuranceLevel, RepositoryError> {
    match value {
        1 => Ok(AssuranceLevel::SingleFactor),
        2 => Ok(AssuranceLevel::MultiFactor),
        3 => Ok(AssuranceLevel::RecentStepUp),
        _ => Err(RepositoryError::CorruptState),
    }
}

pub(super) fn to_i64(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::CapacityExceeded)
}
