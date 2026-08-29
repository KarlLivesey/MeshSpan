// SPDX-License-Identifier: GPL-2.0-only

//! Evidence-complete reconstruction of bilateral grant authority and succession.

use std::collections::BTreeSet;

use meshspan_domain::{FederationGrant, FederationGrantId, FederationPolicy, Revision, UnixMicros};
use rusqlite::{Connection, OptionalExtension};

use super::RepositoryError;
use super::federation_grant::{
    load_restrictions, parse_mesh, parse_principal, parse_relationship, parse_resource,
    policy_is_no_broader, positive, validate_stored_restriction_parties,
};
use crate::federation_grant_command::policy_digest;
use crate::{FederationGrantRestriction, PartitionDatabase};

const RELATIONSHIP_ACTIVE: i64 = 2;

/// Durable lifecycle of one federation grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationGrantState {
    /// Grant has not been terminated.
    Active,
    /// Grant was explicitly revoked or replaced.
    Revoked,
}

/// Why a grant stopped carrying authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationGrantTerminationKind {
    /// Authority was explicitly revoked without a successor.
    Revoked,
    /// Authority was renewed by an exact successor.
    Renewed,
    /// Authority was narrowed by an exact successor.
    Restricted,
    /// A pre-schema-38 revocation whose discarded reason cannot be reconstructed.
    LegacyReasonUnknown,
}

/// Immutable evidence which ended one grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationGrantTermination {
    /// Revocation or replacement category.
    pub kind: FederationGrantTerminationKind,
    /// Exact validated reason, absent only for an explicitly migrated legacy revocation.
    pub reason: Option<String>,
    /// Authoritative occurrence time.
    pub terminated_at: UnixMicros,
    /// Authoritative revision which ended the grant.
    pub revision: Revision,
}

/// One bilateral grant plus its immutable restrictions and succession evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationGrantRecord {
    /// Reconstructed effective authority envelope.
    pub grant: FederationGrant,
    /// Both sides' independently persisted restrictions.
    pub restrictions: Vec<FederationGrantRestriction>,
    /// Current durable lifecycle state.
    pub state: FederationGrantState,
    /// When this exact grant was issued.
    pub issued_at: UnixMicros,
    /// Evidence ending this grant, if any.
    pub termination: Option<FederationGrantTermination>,
    /// Grant immediately preceding this one, if it is a replacement.
    pub predecessor_grant_id: Option<FederationGrantId>,
    /// Grant immediately succeeding this one, if it was replaced.
    pub successor_grant_id: Option<FederationGrantId>,
    /// Last authoritative grant revision.
    pub revision: Revision,
}

#[derive(Clone, Debug)]
struct SuccessionEdge {
    predecessor: FederationGrantId,
    successor: FederationGrantId,
    relationship_id: meshspan_domain::FederationRelationshipId,
    kind: i64,
    reason: String,
    succeeded_at: UnixMicros,
    revision: Revision,
}

struct RawGrant {
    relationship_id: Vec<u8>,
    subject_home_mesh_id: Vec<u8>,
    subject_principal_id: Vec<u8>,
    resource_kind: i64,
    authority_mesh_id: Vec<u8>,
    volume_id: Option<Vec<u8>>,
    object_id: Option<Vec<u8>>,
    authority_epoch: i64,
    valid_from: i64,
    valid_until: Option<i64>,
    effective_policy_digest: Vec<u8>,
    state: i64,
    issued_at: i64,
    revoked_at: Option<i64>,
    revision: i64,
    local_mesh_id: Vec<u8>,
    remote_mesh_id: Vec<u8>,
}

pub(super) fn grant(
    database: &PartitionDatabase,
    grant_id: FederationGrantId,
) -> Result<Option<FederationGrantRecord>, RepositoryError> {
    load_verified(database.connection(), grant_id)
}

pub(super) fn active_grant(
    database: &PartitionDatabase,
    grant_id: FederationGrantId,
) -> Result<Option<FederationGrantRecord>, RepositoryError> {
    let Some(record) = load_verified(database.connection(), grant_id)? else {
        return Ok(None);
    };
    if record.state == FederationGrantState::Revoked {
        return Ok(None);
    }
    if is_current_authority(database.connection(), &record)? {
        Ok(Some(record))
    } else {
        Ok(None)
    }
}

pub(super) fn load_verified(
    connection: &Connection,
    grant_id: FederationGrantId,
) -> Result<Option<FederationGrantRecord>, RepositoryError> {
    let Some(record) = load_record(connection, grant_id)? else {
        return Ok(None);
    };
    validate_lineage(connection, &record)?;
    Ok(Some(record))
}

fn load_record(
    connection: &Connection,
    grant_id: FederationGrantId,
) -> Result<Option<FederationGrantRecord>, RepositoryError> {
    let row = connection
        .query_row(
            "SELECT g.relationship_id, g.subject_home_mesh_id, g.subject_principal_id,
                    g.resource_kind, g.authority_mesh_id, g.volume_id, g.object_id,
                    g.authority_epoch, g.valid_from, g.valid_until,
                    g.effective_policy_digest, g.state, g.issued_at, g.revoked_at, g.revision,
                    r.local_mesh_id, r.remote_mesh_id
             FROM federation_grants AS g
             JOIN federation_relationships AS r ON r.relationship_id = g.relationship_id
             WHERE g.grant_id = ?1",
            [grant_id.as_bytes().as_slice()],
            |row| {
                Ok(RawGrant {
                    relationship_id: row.get(0)?,
                    subject_home_mesh_id: row.get(1)?,
                    subject_principal_id: row.get(2)?,
                    resource_kind: row.get(3)?,
                    authority_mesh_id: row.get(4)?,
                    volume_id: row.get(5)?,
                    object_id: row.get(6)?,
                    authority_epoch: row.get(7)?,
                    valid_from: row.get(8)?,
                    valid_until: row.get(9)?,
                    effective_policy_digest: row.get(10)?,
                    state: row.get(11)?,
                    issued_at: row.get(12)?,
                    revoked_at: row.get(13)?,
                    revision: row.get(14)?,
                    local_mesh_id: row.get(15)?,
                    remote_mesh_id: row.get(16)?,
                })
            },
        )
        .optional()?;
    row.map(|row| reconstruct_record(connection, grant_id, &row))
        .transpose()
}

fn reconstruct_record(
    connection: &Connection,
    grant_id: FederationGrantId,
    row: &RawGrant,
) -> Result<FederationGrantRecord, RepositoryError> {
    let restrictions = load_restrictions(connection, grant_id)?;
    validate_stored_restriction_parties(&restrictions, &row.local_mesh_id, &row.remote_mesh_id)?;
    let policies = restrictions
        .iter()
        .map(|restriction| restriction.policy)
        .collect::<Vec<_>>();
    let policy =
        FederationPolicy::intersect(&policies).map_err(|_| RepositoryError::CorruptState)?;
    if row.effective_policy_digest.as_slice() != policy_digest(policy) {
        return Err(RepositoryError::CorruptState);
    }
    let grant = FederationGrant::new(
        grant_id,
        parse_relationship(&row.relationship_id)?,
        meshspan_domain::FederatedPrincipal::new(
            parse_mesh(&row.subject_home_mesh_id)?,
            parse_principal(&row.subject_principal_id)?,
        ),
        parse_resource(
            row.resource_kind,
            &row.authority_mesh_id,
            row.volume_id.as_deref(),
            row.object_id.as_deref(),
        )?,
        policy,
        positive(row.authority_epoch)?,
        UnixMicros::new(row.valid_from),
        row.valid_until.map(UnixMicros::new),
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    let state = match row.state {
        1 if row.revoked_at.is_none() => FederationGrantState::Active,
        3 if row.revoked_at.is_some() => FederationGrantState::Revoked,
        _ => return Err(RepositoryError::CorruptState),
    };
    let termination = load_termination(connection, grant_id)?;
    validate_termination_shape(state, row.revoked_at, row.revision, termination.as_ref())?;
    let predecessor = load_predecessor(connection, grant_id)?;
    let successor = load_successor(connection, grant_id)?;
    validate_edge_evidence(
        connection,
        &grant,
        policy,
        termination.as_ref(),
        successor.as_ref(),
    )?;
    Ok(FederationGrantRecord {
        grant,
        restrictions,
        state,
        issued_at: UnixMicros::new(row.issued_at),
        termination,
        predecessor_grant_id: predecessor.as_ref().map(|edge| edge.predecessor),
        successor_grant_id: successor.as_ref().map(|edge| edge.successor),
        revision: Revision::new(positive(row.revision)?),
    })
}

fn validate_lineage(
    connection: &Connection,
    record: &FederationGrantRecord,
) -> Result<(), RepositoryError> {
    let mut seen = BTreeSet::from([record.grant.grant_id()]);
    let mut expected_successor = record.grant.grant_id();
    let mut current = record.predecessor_grant_id;
    while let Some(grant_id) = current {
        if !seen.insert(grant_id) {
            return Err(RepositoryError::CorruptState);
        }
        let predecessor =
            load_record(connection, grant_id)?.ok_or(RepositoryError::CorruptState)?;
        if predecessor.successor_grant_id != Some(expected_successor) {
            return Err(RepositoryError::CorruptState);
        }
        expected_successor = grant_id;
        current = predecessor.predecessor_grant_id;
    }
    let mut expected_predecessor = record.grant.grant_id();
    let mut current = record.successor_grant_id;
    while let Some(grant_id) = current {
        if !seen.insert(grant_id) {
            return Err(RepositoryError::CorruptState);
        }
        let successor = load_record(connection, grant_id)?.ok_or(RepositoryError::CorruptState)?;
        if successor.predecessor_grant_id != Some(expected_predecessor) {
            return Err(RepositoryError::CorruptState);
        }
        expected_predecessor = grant_id;
        current = successor.successor_grant_id;
    }
    Ok(())
}

fn load_termination(
    connection: &Connection,
    grant_id: FederationGrantId,
) -> Result<Option<FederationGrantTermination>, RepositoryError> {
    connection
        .query_row(
            "SELECT termination_kind, reason, terminated_at, revision
             FROM federation_grant_terminations WHERE grant_id = ?1",
            [grant_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(FederationGrantTermination {
                kind: parse_termination_kind(row.0)?,
                reason: row.1,
                terminated_at: UnixMicros::new(row.2),
                revision: Revision::new(positive(row.3)?),
            })
        })
        .transpose()
}

fn load_predecessor(
    connection: &Connection,
    grant_id: FederationGrantId,
) -> Result<Option<SuccessionEdge>, RepositoryError> {
    load_edge(connection, "successor_grant_id", grant_id)
}

fn load_successor(
    connection: &Connection,
    grant_id: FederationGrantId,
) -> Result<Option<SuccessionEdge>, RepositoryError> {
    load_edge(connection, "predecessor_grant_id", grant_id)
}

fn load_edge(
    connection: &Connection,
    column: &str,
    grant_id: FederationGrantId,
) -> Result<Option<SuccessionEdge>, RepositoryError> {
    let query = format!(
        "SELECT predecessor_grant_id, successor_grant_id, relationship_id,
                succession_kind, reason, succeeded_at, revision
         FROM federation_grant_successions WHERE {column} = ?1"
    );
    connection
        .query_row(&query, [grant_id.as_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .optional()?
        .map(|row| {
            Ok(SuccessionEdge {
                predecessor: parse_grant(&row.0)?,
                successor: parse_grant(&row.1)?,
                relationship_id: parse_relationship(&row.2)?,
                kind: row.3,
                reason: row.4,
                succeeded_at: UnixMicros::new(row.5),
                revision: Revision::new(positive(row.6)?),
            })
        })
        .transpose()
}

fn validate_termination_shape(
    state: FederationGrantState,
    revoked_at: Option<i64>,
    revision: i64,
    termination: Option<&FederationGrantTermination>,
) -> Result<(), RepositoryError> {
    match (state, revoked_at, termination) {
        (FederationGrantState::Active, None, None) => Ok(()),
        (FederationGrantState::Revoked, Some(revoked_at), Some(termination))
            if termination.terminated_at == UnixMicros::new(revoked_at)
                && termination.revision == Revision::new(positive(revision)?) =>
        {
            Ok(())
        }
        _ => Err(RepositoryError::CorruptState),
    }
}

fn validate_edge_evidence(
    connection: &Connection,
    grant: &FederationGrant,
    policy: FederationPolicy,
    termination: Option<&FederationGrantTermination>,
    successor: Option<&SuccessionEdge>,
) -> Result<(), RepositoryError> {
    match (termination, successor) {
        (None, None) => Ok(()),
        (Some(termination), None)
            if matches!(
                termination.kind,
                FederationGrantTerminationKind::Revoked
                    | FederationGrantTerminationKind::LegacyReasonUnknown
            ) =>
        {
            Ok(())
        }
        (Some(termination), Some(edge)) => {
            let expected_kind = match edge.kind {
                1 => FederationGrantTerminationKind::Renewed,
                2 => FederationGrantTerminationKind::Restricted,
                _ => return Err(RepositoryError::CorruptState),
            };
            if edge.predecessor != grant.grant_id()
                || edge.relationship_id != grant.relationship_id()
                || termination.kind != expected_kind
                || termination.reason.as_deref() != Some(edge.reason.as_str())
                || termination.terminated_at != edge.succeeded_at
                || termination.revision != edge.revision
            {
                return Err(RepositoryError::CorruptState);
            }
            let successor = load_successor_authority(connection, edge.successor)?;
            if successor.relationship_id != grant.relationship_id()
                || successor.subject != grant.subject()
                || successor.resource != grant.resource()
                || successor.authority_epoch != grant.authority_epoch()
                || successor.issued_at != edge.succeeded_at
                || (edge.kind == 2 && !policy_is_no_broader(successor.policy, policy))
            {
                return Err(RepositoryError::CorruptState);
            }
            Ok(())
        }
        _ => Err(RepositoryError::CorruptState),
    }
}

struct SuccessorAuthority {
    relationship_id: meshspan_domain::FederationRelationshipId,
    subject: meshspan_domain::FederatedPrincipal,
    resource: meshspan_domain::FederationResourceScope,
    authority_epoch: u64,
    policy: FederationPolicy,
    issued_at: UnixMicros,
}

fn load_successor_authority(
    connection: &Connection,
    grant_id: FederationGrantId,
) -> Result<SuccessorAuthority, RepositoryError> {
    let row = connection
        .query_row(
            "SELECT relationship_id, subject_home_mesh_id, subject_principal_id,
                    resource_kind, authority_mesh_id, volume_id, object_id,
                    authority_epoch, effective_policy_digest, issued_at
             FROM federation_grants WHERE grant_id = ?1",
            [grant_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    let restrictions = load_restrictions(connection, grant_id)?;
    let policies = restrictions
        .iter()
        .map(|restriction| restriction.policy)
        .collect::<Vec<_>>();
    let policy =
        FederationPolicy::intersect(&policies).map_err(|_| RepositoryError::CorruptState)?;
    if row.8.as_slice() != policy_digest(policy) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(SuccessorAuthority {
        relationship_id: parse_relationship(&row.0)?,
        subject: meshspan_domain::FederatedPrincipal::new(
            parse_mesh(&row.1)?,
            parse_principal(&row.2)?,
        ),
        resource: parse_resource(row.3, &row.4, row.5.as_deref(), row.6.as_deref())?,
        authority_epoch: positive(row.7)?,
        policy,
        issued_at: UnixMicros::new(row.9),
    })
}

fn is_current_authority(
    connection: &Connection,
    record: &FederationGrantRecord,
) -> Result<bool, RepositoryError> {
    let relationship: (i64, i64) = connection
        .query_row(
            "SELECT state, authority_epoch FROM federation_relationships
             WHERE relationship_id = ?1",
            [record.grant.relationship_id().as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    let retired: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM federation_ownership_successions
            WHERE state = 3 AND retiring_mesh_id IN (?1, ?2)
         )",
        rusqlite::params![
            record.grant.subject().home_mesh_id().as_bytes().as_slice(),
            record
                .grant
                .resource()
                .authority_mesh_id()
                .as_bytes()
                .as_slice(),
        ],
        |row| row.get(0),
    )?;
    Ok(relationship.0 == RELATIONSHIP_ACTIVE
        && positive(relationship.1)? == record.grant.authority_epoch()
        && retired == 0)
}

fn parse_termination_kind(value: i64) -> Result<FederationGrantTerminationKind, RepositoryError> {
    match value {
        1 => Ok(FederationGrantTerminationKind::Revoked),
        2 => Ok(FederationGrantTerminationKind::Renewed),
        3 => Ok(FederationGrantTerminationKind::Restricted),
        4 => Ok(FederationGrantTerminationKind::LegacyReasonUnknown),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_grant(value: &[u8]) -> Result<FederationGrantId, RepositoryError> {
    FederationGrantId::from_bytes(
        value
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}
