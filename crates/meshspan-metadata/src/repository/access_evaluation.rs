// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic connector-neutral namespace access evaluation.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use meshspan_domain::{
    AssuranceLevel, GrantId, NodeId, ObjectId, PrincipalId, Revision, Rights, SessionId,
    UnixMicros, VolumeId,
};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use super::RepositoryError;
use crate::PartitionDatabase;

const MAXIMUM_ANCESTORS: usize = 1_024;
const MAXIMUM_MEMBERSHIPS: usize = 65_536;
const MAXIMUM_GRANTS: usize = 65_536;
const DEFINED_RIGHTS: usize = 13;

type TargetRow = (Vec<u8>, Option<Vec<u8>>, Vec<u8>, i64);

/// Authenticated, gateway-bound request for one exact namespace object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    /// Digest of the presented bearer token; raw token bytes remain outside metadata.
    pub token_digest: [u8; 32],
    /// Minimum assurance required by this operation class.
    pub required_assurance: AssuranceLevel,
    /// Gateway executing the authorised operation.
    pub gateway_node_id: NodeId,
    /// Exact live process incarnation presented by that gateway.
    pub gateway_incarnation: u64,
    /// Exact containing volume.
    pub volume_id: VolumeId,
    /// Exact target object.
    pub object_id: ObjectId,
    /// Non-empty protocol-neutral rights required atomically.
    pub requested_rights: Rights,
    /// Authoritative mesh time used for every window decision.
    pub now: UnixMicros,
}

/// Stable internal denial classes; connectors map them to non-disclosing protocol errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessDenial {
    /// No current committed session matches the supplied digest.
    SessionUnavailable,
    /// The session predates the current identity/ACL projection.
    StaleIdentity,
    /// The session does not prove the operation's required assurance.
    InsufficientAssurance,
    /// The named gateway incarnation is not currently active.
    GatewayUnavailable,
    /// The target is absent, retired or belongs to another volume.
    ObjectUnavailable,
    /// Applicable owner and allow-grant sources do not contain every requested right.
    MissingRights,
}

/// One bounded capability input, tied to every mutable authority used by the decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessCapability {
    /// Committed session that authenticated the user.
    pub session_id: SessionId,
    /// User receiving authority.
    pub principal_id: PrincipalId,
    /// Gateway to which this decision is fenced.
    pub gateway_node_id: NodeId,
    /// Exact live process incarnation of the gateway.
    pub gateway_incarnation: u64,
    /// Target volume.
    pub volume_id: VolumeId,
    /// Target object.
    pub object_id: ObjectId,
    /// Rights required by the operation.
    pub requested_rights: Rights,
    /// Complete rights available at evaluation time.
    pub effective_rights: Rights,
    /// Current identity, group and ACL revision.
    pub identity_revision: Revision,
    /// Current namespace authority revision.
    pub namespace_revision: Revision,
    /// Exact target object revision.
    pub object_revision: Revision,
    /// Exact gateway record revision.
    pub gateway_revision: Revision,
    /// Exclusive expiry, never later than the session or a required source.
    pub expires_at: UnixMicros,
    /// Canonical digest over every field above.
    pub capability_digest: [u8; 32],
}

/// Complete outcome of one access evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessDecision {
    /// Every requested right is present and bound into a capability input.
    Granted(AccessCapability),
    /// The request is not authorised at the committed projection.
    Denied(AccessDenial),
}

#[derive(Clone, Copy)]
struct Session {
    id: SessionId,
    principal_id: PrincipalId,
    assurance: AssuranceLevel,
    identity_revision: Revision,
    expires_at: UnixMicros,
}

#[derive(Clone, Copy)]
struct Target {
    object_revision: Revision,
    owner_set_id: [u8; 16],
    is_root: bool,
}

#[derive(Clone, Copy)]
struct AuthorityRevisions {
    identity: Revision,
    namespace: Revision,
    gateway: Revision,
}

#[derive(Clone, Copy)]
struct MembershipEdge {
    containing_group: PrincipalId,
    member: PrincipalId,
    expires_at: Option<UnixMicros>,
    requires_activation: bool,
}

#[derive(Clone, Copy)]
struct GrantEvaluation<'a> {
    request: AccessRequest,
    principal_id: PrincipalId,
    target_is_root: bool,
    ancestors: &'a BTreeSet<ObjectId>,
    subjects: &'a BTreeMap<PrincipalId, Option<UnixMicros>>,
    activations: &'a BTreeMap<GrantId, UnixMicros>,
}

#[derive(Clone, Copy, Default)]
struct RightLifetime {
    present: bool,
    expires_at: Option<UnixMicros>,
}

pub(super) fn evaluate(
    database: &PartitionDatabase,
    request: AccessRequest,
) -> Result<AccessDecision, RepositoryError> {
    if request.requested_rights == Rights::default() || request.gateway_incarnation == 0 {
        return Ok(AccessDecision::Denied(AccessDenial::MissingRights));
    }
    let Some(session) = load_session(database, request.token_digest, request.now)? else {
        return Ok(AccessDecision::Denied(AccessDenial::SessionUnavailable));
    };
    let revisions = load_authority_revisions(database, request)?;
    if session.identity_revision != revisions.identity {
        return Ok(AccessDecision::Denied(AccessDenial::StaleIdentity));
    }
    if session.assurance < request.required_assurance {
        return Ok(AccessDecision::Denied(AccessDenial::InsufficientAssurance));
    }
    if revisions.gateway == Revision::ZERO {
        return Ok(AccessDecision::Denied(AccessDenial::GatewayUnavailable));
    }
    let Some((target, ancestors)) = load_target_and_ancestors(database, request)? else {
        return Ok(AccessDecision::Denied(AccessDenial::ObjectUnavailable));
    };
    let group_activations = load_group_activations(database, session, request.now)?;
    let subjects = load_effective_subjects(database, session, request.now, &group_activations)?;
    let grant_activations = load_grant_activations(database, session, request.now)?;
    let mut rights = [RightLifetime::default(); DEFINED_RIGHTS];
    apply_ownership(database, target.owner_set_id, &subjects, &mut rights)?;
    apply_grants(
        database,
        GrantEvaluation {
            request,
            principal_id: session.principal_id,
            target_is_root: target.is_root,
            ancestors: &ancestors,
            subjects: &subjects,
            activations: &grant_activations,
        },
        &mut rights,
    )?;
    build_decision(request, session, target, revisions, &rights)
}

fn load_session(
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
    row.map(|value| {
        Ok(Session {
            id: parse_session(&value.0)?,
            principal_id: parse_principal(&value.1)?,
            assurance: parse_assurance(value.2)?,
            identity_revision: parse_revision(value.3)?,
            expires_at: UnixMicros::new(value.4),
        })
    })
    .transpose()
}

fn load_authority_revisions(
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

fn load_target_and_ancestors(
    database: &PartitionDatabase,
    request: AccessRequest,
) -> Result<Option<(Target, BTreeSet<ObjectId>)>, RepositoryError> {
    let mut ancestors = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let expected_volume = request.volume_id.as_bytes();
    visited.insert(request.object_id);
    let object = request.object_id.as_bytes();
    let row: Option<TargetRow> = database
        .connection()
        .query_row(
            "SELECT volume_id, parent_object_id, owner_set_id, revision
             FROM namespace_objects WHERE object_id = ?1 AND state = 1",
            [object.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((volume, parent, owners, revision)) = row else {
        return Ok(None);
    };
    if volume.as_slice() != expected_volume {
        return Ok(None);
    }
    let target = Target {
        object_revision: parse_revision(revision)?,
        owner_set_id: parse_identifier(&owners)?,
        is_root: parent.is_none(),
    };
    let Some(parent) = parent else {
        return Ok(Some((target, ancestors)));
    };
    let mut parent_id = parse_object(&parent)?;
    ancestors.insert(parent_id);
    load_remaining_ancestors(
        database,
        expected_volume,
        &mut ancestors,
        &mut visited,
        &mut parent_id,
    )?;
    Ok(Some((target, ancestors)))
}

fn load_remaining_ancestors(
    database: &PartitionDatabase,
    expected_volume: [u8; 16],
    ancestors: &mut BTreeSet<ObjectId>,
    visited: &mut BTreeSet<ObjectId>,
    current: &mut ObjectId,
) -> Result<(), RepositoryError> {
    for _ in 0..MAXIMUM_ANCESTORS {
        if !visited.insert(*current) {
            return Err(RepositoryError::CorruptState);
        }
        let object = current.as_bytes();
        let row: (Vec<u8>, Option<Vec<u8>>) = database.connection().query_row(
            "SELECT volume_id, parent_object_id FROM namespace_objects
             WHERE object_id = ?1 AND state = 1",
            [object.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if row.0.as_slice() != expected_volume {
            return Err(RepositoryError::CorruptState);
        }
        let Some(parent) = row.1 else {
            return Ok(());
        };
        *current = parse_object(&parent)?;
        ancestors.insert(*current);
    }
    Err(RepositoryError::CapacityExceeded)
}

fn load_group_activations(
    database: &PartitionDatabase,
    session: Session,
    now: UnixMicros,
) -> Result<BTreeMap<PrincipalId, UnixMicros>, RepositoryError> {
    let principal = session.principal_id.as_bytes();
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
            to_i64(session.identity_revision.get())?,
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

fn load_effective_subjects(
    database: &PartitionDatabase,
    session: Session,
    now: UnixMicros,
    activations: &BTreeMap<PrincipalId, UnixMicros>,
) -> Result<BTreeMap<PrincipalId, Option<UnixMicros>>, RepositoryError> {
    let edges = load_active_memberships(database, session.principal_id, now)?;
    let mut by_member = BTreeMap::<PrincipalId, Vec<MembershipEdge>>::new();
    for edge in edges {
        by_member.entry(edge.member).or_default().push(edge);
    }
    let mut subjects = BTreeMap::from([(session.principal_id, None)]);
    let mut pending = VecDeque::from([session.principal_id]);
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
         WHERE p.state = 1 AND (gm.valid_from IS NULL OR gm.valid_from <= ?1)
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

fn load_grant_activations(
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

fn apply_ownership(
    database: &PartitionDatabase,
    owner_set_id: [u8; 16],
    subjects: &BTreeMap<PrincipalId, Option<UnixMicros>>,
    rights: &mut [RightLifetime; DEFINED_RIGHTS],
) -> Result<(), RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT owner_principal_id FROM object_owners
         WHERE owner_set_id = ?1 ORDER BY owner_principal_id LIMIT 1025",
    )?;
    let rows = statement.query_map([owner_set_id.as_slice()], |row| row.get::<_, Vec<u8>>(0))?;
    let mut count = 0_usize;
    for row in rows {
        count += 1;
        if count > 1_024 {
            return Err(RepositoryError::CapacityExceeded);
        }
        if let Some(expiry) = subjects.get(&parse_principal(&row?)?) {
            contribute(rights, Rights::ALL, *expiry);
        }
    }
    if count == 0 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(())
}

fn apply_grants(
    database: &PartitionDatabase,
    evaluation: GrantEvaluation<'_>,
    rights: &mut [RightLifetime; DEFINED_RIGHTS],
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
            evaluation.request,
            evaluation.target_is_root,
            evaluation.ancestors,
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
        contribute(rights, grant_rights, expiry);
    }
    Ok(())
}

fn grant_applies(
    request: AccessRequest,
    target_is_root: bool,
    ancestors: &BTreeSet<ObjectId>,
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
        1 if volume.is_none() && object.is_none() => Ok(descendants),
        2 if volume == Some(request.volume_id.as_bytes().as_slice()) && object.is_none() => {
            Ok((target_is_root && exact) || (!target_is_root && descendants))
        }
        3 if volume == Some(request.volume_id.as_bytes().as_slice()) => {
            let scoped = parse_object(object.ok_or(RepositoryError::CorruptState)?)?;
            Ok((scoped == request.object_id && exact)
                || (ancestors.contains(&scoped) && descendants))
        }
        _ => Err(RepositoryError::CorruptState),
    }
}

fn build_decision(
    request: AccessRequest,
    session: Session,
    target: Target,
    revisions: AuthorityRevisions,
    rights: &[RightLifetime; DEFINED_RIGHTS],
) -> Result<AccessDecision, RepositoryError> {
    let mut effective_bits = 0_u32;
    let mut expires_at = session.expires_at;
    for (index, lifetime) in rights.iter().enumerate() {
        let bit = 1_u32 << index;
        if lifetime.present {
            effective_bits |= bit;
        }
        if request.requested_rights.bits() & bit != 0 {
            if !lifetime.present {
                return Ok(AccessDecision::Denied(AccessDenial::MissingRights));
            }
            if let Some(source_expiry) = lifetime.expires_at {
                expires_at = expires_at.min(source_expiry);
            }
        }
    }
    if expires_at <= request.now {
        return Ok(AccessDecision::Denied(AccessDenial::MissingRights));
    }
    let effective_rights =
        Rights::from_bits(effective_bits).map_err(|_| RepositoryError::CorruptState)?;
    let mut capability = AccessCapability {
        session_id: session.id,
        principal_id: session.principal_id,
        gateway_node_id: request.gateway_node_id,
        gateway_incarnation: request.gateway_incarnation,
        volume_id: request.volume_id,
        object_id: request.object_id,
        requested_rights: request.requested_rights,
        effective_rights,
        identity_revision: revisions.identity,
        namespace_revision: revisions.namespace,
        object_revision: target.object_revision,
        gateway_revision: revisions.gateway,
        expires_at,
        capability_digest: [0; 32],
    };
    capability.capability_digest = capability_digest(capability);
    Ok(AccessDecision::Granted(capability))
}

fn contribute(
    lifetimes: &mut [RightLifetime; DEFINED_RIGHTS],
    rights: Rights,
    expires_at: Option<UnixMicros>,
) {
    for (index, lifetime) in lifetimes.iter_mut().enumerate() {
        if rights.bits() & (1_u32 << index) == 0 {
            continue;
        }
        if !lifetime.present || extends_expiry(lifetime.expires_at, expires_at) {
            *lifetime = RightLifetime {
                present: true,
                expires_at,
            };
        }
    }
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

fn earliest<const N: usize>(values: [Option<UnixMicros>; N]) -> Option<UnixMicros> {
    values.into_iter().flatten().min()
}

fn capability_digest(capability: AccessCapability) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.access-capability.v1");
    digest.update(capability.session_id.as_bytes());
    digest.update(capability.principal_id.as_bytes());
    digest.update(capability.gateway_node_id.as_bytes());
    digest.update(capability.gateway_incarnation.to_be_bytes());
    digest.update(capability.volume_id.as_bytes());
    digest.update(capability.object_id.as_bytes());
    digest.update(capability.requested_rights.bits().to_be_bytes());
    digest.update(capability.effective_rights.bits().to_be_bytes());
    digest.update(capability.identity_revision.get().to_be_bytes());
    digest.update(capability.namespace_revision.get().to_be_bytes());
    digest.update(capability.object_revision.get().to_be_bytes());
    digest.update(capability.gateway_revision.get().to_be_bytes());
    digest.update(capability.expires_at.get().to_be_bytes());
    digest.finalize().into()
}

fn parse_identifier(bytes: &[u8]) -> Result<[u8; 16], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn parse_principal(bytes: &[u8]) -> Result<PrincipalId, RepositoryError> {
    PrincipalId::from_bytes(parse_identifier(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

fn parse_object(bytes: &[u8]) -> Result<ObjectId, RepositoryError> {
    ObjectId::from_bytes(parse_identifier(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

fn parse_grant(bytes: &[u8]) -> Result<GrantId, RepositoryError> {
    GrantId::from_bytes(parse_identifier(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

fn parse_session(bytes: &[u8]) -> Result<SessionId, RepositoryError> {
    SessionId::from_bytes(parse_identifier(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

fn parse_revision(value: i64) -> Result<Revision, RepositoryError> {
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

fn to_i64(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::CapacityExceeded)
}
