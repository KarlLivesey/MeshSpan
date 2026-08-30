// SPDX-License-Identifier: GPL-2.0-only

//! Atomic effective grant issuance, immutable replacement and revocation.

use std::collections::BTreeSet;

use meshspan_domain::{
    DurationMicros, FederatedMutationAdmission, FederatedMutationEvidence, FederationAccess,
    FederationGrant, FederationGrantError, FederationGrantId, FederationGrantRoute,
    FederationPolicy, FederationResourceScope, MeshId, NamespaceFederationPolicy, QuarantineReason,
    Revision, StorageFederationPolicy, UnixMicros, classify_federated_mutation,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::federation_grant_command::policy_digest;
use crate::{
    AuthoritativeCommand, CommandContext, FederationGrantRestriction, IssueFederationGrant,
    ReplaceFederationGrant, RevokeFederationGrant,
};

const RELATIONSHIP_ACTIVE: i64 = 2;
const MAXIMUM_REASON_BYTES: usize = 512;

#[derive(Clone, Copy)]
struct RelationshipAuthority {
    local_mesh_id: MeshId,
    remote_mesh_id: MeshId,
    authority_epoch: u64,
}

#[derive(Clone)]
struct StoredGrantAuthority {
    relationship_id: meshspan_domain::FederationRelationshipId,
    route: FederationGrantRoute,
    upstream_grant_id: Option<FederationGrantId>,
    resource: FederationResourceScope,
    policy: FederationPolicy,
    authority_epoch: u64,
    valid_from: UnixMicros,
    valid_until: Option<UnixMicros>,
}

pub(super) fn classify_persisted_mutation(
    connection: &Connection,
    evidence: FederatedMutationEvidence,
) -> Result<FederatedMutationAdmission, RepositoryError> {
    let record = super::federation_grant_evidence::load_verified(connection, evidence.grant_id())?
        .ok_or(RepositoryError::InvalidCommand)?;
    let revoked_at = record
        .termination
        .as_ref()
        .map(|termination| termination.terminated_at);
    let admission =
        classify_federated_mutation(&record.grant, evidence, revoked_at).map_err(|error| {
            if error == FederationGrantError::EvidenceMismatch {
                RepositoryError::InvalidCommand
            } else {
                RepositoryError::CorruptState
            }
        })?;
    if admission != FederatedMutationAdmission::Admitted {
        return Ok(admission);
    }
    classify_upstream_history(connection, &record, evidence.accepted_at())
}

fn classify_upstream_history(
    connection: &Connection,
    record: &super::FederationGrantRecord,
    accepted_at: UnixMicros,
) -> Result<FederatedMutationAdmission, RepositoryError> {
    let mut current = record.grant.upstream_grant_id();
    let mut remaining = meshspan_domain::MAXIMUM_FEDERATION_ROUTE_MESHES;
    while let Some(grant_id) = current {
        if remaining == 0 {
            return Err(RepositoryError::CorruptState);
        }
        remaining -= 1;
        let upstream = super::federation_grant_evidence::load_verified(connection, grant_id)?
            .ok_or(RepositoryError::CorruptState)?;
        if accepted_at < upstream.grant.valid_from() {
            return Ok(FederatedMutationAdmission::Quarantined(
                QuarantineReason::BeforeValidity,
            ));
        }
        if upstream
            .grant
            .valid_until()
            .is_some_and(|valid_until| accepted_at >= valid_until)
        {
            return Ok(FederatedMutationAdmission::Quarantined(
                QuarantineReason::Expired,
            ));
        }
        if upstream
            .termination
            .as_ref()
            .is_some_and(|termination| accepted_at >= termination.terminated_at)
        {
            return Ok(FederatedMutationAdmission::Quarantined(
                QuarantineReason::Revoked,
            ));
        }
        current = upstream.grant.upstream_grant_id();
    }
    Ok(FederatedMutationAdmission::Admitted)
}

pub(super) fn is_command(command: &AuthoritativeCommand) -> bool {
    matches!(
        command,
        AuthoritativeCommand::IssueFederationGrant(_)
            | AuthoritativeCommand::ReplaceFederationGrant(_)
            | AuthoritativeCommand::RevokeFederationGrant(_)
    )
}

pub(super) fn execute(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    match command {
        AuthoritativeCommand::IssueFederationGrant(value) => {
            issue(transaction, context, value, revision)
        }
        AuthoritativeCommand::ReplaceFederationGrant(value) => {
            replace(transaction, context, value, revision)
        }
        AuthoritativeCommand::RevokeFederationGrant(value) => {
            revoke(transaction, context, value, revision)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn issue(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &IssueFederationGrant,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let relationship = load_relationship_authority(transaction, &command.grant)?;
    validate_and_persist(
        transaction,
        context,
        &command.grant,
        command.restrictions.as_slice(),
        relationship,
        revision,
    )?;
    Ok(grant_reference(command.grant.grant_id()))
}

fn replace(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ReplaceFederationGrant,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_reason(&command.reason)?;
    if command.predecessor_grant_id == command.grant.grant_id() {
        return Err(RepositoryError::InvalidCommand);
    }
    let predecessor = load_grant_authority(transaction, command.predecessor_grant_id)?;
    validate_successor_identity(&predecessor, &command.grant)?;
    if command.restricts_authority
        && !policy_is_no_broader(command.grant.policy(), predecessor.policy)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let relationship = load_relationship_authority(transaction, &command.grant)?;
    validate_and_persist(
        transaction,
        context,
        &command.grant,
        command.restrictions.as_slice(),
        relationship,
        revision,
    )?;
    let changed = transaction.execute(
        "UPDATE federation_grants SET state = 3, revoked_at = ?1, revision = ?2
         WHERE grant_id = ?3 AND state = 1",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.predecessor_grant_id.as_bytes().as_slice()
        ],
    )?;
    require_one(changed)?;
    transaction.execute(
        "INSERT INTO federation_grant_successions(
            predecessor_grant_id, successor_grant_id, relationship_id,
            succession_kind, reason, succeeded_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            command.predecessor_grant_id.as_bytes().as_slice(),
            command.grant.grant_id().as_bytes().as_slice(),
            command.grant.relationship_id().as_bytes().as_slice(),
            if command.restricts_authority { 2 } else { 1 },
            command.reason,
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    persist_termination(
        transaction,
        command.predecessor_grant_id,
        if command.restricts_authority { 3 } else { 2 },
        &command.reason,
        context.occurred_at,
        revision,
    )?;
    Ok(grant_reference(command.grant.grant_id()))
}

fn revoke(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RevokeFederationGrant,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_reason(&command.reason)?;
    let stored = load_grant_authority(transaction, command.grant_id)?;
    if stored.authority_epoch != command.expected_authority_epoch {
        return Err(RepositoryError::InvalidCommand);
    }
    let changed = transaction.execute(
        "UPDATE federation_grants SET state = 3, revoked_at = ?1, revision = ?2
         WHERE grant_id = ?3 AND state = 1 AND authority_epoch = ?4",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.grant_id.as_bytes().as_slice(),
            to_i64(command.expected_authority_epoch)?,
        ],
    )?;
    require_one(changed)?;
    persist_termination(
        transaction,
        command.grant_id,
        1,
        &command.reason,
        context.occurred_at,
        revision,
    )?;
    Ok(grant_reference(command.grant_id))
}

fn persist_termination(
    transaction: &Transaction<'_>,
    grant_id: FederationGrantId,
    kind: i64,
    reason: &str,
    occurred_at: UnixMicros,
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO federation_grant_terminations(
            grant_id, termination_kind, reason, terminated_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            grant_id.as_bytes().as_slice(),
            kind,
            reason,
            occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn validate_and_persist(
    transaction: &Transaction<'_>,
    context: CommandContext,
    grant: &FederationGrant,
    restrictions: &[FederationGrantRestriction],
    relationship: RelationshipAuthority,
    revision: Revision,
) -> Result<(), RepositoryError> {
    validate_parties(grant, relationship)?;
    validate_upstream(transaction, grant)?;
    reject_retired_authority(transaction, grant)?;
    validate_restrictions(grant, restrictions, relationship)?;
    persist_grant(transaction, context, grant, revision)?;
    for restriction in restrictions {
        persist_restriction(transaction, grant.grant_id(), *restriction, revision)?;
    }
    Ok(())
}

fn reject_retired_authority(
    connection: &Connection,
    grant: &FederationGrant,
) -> Result<(), RepositoryError> {
    let retired: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM federation_ownership_successions
            WHERE state = 3 AND retiring_mesh_id IN (?1, ?2)
         )",
        params![
            grant.recipient_mesh_id().as_bytes().as_slice(),
            grant.resource().authority_mesh_id().as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    if retired == 0 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_parties(
    grant: &FederationGrant,
    relationship: RelationshipAuthority,
) -> Result<(), RepositoryError> {
    let parties = [relationship.local_mesh_id, relationship.remote_mesh_id];
    if grant.authority_epoch() != relationship.authority_epoch
        || !parties.contains(&grant.issuer_mesh_id())
        || !parties.contains(&grant.recipient_mesh_id())
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn validate_upstream(
    transaction: &Transaction<'_>,
    grant: &FederationGrant,
) -> Result<(), RepositoryError> {
    let Some(upstream_grant_id) = grant.upstream_grant_id() else {
        return (grant.route().downstream_depth() == 0)
            .then_some(())
            .ok_or(RepositoryError::InvalidCommand);
    };
    let upstream = load_grant_authority(transaction, upstream_grant_id)?;
    let expected_route = upstream
        .route
        .delegate_to(grant.recipient_mesh_id())
        .map_err(|_| RepositoryError::InvalidCommand)?;
    if expected_route != *grant.route()
        || upstream.resource != grant.resource()
        || !policy_is_no_broader(grant.policy(), upstream.policy)
        || !validity_is_no_broader(
            grant.valid_from(),
            grant.valid_until(),
            upstream.valid_from,
            upstream.valid_until,
        )
        || !policy_allows_downstream(upstream.policy)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn policy_allows_downstream(policy: FederationPolicy) -> bool {
    match policy {
        FederationPolicy::Namespace(policy) => policy.access().allows_downstream_delegation(),
        FederationPolicy::Storage(policy) => policy.allows_downstream_delegation(),
    }
}

fn validity_is_no_broader(
    next_from: UnixMicros,
    next_until: Option<UnixMicros>,
    prior_from: UnixMicros,
    prior_until: Option<UnixMicros>,
) -> bool {
    next_from >= prior_from
        && match (next_until, prior_until) {
            (Some(next), Some(prior)) => next <= prior,
            (Some(_), None) | (None, None) => true,
            (None, Some(_)) => false,
        }
}

fn validate_restrictions(
    grant: &FederationGrant,
    restrictions: &[FederationGrantRestriction],
    relationship: RelationshipAuthority,
) -> Result<(), RepositoryError> {
    if !(2..=meshspan_domain::MAXIMUM_FEDERATION_ROUTE_MESHES).contains(&restrictions.len()) {
        return Err(RepositoryError::InvalidCommand);
    }
    let imposing = restrictions
        .iter()
        .map(|value| value.imposing_mesh_id)
        .collect::<BTreeSet<_>>();
    let relationship_parties = [relationship.local_mesh_id, relationship.remote_mesh_id];
    if !relationship_parties
        .iter()
        .all(|mesh_id| imposing.contains(mesh_id))
        || !grant
            .route()
            .meshes()
            .iter()
            .all(|mesh_id| imposing.contains(mesh_id))
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let policies = restrictions
        .iter()
        .map(|restriction| restriction.policy)
        .collect::<Vec<_>>();
    let effective =
        FederationPolicy::intersect(&policies).map_err(|_| RepositoryError::InvalidCommand)?;
    if effective != grant.policy() || !policy_matches_resource(effective, grant.resource()) {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn persist_grant(
    transaction: &Transaction<'_>,
    context: CommandContext,
    grant: &FederationGrant,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let (resource_kind, authority, volume, object) = resource_columns(grant.resource());
    transaction.execute(
        "INSERT INTO federation_grants(
            grant_id, relationship_id, issuer_mesh_id, recipient_mesh_id,
            upstream_grant_id, route_depth,
            resource_kind, authority_mesh_id, volume_id, object_id, authority_epoch,
            valid_from, valid_until, state, effective_policy_digest, issued_at,
            revoked_at, revision
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            1, ?14, ?15, NULL, ?16
         )",
        params![
            grant.grant_id().as_bytes().as_slice(),
            grant.relationship_id().as_bytes().as_slice(),
            grant.issuer_mesh_id().as_bytes().as_slice(),
            grant.recipient_mesh_id().as_bytes().as_slice(),
            grant.upstream_grant_id().map(FederationGrantId::as_bytes),
            to_i64(
                u64::try_from(grant.route().downstream_depth())
                    .map_err(|_| RepositoryError::CapacityExceeded)?
            )?,
            resource_kind,
            authority.as_bytes().as_slice(),
            volume.map(meshspan_domain::VolumeId::as_bytes),
            object.map(meshspan_domain::ObjectId::as_bytes),
            to_i64(grant.authority_epoch())?,
            grant.valid_from().get(),
            grant.valid_until().map(UnixMicros::get),
            policy_digest(grant.policy()).as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    for (hop_index, mesh_id) in grant.route().meshes().iter().enumerate() {
        transaction.execute(
            "INSERT INTO federation_grant_route_hops(
                grant_id, hop_index, mesh_id, revision
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                grant.grant_id().as_bytes().as_slice(),
                to_i64(u64::try_from(hop_index).map_err(|_| RepositoryError::CapacityExceeded)?)?,
                mesh_id.as_bytes().as_slice(),
                to_i64(revision.get())?,
            ],
        )?;
    }
    Ok(())
}

fn persist_restriction(
    transaction: &Transaction<'_>,
    grant_id: FederationGrantId,
    restriction: FederationGrantRestriction,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let digest = policy_digest(restriction.policy);
    match restriction.policy {
        FederationPolicy::Namespace(policy) => transaction.execute(
            "INSERT INTO federation_grant_restrictions(
                grant_id, imposing_mesh_id, policy_kind, rights, allows_downstream_delegation,
                maximum_storage_bytes, counts_towards_protection, serves_reads,
                maximum_offline_micros, policy_digest, revision
             ) VALUES (?1, ?2, 1, ?3, ?4, NULL, NULL, NULL, ?5, ?6, ?7)",
            params![
                grant_id.as_bytes().as_slice(),
                restriction.imposing_mesh_id.as_bytes().as_slice(),
                policy.access().rights().bits(),
                policy.access().allows_downstream_delegation(),
                optional_duration(policy.maximum_offline_duration())?,
                digest.as_slice(),
                to_i64(revision.get())?,
            ],
        )?,
        FederationPolicy::Storage(policy) => transaction.execute(
            "INSERT INTO federation_grant_restrictions(
                grant_id, imposing_mesh_id, policy_kind, rights, allows_downstream_delegation,
                maximum_storage_bytes, counts_towards_protection, serves_reads,
                maximum_offline_micros, policy_digest, revision
             ) VALUES (?1, ?2, 2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                grant_id.as_bytes().as_slice(),
                restriction.imposing_mesh_id.as_bytes().as_slice(),
                policy.allows_downstream_delegation(),
                to_i64(policy.maximum_storage_bytes())?,
                policy.participation().counts_towards_protection(),
                policy.participation().serves_reads(),
                optional_duration(policy.maximum_offline_duration())?,
                digest.as_slice(),
                to_i64(revision.get())?,
            ],
        )?,
    };
    Ok(())
}

fn load_relationship_authority(
    transaction: &Transaction<'_>,
    grant: &FederationGrant,
) -> Result<RelationshipAuthority, RepositoryError> {
    let row = transaction
        .query_row(
            "SELECT local_mesh_id, remote_mesh_id, state, authority_epoch
             FROM federation_relationships WHERE relationship_id = ?1",
            [grant.relationship_id().as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    if row.2 != RELATIONSHIP_ACTIVE {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(RelationshipAuthority {
        local_mesh_id: parse_mesh(&row.0)?,
        remote_mesh_id: parse_mesh(&row.1)?,
        authority_epoch: positive(row.3)?,
    })
}

fn load_grant_authority(
    transaction: &Transaction<'_>,
    grant_id: FederationGrantId,
) -> Result<StoredGrantAuthority, RepositoryError> {
    let row = transaction
        .query_row(
            "SELECT relationship_id, issuer_mesh_id, recipient_mesh_id,
                    upstream_grant_id, route_depth,
                    resource_kind, authority_mesh_id, volume_id, object_id,
                    authority_epoch, valid_from, valid_until, effective_policy_digest
             FROM federation_grants WHERE grant_id = ?1 AND state = 1",
            [grant_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    let policy = load_effective_policy(transaction, grant_id)?;
    if row.12.as_slice() != policy_digest(policy) {
        return Err(RepositoryError::CorruptState);
    }
    let route = load_route(transaction, grant_id)?;
    let stored_depth = usize::try_from(row.4).map_err(|_| RepositoryError::CorruptState)?;
    if parse_mesh(&row.1)? != route.issuer_mesh_id()
        || parse_mesh(&row.2)? != route.recipient_mesh_id()
        || stored_depth != route.downstream_depth()
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(StoredGrantAuthority {
        relationship_id: parse_relationship(&row.0)?,
        route,
        upstream_grant_id: row.3.as_deref().map(parse_federation_grant).transpose()?,
        resource: parse_resource(row.5, &row.6, row.7.as_deref(), row.8.as_deref())?,
        policy,
        authority_epoch: positive(row.9)?,
        valid_from: UnixMicros::new(row.10),
        valid_until: row.11.map(UnixMicros::new),
    })
}

pub(super) fn load_route(
    connection: &Connection,
    grant_id: FederationGrantId,
) -> Result<FederationGrantRoute, RepositoryError> {
    let mut statement = connection.prepare(
        "SELECT hop_index, mesh_id FROM federation_grant_route_hops
         WHERE grant_id = ?1 ORDER BY hop_index",
    )?;
    let rows = statement.query_map([grant_id.as_bytes().as_slice()], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut meshes = Vec::new();
    for row in rows {
        let (hop_index, mesh_id) = row?;
        if hop_index
            != i64::try_from(meshes.len()).map_err(|_| RepositoryError::CapacityExceeded)?
        {
            return Err(RepositoryError::CorruptState);
        }
        meshes.push(parse_mesh(&mesh_id)?);
        if meshes.len() > meshspan_domain::MAXIMUM_FEDERATION_ROUTE_MESHES {
            return Err(RepositoryError::CapacityExceeded);
        }
    }
    FederationGrantRoute::from_meshes(meshes).map_err(|_| RepositoryError::CorruptState)
}

fn load_effective_policy(
    connection: &Connection,
    grant_id: FederationGrantId,
) -> Result<FederationPolicy, RepositoryError> {
    let restrictions = load_restrictions(connection, grant_id)?;
    let policies = restrictions
        .iter()
        .map(|restriction| restriction.policy)
        .collect::<Vec<_>>();
    FederationPolicy::intersect(&policies).map_err(|_| RepositoryError::CorruptState)
}

pub(super) fn load_restrictions(
    connection: &Connection,
    grant_id: FederationGrantId,
) -> Result<Vec<FederationGrantRestriction>, RepositoryError> {
    let mut statement = connection.prepare(
        "SELECT imposing_mesh_id, policy_kind, rights, allows_downstream_delegation, maximum_storage_bytes,
                counts_towards_protection, serves_reads, maximum_offline_micros,
                policy_digest
         FROM federation_grant_restrictions WHERE grant_id = ?1 ORDER BY imposing_mesh_id",
    )?;
    let rows = statement.query_map([grant_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Option<i64>>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, Option<i64>>(4)?,
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, Option<i64>>(6)?,
            row.get::<_, Option<i64>>(7)?,
            row.get::<_, Vec<u8>>(8)?,
        ))
    })?;
    let mut restrictions = Vec::new();
    for row in rows {
        let row = row?;
        let policy = parse_policy(row.1, row.2, row.3, row.4, row.5, row.6, row.7)?;
        if row.8.as_slice() != policy_digest(policy) {
            return Err(RepositoryError::CorruptState);
        }
        restrictions.push(FederationGrantRestriction {
            imposing_mesh_id: parse_mesh(&row.0)?,
            policy,
        });
    }
    if !(2..=meshspan_domain::MAXIMUM_FEDERATION_ROUTE_MESHES).contains(&restrictions.len()) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(restrictions)
}

pub(super) fn validate_stored_restriction_parties(
    restrictions: &[FederationGrantRestriction],
    local_mesh: &[u8],
    remote_mesh: &[u8],
) -> Result<(), RepositoryError> {
    let actual = restrictions
        .iter()
        .map(|restriction| restriction.imposing_mesh_id)
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([parse_mesh(local_mesh)?, parse_mesh(remote_mesh)?]);
    if expected.iter().all(|mesh_id| actual.contains(mesh_id)) {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn validate_successor_identity(
    predecessor: &StoredGrantAuthority,
    successor: &FederationGrant,
) -> Result<(), RepositoryError> {
    if predecessor.relationship_id != successor.relationship_id()
        || predecessor.route != *successor.route()
        || predecessor.upstream_grant_id != successor.upstream_grant_id()
        || predecessor.resource != successor.resource()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

pub(super) fn policy_is_no_broader(next: FederationPolicy, prior: FederationPolicy) -> bool {
    match (next, prior) {
        (FederationPolicy::Namespace(next), FederationPolicy::Namespace(prior)) => {
            next.access().rights().intersection(prior.access().rights()) == next.access().rights()
                && (!next.access().allows_downstream_delegation()
                    || prior.access().allows_downstream_delegation())
                && duration_is_no_broader(
                    next.maximum_offline_duration(),
                    prior.maximum_offline_duration(),
                )
        }
        (FederationPolicy::Storage(next), FederationPolicy::Storage(prior)) => {
            next.maximum_storage_bytes() <= prior.maximum_storage_bytes()
                && (!next.participation().counts_towards_protection()
                    || prior.participation().counts_towards_protection())
                && (!next.participation().serves_reads() || prior.participation().serves_reads())
                && (!next.allows_downstream_delegation() || prior.allows_downstream_delegation())
                && duration_is_no_broader(
                    next.maximum_offline_duration(),
                    prior.maximum_offline_duration(),
                )
        }
        _ => false,
    }
}

const fn duration_is_no_broader(
    next: Option<DurationMicros>,
    prior: Option<DurationMicros>,
) -> bool {
    match (next, prior) {
        (Some(next), Some(prior)) => next.get() <= prior.get(),
        (Some(_) | None, None) => true,
        (None, Some(_)) => false,
    }
}

fn policy_matches_resource(policy: FederationPolicy, resource: FederationResourceScope) -> bool {
    matches!(
        (policy, resource),
        (
            FederationPolicy::Namespace(_),
            FederationResourceScope::Volume { .. }
                | FederationResourceScope::Subtree { .. }
                | FederationResourceScope::File { .. }
        ) | (
            FederationPolicy::Storage(_),
            FederationResourceScope::StorageCapacity { .. }
        )
    )
}

fn resource_columns(
    resource: FederationResourceScope,
) -> (
    u8,
    MeshId,
    Option<meshspan_domain::VolumeId>,
    Option<meshspan_domain::ObjectId>,
) {
    match resource {
        FederationResourceScope::Volume {
            owner_mesh_id,
            volume_id,
        } => (1, owner_mesh_id, Some(volume_id), None),
        FederationResourceScope::Subtree {
            owner_mesh_id,
            volume_id,
            root_object_id,
        } => (2, owner_mesh_id, Some(volume_id), Some(root_object_id)),
        FederationResourceScope::File {
            owner_mesh_id,
            volume_id,
            object_id,
        } => (3, owner_mesh_id, Some(volume_id), Some(object_id)),
        FederationResourceScope::StorageCapacity { provider_mesh_id } => {
            (4, provider_mesh_id, None, None)
        }
    }
}

fn parse_policy(
    kind: i64,
    rights: Option<i64>,
    allows_downstream_delegation: Option<i64>,
    maximum_storage_bytes: Option<i64>,
    counts_towards_protection: Option<i64>,
    serves_reads: Option<i64>,
    maximum_offline_micros: Option<i64>,
) -> Result<FederationPolicy, RepositoryError> {
    let offline = maximum_offline_micros
        .map(positive)
        .transpose()?
        .map(DurationMicros::new);
    match kind {
        1 => {
            let bits = u32::try_from(rights.ok_or(RepositoryError::CorruptState)?)
                .map_err(|_| RepositoryError::CorruptState)?;
            let rights = meshspan_domain::Rights::from_bits(bits)
                .map_err(|_| RepositoryError::CorruptState)?;
            let allows_downstream_delegation = parse_bool(allows_downstream_delegation)?;
            Ok(FederationPolicy::Namespace(NamespaceFederationPolicy::new(
                FederationAccess::new(rights, allows_downstream_delegation),
                offline,
            )))
        }
        2 => {
            let bytes = positive(maximum_storage_bytes.ok_or(RepositoryError::CorruptState)?)?;
            let participation = meshspan_domain::StorageParticipation::new(
                parse_bool(counts_towards_protection)?,
                parse_bool(serves_reads)?,
            );
            StorageFederationPolicy::new(
                bytes,
                participation,
                parse_bool(allows_downstream_delegation)?,
                offline,
            )
            .map(FederationPolicy::Storage)
            .map_err(|_| RepositoryError::CorruptState)
        }
        _ => Err(RepositoryError::CorruptState),
    }
}

pub(super) fn parse_resource(
    kind: i64,
    authority: &[u8],
    volume: Option<&[u8]>,
    object: Option<&[u8]>,
) -> Result<FederationResourceScope, RepositoryError> {
    let authority = parse_mesh(authority)?;
    match (kind, volume, object) {
        (1, Some(volume), None) => Ok(FederationResourceScope::Volume {
            owner_mesh_id: authority,
            volume_id: parse_volume(volume)?,
        }),
        (2, Some(volume), Some(object)) => Ok(FederationResourceScope::Subtree {
            owner_mesh_id: authority,
            volume_id: parse_volume(volume)?,
            root_object_id: parse_object(object)?,
        }),
        (3, Some(volume), Some(object)) => Ok(FederationResourceScope::File {
            owner_mesh_id: authority,
            volume_id: parse_volume(volume)?,
            object_id: parse_object(object)?,
        }),
        (4, None, None) => Ok(FederationResourceScope::StorageCapacity {
            provider_mesh_id: authority,
        }),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn validate_reason(reason: &str) -> Result<(), RepositoryError> {
    if reason.trim().is_empty()
        || reason.len() > MAXIMUM_REASON_BYTES
        || reason.chars().any(char::is_control)
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn parse_bool(value: Option<i64>) -> Result<bool, RepositoryError> {
    match value {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(RepositoryError::CorruptState),
    }
}

pub(super) fn parse_mesh(value: &[u8]) -> Result<MeshId, RepositoryError> {
    parse_id(value, MeshId::from_bytes)
}

pub(super) fn parse_relationship(
    value: &[u8],
) -> Result<meshspan_domain::FederationRelationshipId, RepositoryError> {
    parse_id(value, meshspan_domain::FederationRelationshipId::from_bytes)
}

fn parse_federation_grant(value: &[u8]) -> Result<FederationGrantId, RepositoryError> {
    parse_id(value, FederationGrantId::from_bytes)
}

fn parse_volume(value: &[u8]) -> Result<meshspan_domain::VolumeId, RepositoryError> {
    parse_id(value, meshspan_domain::VolumeId::from_bytes)
}

fn parse_object(value: &[u8]) -> Result<meshspan_domain::ObjectId, RepositoryError> {
    parse_id(value, meshspan_domain::ObjectId::from_bytes)
}

fn parse_id<T, E>(
    value: &[u8],
    constructor: impl FnOnce([u8; 16]) -> Result<T, E>,
) -> Result<T, RepositoryError> {
    constructor(
        value
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

pub(super) fn positive(value: i64) -> Result<u64, RepositoryError> {
    let value = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(value)
    }
}

fn optional_duration(value: Option<DurationMicros>) -> Result<Option<i64>, RepositoryError> {
    value.map(|value| to_i64(value.get())).transpose()
}

fn require_one(changed: usize) -> Result<(), RepositoryError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn grant_reference(grant_id: FederationGrantId) -> EntityReference {
    EntityReference {
        kind: EntityKind::FederationGrant,
        id: grant_id.as_bytes(),
    }
}
