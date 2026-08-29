// SPDX-License-Identifier: GPL-2.0-only

//! Permanent-root metadata delegation policy, history and child route projections.

use meshspan_domain::{
    DelegatedMetadataScope, MetadataKeyRange, MetadataOperationFamily, PartitionId, Revision,
    RootDelegatedRoute, RouteState, ScopeId, ScopeRoute,
};
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::apply::to_i64;
use super::root_delegation_evidence::load_root_route;
use super::routing::{persist_new_scope, update_scope, verify_attestation};
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    AbortScopeHandoff, ActivateScopeHandoff, BeginScopeHandoff, CommandContext, CreateScopeRoute,
    FreezeScopeHandoff, InstallScopeRouteProjection, RouteAttestation,
};

pub(super) fn create_scope(
    transaction: &Transaction<'_>,
    repository_partition_id: PartitionId,
    context: CommandContext,
    command: CreateScopeRoute,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.root_partition_id != repository_partition_id
        || !is_root_partition(transaction, repository_partition_id)?
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let route = RootDelegatedRoute::new(
        command.root_partition_id,
        command.scope,
        1,
        command.routing_epoch,
    )
    .map_err(|_| RepositoryError::InvalidCommand)?;
    reject_overlapping_scope(transaction, route.scope())?;
    verify_attestation(transaction, &route.signing_payload(), command.attestation)?;
    persist_new_scope(transaction, route.route(), revision)?;
    persist_root_scope(transaction, context, &route, 1, revision)?;
    persist_route_history(transaction, context, &route, command.attestation)?;
    Ok(route_reference(route.route()))
}

fn reject_overlapping_scope(
    connection: &rusqlite::Connection,
    scope: DelegatedMetadataScope,
) -> Result<(), RepositoryError> {
    let family = family_code(scope.family());
    let overlaps: i64 = match scope.key_range() {
        MetadataKeyRange::All => connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM root_delegated_scopes WHERE operation_family = ?1
             )",
            [family],
            |row| row.get(0),
        )?,
        MetadataKeyRange::Bounded {
            start_inclusive,
            end_exclusive,
        } => connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM root_delegated_scopes
                WHERE operation_family = ?1
                  AND (key_range_kind = 1
                       OR (?2 < end_exclusive AND start_inclusive < ?3))
             )",
            params![family, start_inclusive.as_slice(), end_exclusive.as_slice()],
            |row| row.get(0),
        )?,
    };
    if overlaps == 0 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

pub(super) fn begin_handoff(
    transaction: &Transaction<'_>,
    repository_partition_id: PartitionId,
    context: CommandContext,
    command: BeginScopeHandoff,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.admission.measured_at() > context.occurred_at {
        return Err(RepositoryError::InvalidCommand);
    }
    let mut route = load_root_route(transaction, command.scope_id)?;
    require_root_authority(transaction, &route, repository_partition_id)?;
    let source_partition_id = route.route().source_partition();
    route
        .begin_delegation(
            command.destination_partition_id,
            command.routing_epoch,
            command.admission,
        )
        .map_err(|_| RepositoryError::InvalidCommand)?;
    verify_attestation(transaction, &route.signing_payload(), command.attestation)?;
    persist_admission(
        transaction,
        context,
        &route,
        source_partition_id,
        command.destination_partition_id,
        revision,
    )?;
    update_scope(transaction, route.route(), revision)?;
    persist_route_history(transaction, context, &route, command.attestation)?;
    Ok(route_reference(route.route()))
}

pub(super) fn freeze_handoff(
    transaction: &Transaction<'_>,
    repository_partition_id: PartitionId,
    context: CommandContext,
    command: FreezeScopeHandoff,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    transition_root_route(
        transaction,
        repository_partition_id,
        context,
        command.scope_id,
        command.attestation,
        revision,
        |route| route.freeze(command.routing_epoch, command.evidence),
    )
}

pub(super) fn activate_handoff(
    transaction: &Transaction<'_>,
    repository_partition_id: PartitionId,
    context: CommandContext,
    command: ActivateScopeHandoff,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    transition_root_route(
        transaction,
        repository_partition_id,
        context,
        command.scope_id,
        command.attestation,
        revision,
        |route| {
            route.activate(
                command.destination_partition_id,
                command.routing_epoch,
                command.evidence,
            )
        },
    )
}

pub(super) fn abort_handoff(
    transaction: &Transaction<'_>,
    repository_partition_id: PartitionId,
    context: CommandContext,
    command: AbortScopeHandoff,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.reason_code == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    transition_root_route(
        transaction,
        repository_partition_id,
        context,
        command.scope_id,
        command.attestation,
        revision,
        |route| route.abort(command.routing_epoch),
    )
}

fn transition_root_route(
    transaction: &Transaction<'_>,
    repository_partition_id: PartitionId,
    context: CommandContext,
    scope_id: ScopeId,
    attestation: RouteAttestation,
    revision: Revision,
    transition: impl FnOnce(&mut RootDelegatedRoute) -> Result<(), meshspan_domain::DelegationError>,
) -> Result<EntityReference, RepositoryError> {
    let mut route = load_root_route(transaction, scope_id)?;
    require_root_authority(transaction, &route, repository_partition_id)?;
    transition(&mut route).map_err(|_| RepositoryError::InvalidCommand)?;
    verify_attestation(transaction, &route.signing_payload(), attestation)?;
    update_scope(transaction, route.route(), revision)?;
    persist_route_history(transaction, context, &route, attestation)?;
    Ok(route_reference(route.route()))
}

pub(super) fn install_projection(
    transaction: &Transaction<'_>,
    repository_partition_id: PartitionId,
    context: CommandContext,
    command: &InstallScopeRouteProjection,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.route.root_partition_id() == repository_partition_id
        || command
            .route
            .pending_admission()
            .is_some_and(|admission| admission.measured_at() > context.occurred_at)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    verify_attestation(
        transaction,
        &command.route.signing_payload(),
        command.attestation,
    )?;
    let scope_id = command.route.scope().scope_id();
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM partition_scopes WHERE scope_id = ?1)",
        [scope_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if exists == 0 {
        validate_initial_projection(&command.route)?;
        persist_new_scope(transaction, command.route.route(), revision)?;
        persist_root_scope(transaction, context, &command.route, 2, revision)?;
    } else {
        let current = load_root_route(transaction, scope_id)?;
        require_projection(transaction, &current, repository_partition_id)?;
        validate_projection_transition(&current, &command.route)?;
        if current.pending_admission().is_none() && command.route.pending_admission().is_some() {
            let destination = command
                .route
                .route()
                .destination_partition()
                .ok_or(RepositoryError::InvalidCommand)?;
            persist_admission(
                transaction,
                context,
                &command.route,
                current.route().source_partition(),
                destination,
                revision,
            )?;
        }
        update_scope(transaction, command.route.route(), revision)?;
    }
    persist_route_history(transaction, context, &command.route, command.attestation)?;
    Ok(route_reference(command.route.route()))
}

fn persist_root_scope(
    transaction: &Transaction<'_>,
    context: CommandContext,
    route: &RootDelegatedRoute,
    directory_role: i64,
    revision: Revision,
) -> Result<(), RepositoryError> {
    if !(1..=2).contains(&directory_role) {
        return Err(RepositoryError::InvalidCommand);
    }
    let (range_kind, start, end) = key_range_columns(route.scope().key_range());
    transaction.execute(
        "INSERT INTO root_delegated_scopes(
            scope_id, root_partition_id, directory_role, operation_family, initial_routing_epoch,
            key_range_kind, start_inclusive, end_exclusive, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            route.scope().scope_id().as_bytes().as_slice(),
            route.root_partition_id().as_bytes().as_slice(),
            directory_role,
            family_code(route.scope().family()),
            to_i64(route.route().routing_epoch())?,
            range_kind,
            start,
            end,
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn persist_admission(
    transaction: &Transaction<'_>,
    context: CommandContext,
    route: &RootDelegatedRoute,
    source_partition_id: PartitionId,
    destination_partition_id: PartitionId,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let admission = route
        .pending_admission()
        .ok_or(RepositoryError::InvalidCommand)?;
    transaction.execute(
        "INSERT INTO root_delegation_admissions(
            scope_id, routing_epoch, source_partition_id, destination_partition_id,
            eligible_member_count, planned_voter_count, quorum_plan_digest,
            load_evidence_digest, measured_at, admitted_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            route.scope().scope_id().as_bytes().as_slice(),
            to_i64(route.route().routing_epoch())?,
            source_partition_id.as_bytes().as_slice(),
            destination_partition_id.as_bytes().as_slice(),
            i64::from(admission.eligible_member_count()),
            i64::from(admission.planned_voter_count()),
            admission.quorum_plan_digest().as_slice(),
            admission.load_evidence_digest().as_slice(),
            admission.measured_at().get(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn persist_route_history(
    transaction: &Transaction<'_>,
    context: CommandContext,
    root_route: &RootDelegatedRoute,
    attestation: RouteAttestation,
) -> Result<(), RepositoryError> {
    let payload = root_route.signing_payload();
    let route = root_route.route();
    let route_digest: [u8; 32] = Sha256::digest(&payload).into();
    let scope = route.scope_id().as_bytes();
    let owner = route.source_partition().as_bytes();
    let signer = attestation.signer_node_id.as_bytes();
    let transition_sequence: i64 = transaction.query_row(
        "SELECT coalesce(max(transition_sequence), 0) + 1 FROM partition_routes
         WHERE routing_epoch = ?1 AND scope_id = ?2",
        params![to_i64(route.routing_epoch())?, scope.as_slice()],
        |row| row.get(0),
    )?;
    if transition_sequence <= 0 {
        return Err(RepositoryError::CapacityExceeded);
    }
    transaction.execute(
        "INSERT INTO partition_routes(
            routing_epoch, transition_sequence, scope_id, partition_id, ownership_epoch, route_payload,
            route_digest, signer_node_id, signer_generation, signature, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            to_i64(route.routing_epoch())?,
            transition_sequence,
            scope.as_slice(),
            owner.as_slice(),
            to_i64(route.ownership_epoch())?,
            payload,
            route_digest.as_slice(),
            signer.as_slice(),
            to_i64(attestation.signer_generation)?,
            attestation.signature.as_slice(),
            context.occurred_at.get()
        ],
    )?;
    Ok(())
}

fn route_reference(route: ScopeRoute) -> EntityReference {
    EntityReference {
        kind: EntityKind::ScopeRoute,
        id: route.scope_id().as_bytes(),
    }
}

fn require_root_authority(
    connection: &rusqlite::Connection,
    route: &RootDelegatedRoute,
    repository_partition_id: PartitionId,
) -> Result<(), RepositoryError> {
    if route.root_partition_id() == repository_partition_id
        && directory_role(connection, route.scope().scope_id())? == 1
    {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn require_projection(
    connection: &rusqlite::Connection,
    route: &RootDelegatedRoute,
    repository_partition_id: PartitionId,
) -> Result<(), RepositoryError> {
    if route.root_partition_id() != repository_partition_id
        && directory_role(connection, route.scope().scope_id())? == 2
    {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn directory_role(
    connection: &rusqlite::Connection,
    scope_id: ScopeId,
) -> Result<i64, RepositoryError> {
    let role = connection
        .query_row(
            "SELECT directory_role FROM root_delegated_scopes WHERE scope_id = ?1",
            [scope_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    if (1..=2).contains(&role) {
        Ok(role)
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn validate_initial_projection(route: &RootDelegatedRoute) -> Result<(), RepositoryError> {
    if route.route().source_partition() == route.root_partition_id()
        && route.route().ownership_epoch() == 1
        && matches!(route.route().state(), RouteState::Active)
        && route.pending_admission().is_none()
    {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_projection_transition(
    current: &RootDelegatedRoute,
    incoming: &RootDelegatedRoute,
) -> Result<(), RepositoryError> {
    if current.root_partition_id() != incoming.root_partition_id()
        || current.scope() != incoming.scope()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let mut expected = *current;
    match (current.route().state(), incoming.route().state()) {
        (RouteState::Active, RouteState::Preparing { destination }) => expected
            .begin_delegation(
                destination,
                incoming.route().routing_epoch(),
                incoming
                    .pending_admission()
                    .ok_or(RepositoryError::InvalidCommand)?,
            )
            .map_err(|_| RepositoryError::InvalidCommand)?,
        (RouteState::Preparing { .. }, RouteState::Frozen { evidence, .. }) => expected
            .freeze(incoming.route().routing_epoch(), evidence)
            .map_err(|_| RepositoryError::InvalidCommand)?,
        (RouteState::Preparing { .. }, RouteState::Active) => expected
            .abort(incoming.route().routing_epoch())
            .map_err(|_| RepositoryError::InvalidCommand)?,
        (RouteState::Frozen { .. }, RouteState::Active) => expected
            .activate(
                incoming.route().source_partition(),
                incoming.route().routing_epoch(),
                current
                    .route()
                    .handoff_evidence()
                    .ok_or(RepositoryError::CorruptState)?,
            )
            .map_err(|_| RepositoryError::InvalidCommand)?,
        _ => return Err(RepositoryError::InvalidCommand),
    }
    if expected == *incoming {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn is_root_partition(
    connection: &rusqlite::Connection,
    partition_id: PartitionId,
) -> Result<bool, RepositoryError> {
    let kind = connection
        .query_row(
            "SELECT partition_kind FROM metadata_partitions WHERE partition_id = ?1",
            [partition_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    Ok(kind == Some(1))
}

const fn family_code(family: MetadataOperationFamily) -> i64 {
    match family {
        MetadataOperationFamily::RootControl => 1,
        MetadataOperationFamily::Identity => 2,
        MetadataOperationFamily::Authentication => 3,
        MetadataOperationFamily::Namespace => 4,
        MetadataOperationFamily::Configuration => 5,
        MetadataOperationFamily::Audit => 6,
        MetadataOperationFamily::StorageCatalogue => 7,
        MetadataOperationFamily::Work => 8,
    }
}

pub(super) fn parse_family(value: i64) -> Result<MetadataOperationFamily, RepositoryError> {
    match value {
        2 => Ok(MetadataOperationFamily::Identity),
        3 => Ok(MetadataOperationFamily::Authentication),
        4 => Ok(MetadataOperationFamily::Namespace),
        5 => Ok(MetadataOperationFamily::Configuration),
        6 => Ok(MetadataOperationFamily::Audit),
        7 => Ok(MetadataOperationFamily::StorageCatalogue),
        8 => Ok(MetadataOperationFamily::Work),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn key_range_columns(range: MetadataKeyRange) -> (i64, Option<Vec<u8>>, Option<Vec<u8>>) {
    match range {
        MetadataKeyRange::All => (1, None, None),
        MetadataKeyRange::Bounded {
            start_inclusive,
            end_exclusive,
        } => (
            2,
            Some(start_inclusive.to_vec()),
            Some(end_exclusive.to_vec()),
        ),
    }
}

pub(super) fn parse_key_range(
    kind: i64,
    start: Option<&[u8]>,
    end: Option<&[u8]>,
) -> Result<MetadataKeyRange, RepositoryError> {
    match (kind, start, end) {
        (1, None, None) => Ok(MetadataKeyRange::All),
        (2, Some(start), Some(end)) => {
            MetadataKeyRange::bounded(identifier_bytes(start)?, identifier_bytes(end)?)
                .map_err(|_| RepositoryError::CorruptState)
        }
        _ => Err(RepositoryError::CorruptState),
    }
}

pub(super) fn identifier_bytes(bytes: &[u8]) -> Result<[u8; 16], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
}
