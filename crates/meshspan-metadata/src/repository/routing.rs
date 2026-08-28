// SPDX-License-Identifier: GPL-2.0-only

//! Signed catalogue routes and atomically persisted fenced scope handoffs.

use ed25519_dalek::{Signature, VerifyingKey};
use meshspan_domain::{HandoffEvidence, PartitionId, Revision, RouteState, ScopeId, ScopeRoute};
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    AbortScopeHandoff, ActivateScopeHandoff, BeginScopeHandoff, CommandContext,
    CreateMetadataPartition, CreateScopeRoute, FreezeScopeHandoff, RegisterRoutingSigner,
    RouteAttestation,
};

const ROUTING_KEY_ACTIVE: i64 = 1;
const ROUTE_ACTIVE: i64 = 1;
const ROUTE_PREPARING: i64 = 2;
const ROUTE_FROZEN: i64 = 3;

pub(super) fn register_signer(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: RegisterRoutingSigner,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.generation == 0 || VerifyingKey::from_bytes(&command.verifying_key).is_err() {
        return Err(RepositoryError::InvalidCommand);
    }
    let node = command.node_id.as_bytes();
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM nodes WHERE node_id = ?1 AND state IN (1, 2))",
        [node.as_slice()],
        |row| row.get(0),
    )?;
    if exists != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    let current_generation: i64 = transaction.query_row(
        "SELECT coalesce(max(generation), 0) FROM routing_signing_keys WHERE node_id = ?1",
        [node.as_slice()],
        |row| row.get(0),
    )?;
    if command.generation
        <= u64::try_from(current_generation).map_err(|_| RepositoryError::CorruptState)?
    {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "UPDATE routing_signing_keys SET state = 2, retired_at = ?1, revision = ?2
         WHERE node_id = ?3 AND state = 1",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            node.as_slice()
        ],
    )?;
    transaction.execute(
        "INSERT INTO routing_signing_keys(
            node_id, generation, verifying_key, state, created_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, 1, ?4, NULL, ?5)",
        params![
            node.as_slice(),
            to_i64(command.generation)?,
            command.verifying_key.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::RoutingSigner,
        id: node,
    })
}

pub(super) fn create_partition(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateMetadataPartition,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if !(1..=3).contains(&command.partition_kind) {
        return Err(RepositoryError::InvalidCommand);
    }
    let partition = command.partition_id.as_bytes();
    transaction.execute(
        "INSERT INTO metadata_partitions(
            partition_id, partition_kind, display_name, state, routing_epoch,
            current_membership_revision, created_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, 1, 1, 1, ?4, NULL, ?5)",
        params![
            partition.as_slice(),
            command.partition_kind,
            command.name.display(),
            context.occurred_at.get(),
            to_i64(revision.get())?
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::MetadataPartition,
        id: partition,
    })
}

pub(super) fn create_scope(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: CreateScopeRoute,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let route = ScopeRoute::new(
        command.scope_id,
        command.partition_id,
        1,
        command.routing_epoch,
    )
    .map_err(|_| RepositoryError::InvalidCommand)?;
    verify_attestation(transaction, &route, command.attestation)?;
    persist_new_scope(transaction, route, revision)?;
    persist_route_history(transaction, context, route, command.attestation)?;
    Ok(route_reference(route))
}

pub(super) fn begin_handoff(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: BeginScopeHandoff,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    transition_route(
        transaction,
        context,
        command.scope_id,
        command.attestation,
        revision,
        |route| route.begin_handoff(command.destination_partition_id, command.routing_epoch),
    )
}

pub(super) fn freeze_handoff(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: FreezeScopeHandoff,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    transition_route(
        transaction,
        context,
        command.scope_id,
        command.attestation,
        revision,
        |route| route.freeze(command.routing_epoch, command.evidence),
    )
}

pub(super) fn activate_handoff(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: ActivateScopeHandoff,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    transition_route(
        transaction,
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
    context: CommandContext,
    command: AbortScopeHandoff,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.reason_code == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    transition_route(
        transaction,
        context,
        command.scope_id,
        command.attestation,
        revision,
        |route| route.abort(command.routing_epoch),
    )
}

fn transition_route(
    transaction: &Transaction<'_>,
    context: CommandContext,
    scope_id: ScopeId,
    attestation: RouteAttestation,
    revision: Revision,
    transition: impl FnOnce(&mut ScopeRoute) -> Result<(), meshspan_domain::RouteError>,
) -> Result<EntityReference, RepositoryError> {
    let mut route = load_scope(transaction, scope_id)?;
    transition(&mut route).map_err(|_| RepositoryError::InvalidCommand)?;
    verify_attestation(transaction, &route, attestation)?;
    update_scope(transaction, route, revision)?;
    persist_route_history(transaction, context, route, attestation)?;
    Ok(route_reference(route))
}

pub(super) fn load_scope(
    transaction: &rusqlite::Connection,
    scope_id: ScopeId,
) -> Result<ScopeRoute, RepositoryError> {
    let scope = scope_id.as_bytes();
    let stored = transaction
        .query_row(
            "SELECT partition_id, ownership_epoch, routing_epoch, handoff_state,
                    destination_partition_id, frozen_revision, snapshot_digest
             FROM partition_scopes WHERE scope_id = ?1",
            [scope.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    let owner = partition_id(&stored.0)?;
    let ownership_epoch = positive_u64(stored.1)?;
    let routing_epoch = positive_u64(stored.2)?;
    match stored.3 {
        ROUTE_ACTIVE if stored.4.is_none() && stored.5.is_none() && stored.6.is_none() => {
            ScopeRoute::new(scope_id, owner, ownership_epoch, routing_epoch)
                .map_err(|_| RepositoryError::CorruptState)
        }
        ROUTE_PREPARING if stored.5.is_none() && stored.6.is_none() => {
            let mut route = route_before_handoff(scope_id, owner, ownership_epoch, routing_epoch)?;
            route
                .begin_handoff(
                    partition_id(stored.4.as_deref().ok_or(RepositoryError::CorruptState)?)?,
                    routing_epoch,
                )
                .map_err(|_| RepositoryError::CorruptState)?;
            Ok(route)
        }
        ROUTE_FROZEN => {
            let destination =
                partition_id(stored.4.as_deref().ok_or(RepositoryError::CorruptState)?)?;
            let mut route = route_before_handoff(scope_id, owner, ownership_epoch, routing_epoch)?;
            route
                .begin_handoff(destination, routing_epoch)
                .map_err(|_| RepositoryError::CorruptState)?;
            route
                .freeze(
                    route.routing_epoch(),
                    HandoffEvidence {
                        frozen_revision: Revision::new(positive_u64(
                            stored.5.ok_or(RepositoryError::CorruptState)?,
                        )?),
                        snapshot_digest: digest(
                            stored.6.as_deref().ok_or(RepositoryError::CorruptState)?,
                        )?,
                    },
                )
                .map_err(|_| RepositoryError::CorruptState)?;
            Ok(route)
        }
        _ => Err(RepositoryError::CorruptState),
    }
}

fn route_before_handoff(
    scope_id: ScopeId,
    owner: PartitionId,
    ownership_epoch: u64,
    routing_epoch: u64,
) -> Result<ScopeRoute, RepositoryError> {
    ScopeRoute::new(
        scope_id,
        owner,
        ownership_epoch,
        routing_epoch
            .checked_sub(1)
            .ok_or(RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn persist_new_scope(
    transaction: &Transaction<'_>,
    route: ScopeRoute,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let scope = route.scope_id().as_bytes();
    let partition = route.source_partition().as_bytes();
    transaction.execute(
        "INSERT INTO partition_scopes(
            scope_id, partition_id, ownership_epoch, routing_epoch, handoff_state,
            destination_partition_id, frozen_revision, snapshot_digest, revision
         ) VALUES (?1, ?2, ?3, ?4, 1, NULL, NULL, NULL, ?5)",
        params![
            scope.as_slice(),
            partition.as_slice(),
            to_i64(route.ownership_epoch())?,
            to_i64(route.routing_epoch())?,
            to_i64(revision.get())?
        ],
    )?;
    Ok(())
}

fn update_scope(
    transaction: &Transaction<'_>,
    route: ScopeRoute,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let scope = route.scope_id().as_bytes();
    let owner = route.source_partition().as_bytes();
    let destination = route.destination_partition().map(PartitionId::as_bytes);
    let evidence = route.handoff_evidence();
    let changed = transaction.execute(
        "UPDATE partition_scopes SET
            partition_id = ?1, ownership_epoch = ?2, routing_epoch = ?3, handoff_state = ?4,
            destination_partition_id = ?5, frozen_revision = ?6, snapshot_digest = ?7,
            revision = ?8
         WHERE scope_id = ?9",
        params![
            owner.as_slice(),
            to_i64(route.ownership_epoch())?,
            to_i64(route.routing_epoch())?,
            route_state_code(route.state()),
            destination.map(|value| value.to_vec()),
            evidence
                .map(|value| to_i64(value.frozen_revision.get()))
                .transpose()?,
            evidence.map(|value| value.snapshot_digest.to_vec()),
            to_i64(revision.get())?,
            scope.as_slice()
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn verify_attestation(
    transaction: &Transaction<'_>,
    route: &ScopeRoute,
    attestation: RouteAttestation,
) -> Result<(), RepositoryError> {
    if attestation.signer_generation == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    let node = attestation.signer_node_id.as_bytes();
    let key: Vec<u8> = transaction
        .query_row(
            "SELECT verifying_key FROM routing_signing_keys
             WHERE node_id = ?1 AND generation = ?2 AND state = ?3",
            params![
                node.as_slice(),
                to_i64(attestation.signer_generation)?,
                ROUTING_KEY_ACTIVE
            ],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key.try_into().map_err(|_| RepositoryError::CorruptState)?)
            .map_err(|_| RepositoryError::CorruptState)?;
    verifying_key
        .verify_strict(
            &route.signing_payload(),
            &Signature::from_bytes(&attestation.signature),
        )
        .map_err(|_| RepositoryError::InvalidCommand)
}

fn persist_route_history(
    transaction: &Transaction<'_>,
    context: CommandContext,
    route: ScopeRoute,
    attestation: RouteAttestation,
) -> Result<(), RepositoryError> {
    let payload = route.signing_payload();
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

const fn route_state_code(state: RouteState) -> i64 {
    match state {
        RouteState::Active => ROUTE_ACTIVE,
        RouteState::Preparing { .. } => ROUTE_PREPARING,
        RouteState::Frozen { .. } => ROUTE_FROZEN,
    }
}

fn route_reference(route: ScopeRoute) -> EntityReference {
    EntityReference {
        kind: EntityKind::ScopeRoute,
        id: route.scope_id().as_bytes(),
    }
}

fn partition_id(bytes: &[u8]) -> Result<PartitionId, RepositoryError> {
    PartitionId::from_bytes(
        bytes
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn digest(bytes: &[u8]) -> Result<[u8; 32], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn positive_u64(value: i64) -> Result<u64, RepositoryError> {
    let value = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(value)
    }
}
