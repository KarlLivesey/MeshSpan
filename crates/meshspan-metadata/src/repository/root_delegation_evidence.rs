// SPDX-License-Identifier: GPL-2.0-only

//! Fail-closed reconstruction and verification of permanent-root route evidence.

use ed25519_dalek::{Signature, VerifyingKey};
use meshspan_domain::{
    DelegatedMetadataScope, DelegationAdmission, RootDelegatedRoute, RouteState, ScopeId,
    ScopeRoute, UnixMicros,
};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use super::RepositoryError;
use super::apply::to_i64;
use super::root_delegation::{identifier_bytes, parse_family, parse_key_range};
use super::routing::{digest, load_scope, partition_id, positive_u64};

pub(super) fn load_root_route(
    connection: &rusqlite::Connection,
    scope_id: ScopeId,
) -> Result<RootDelegatedRoute, RepositoryError> {
    let route = load_scope(connection, scope_id)?;
    let scope_bytes = scope_id.as_bytes();
    let directory = connection
        .query_row(
            "SELECT root_partition_id, directory_role, operation_family, initial_routing_epoch,
                    key_range_kind, start_inclusive, end_exclusive
             FROM root_delegated_scopes WHERE scope_id = ?1",
            [scope_bytes.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    let scope = DelegatedMetadataScope::new(
        scope_id,
        parse_family(directory.2)?,
        parse_key_range(directory.4, directory.5.as_deref(), directory.6.as_deref())?,
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    let pending_admission = if matches!(route.state(), RouteState::Active) {
        None
    } else {
        Some(load_admission(connection, route)?)
    };
    if !(1..=2).contains(&directory.1) {
        return Err(RepositoryError::CorruptState);
    }
    let restored =
        RootDelegatedRoute::restore(partition_id(&directory.0)?, scope, route, pending_admission)
            .map_err(|_| RepositoryError::CorruptState)?;
    verify_route_history(connection, &restored, positive_u64(directory.3)?)?;
    Ok(restored)
}

fn verify_route_history(
    connection: &rusqlite::Connection,
    current: &RootDelegatedRoute,
    initial_routing_epoch: u64,
) -> Result<(), RepositoryError> {
    let mut statement = connection.prepare(
        "SELECT routing_epoch, transition_sequence, scope_id, partition_id,
                ownership_epoch, route_payload, route_digest, signer_node_id,
                signer_generation, signature
         FROM partition_routes WHERE scope_id = ?1
         ORDER BY routing_epoch, transition_sequence",
    )?;
    let rows = statement
        .query_map([current.scope().scope_id().as_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, Vec<u8>>(9)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut previous: Option<(u64, u64)> = None;
    for row in &rows {
        let epoch = positive_u64(row.0)?;
        let sequence = positive_u64(row.1)?;
        let valid_order = match previous {
            None => sequence == 1,
            Some((prior_epoch, prior_sequence)) if epoch == prior_epoch => {
                sequence == prior_sequence.saturating_add(1)
            }
            Some((prior_epoch, _)) => epoch > prior_epoch && sequence == 1,
        };
        if !valid_order
            || ScopeId::from_bytes(identifier_bytes(&row.2)?)
                .map_err(|_| RepositoryError::CorruptState)?
                != current.scope().scope_id()
        {
            return Err(RepositoryError::CorruptState);
        }
        let computed_digest: [u8; 32] = Sha256::digest(&row.5).into();
        if row.6.as_slice() != computed_digest {
            return Err(RepositoryError::CorruptState);
        }
        verify_stored_attestation(connection, &row.5, &row.7, row.8, &row.9)?;
        previous = Some((epoch, sequence));
    }
    let first = rows.first().ok_or(RepositoryError::CorruptState)?;
    let latest = rows.last().ok_or(RepositoryError::CorruptState)?;
    if positive_u64(first.0)? != initial_routing_epoch
        || positive_u64(first.1)? != 1
        || partition_id(&first.3)? != current.root_partition_id()
        || positive_u64(first.4)? != 1
        || positive_u64(latest.0)? != current.route().routing_epoch()
        || partition_id(&latest.3)? != current.route().source_partition()
        || positive_u64(latest.4)? != current.route().ownership_epoch()
        || latest.5 != current.signing_payload()
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(())
}

fn verify_stored_attestation(
    connection: &rusqlite::Connection,
    payload: &[u8],
    signer_node_id: &[u8],
    signer_generation: i64,
    signature: &[u8],
) -> Result<(), RepositoryError> {
    let key: Vec<u8> = connection
        .query_row(
            "SELECT verifying_key FROM routing_signing_keys
             WHERE node_id = ?1 AND generation = ?2 AND state IN (1, 2)",
            params![signer_node_id, signer_generation],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key.try_into().map_err(|_| RepositoryError::CorruptState)?)
            .map_err(|_| RepositoryError::CorruptState)?;
    verifying_key
        .verify_strict(
            payload,
            &Signature::from_bytes(
                &signature
                    .try_into()
                    .map_err(|_| RepositoryError::CorruptState)?,
            ),
        )
        .map_err(|_| RepositoryError::CorruptState)
}

fn load_admission(
    connection: &rusqlite::Connection,
    route: ScopeRoute,
) -> Result<DelegationAdmission, RepositoryError> {
    let destination = route
        .destination_partition()
        .ok_or(RepositoryError::CorruptState)?;
    let row = connection
        .query_row(
            "SELECT source_partition_id, destination_partition_id,
                    eligible_member_count, planned_voter_count, quorum_plan_digest,
                    load_evidence_digest, measured_at
             FROM root_delegation_admissions
             WHERE scope_id = ?1 AND routing_epoch = ?2",
            params![
                route.scope_id().as_bytes().as_slice(),
                to_i64(route.routing_epoch())?
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    if partition_id(&row.0)? != route.source_partition() || partition_id(&row.1)? != destination {
        return Err(RepositoryError::CorruptState);
    }
    DelegationAdmission::new(
        u32::try_from(row.2).map_err(|_| RepositoryError::CorruptState)?,
        u8::try_from(row.3).map_err(|_| RepositoryError::CorruptState)?,
        digest(&row.4)?,
        digest(&row.5)?,
        UnixMicros::new(row.6),
    )
    .map_err(|_| RepositoryError::CorruptState)
}
