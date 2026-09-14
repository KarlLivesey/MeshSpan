// SPDX-License-Identifier: GPL-2.0-only

//! Selected identity projection and retirement of source-node wrapping authority.

use super::{Error, Projection};
use crate::repository::{apply::to_i64, node_wrapping_key};
use crate::{AuthoritativeRepository, JoinRoles, RecoveryReplacementNode, RegisterNodeWrappingKey};
use meshspan_domain::NodeId;
use meshspan_recovery_bundle::RecoveredAuthority;
use rusqlite::{OptionalExtension as _, Transaction, params};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

pub(super) fn install(
    repository: &AuthoritativeRepository,
    transaction: &Transaction<'_>,
    authority: &RecoveredAuthority,
    projection: &Projection,
) -> Result<(), Error> {
    retire_wrapping_keys(transaction, projection)?;
    transaction.execute(
        "UPDATE nodes SET state = 4, retired_at = ?1, revision = ?2,
        bootstrap_private_endpoint = NULL WHERE state != 4",
        params![
            projection.fence.fenced_at.get(),
            to_i64(projection.revision.get())?
        ],
    )?;
    for node in &projection.plan.nodes {
        // Certificate generation is calculated before inserting this node's replacement leaf.
        let certificate = repository
            .issue_recovery_node_certificate(
                authority,
                &projection.control,
                node,
                projection.fence.fenced_at,
            )
            .map_err(|_| Error::InvalidCommand)?;
        project_identity(transaction, node, projection)?;
        project_wrapping_key(repository, transaction, node, projection)?;
        transaction.execute(
            "INSERT INTO node_certificates (node_id, generation, certificate_der,
            certificate_fingerprint, valid_from, valid_until, state, revision)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)",
            params![
                node.node_id.as_bytes().as_slice(),
                to_i64(certificate.generation())?,
                certificate.certificate_der(),
                Sha256::digest(certificate.certificate_der()).as_slice(),
                certificate
                    .not_before()
                    .checked_mul(1_000_000)
                    .ok_or(Error::InvalidCommand)?,
                certificate
                    .not_after()
                    .checked_mul(1_000_000)
                    .ok_or(Error::InvalidCommand)?,
                to_i64(projection.revision.get())?
            ],
        )?;
    }
    Ok(())
}

fn project_identity(
    transaction: &Transaction<'_>,
    node: &RecoveryReplacementNode,
    projection: &Projection,
) -> Result<(), Error> {
    let revision = to_i64(projection.revision.get())?;
    let now = projection.fence.fenced_at.get();
    transaction.execute("INSERT INTO hosts(host_id, display_name, canonical_name, state, created_at, retired_at, revision)
        VALUES (?1, ?2, ?3, 1, ?4, NULL, ?5) ON CONFLICT(host_id) DO UPDATE SET
        display_name = excluded.display_name, canonical_name = excluded.canonical_name,
        state = 1, retired_at = NULL, revision = excluded.revision",
        params![node.host_id.as_bytes().as_slice(), node.host_name.display(), node.host_name.canonical(), now, revision])?;
    transaction.execute("INSERT INTO nodes(node_id, host_id, display_name, canonical_name, state,
        current_incarnation, admitted_at, activated_at, retired_at, revision, bootstrap_private_endpoint)
        VALUES (?1, ?2, ?3, ?4, 2, ?5, ?6, ?6, NULL, ?7, ?8)
        ON CONFLICT(node_id) DO UPDATE SET host_id = excluded.host_id, display_name = excluded.display_name,
        canonical_name = excluded.canonical_name, state = 2, current_incarnation = excluded.current_incarnation,
        activated_at = excluded.activated_at, retired_at = NULL, revision = excluded.revision,
        bootstrap_private_endpoint = excluded.bootstrap_private_endpoint", params![node.node_id.as_bytes().as_slice(),
            node.host_id.as_bytes().as_slice(), node.node_name.display(), node.node_name.canonical(),
            to_i64(node.incarnation)?, now, revision, &node.private_endpoint])?;
    // This is current activation state, not the immutable audit history. Its old endpoint and
    // capability claim must not override the root-selected replacement's endpoint/incarnation.
    transaction.execute(
        "DELETE FROM node_activations WHERE node_id = ?1",
        [node.node_id.as_bytes().as_slice()],
    )?;
    transaction.execute(
        "DELETE FROM node_roles WHERE node_id = ?1",
        [node.node_id.as_bytes().as_slice()],
    )?;
    for (bit, code) in [
        (JoinRoles::STORAGE, 1),
        (JoinRoles::GATEWAY, 2),
        (JoinRoles::METADATA_ELIGIBLE, 3),
    ] {
        if node.roles.bits() & bit != 0 {
            transaction.execute(
                "INSERT INTO node_roles(node_id, role_code, revision) VALUES (?1, ?2, ?3)",
                params![node.node_id.as_bytes().as_slice(), code, revision],
            )?;
        }
    }
    Ok(())
}

fn project_wrapping_key(
    repository: &AuthoritativeRepository,
    transaction: &Transaction<'_>,
    node: &RecoveryReplacementNode,
    projection: &Projection,
) -> Result<(), Error> {
    if let Some(current) = node_wrapping_key::current(&repository.database, node.node_id)? {
        if current.public_key != node.wrapping_public_key {
            return Err(Error::CorruptState);
        }
        return Ok(());
    }
    let previous: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(generation), 0) FROM node_wrapping_keys WHERE node_id = ?1",
        [node.node_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let generation = previous
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(Error::CapacityExceeded)?;
    node_wrapping_key::register_at(
        transaction,
        projection.fence.fenced_at,
        RegisterNodeWrappingKey {
            node_id: node.node_id,
            generation,
            public_key: node.wrapping_public_key.as_bytes(),
            key_fingerprint: node.wrapping_public_key.fingerprint(),
        },
        projection.revision,
    )?;
    Ok(())
}

fn retire_wrapping_keys(
    transaction: &Transaction<'_>,
    projection: &Projection,
) -> Result<(), Error> {
    let selected: BTreeMap<_, _> = projection
        .plan
        .nodes
        .iter()
        .map(|node| (node.wrapping_public_key.fingerprint(), node.node_id))
        .collect();
    for (fingerprint, node) in &selected {
        let source: Option<(Vec<u8>, i64)> = transaction
            .query_row(
                "SELECT node_id, state FROM node_wrapping_keys WHERE key_fingerprint = ?1",
                [fingerprint.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if source.is_some_and(|(owner, state)| owner != node.as_bytes() || state != 1) {
            return Err(Error::InvalidCommand);
        }
    }
    let mut after: Option<[u8; 32]> = None;
    loop {
        let mut statement = transaction.prepare("SELECT key_fingerprint, node_id FROM node_wrapping_keys
            WHERE state IN (1, 2) AND (?1 IS NULL OR key_fingerprint > ?1) ORDER BY key_fingerprint LIMIT 128")?;
        let rows = statement
            .query_map([after.map(|key| key.to_vec())], |row| {
                Ok((row.get::<_, [u8; 32]>(0)?, row.get::<_, [u8; 16]>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if rows.is_empty() {
            break;
        }
        for (fingerprint, node) in rows {
            after = Some(fingerprint);
            if selected.get(&fingerprint)
                == Some(&NodeId::from_bytes(node).map_err(|_| Error::CorruptState)?)
            {
                continue;
            }
            retire_key(transaction, fingerprint, projection)?;
        }
    }
    Ok(())
}

fn retire_key(
    transaction: &Transaction<'_>,
    fingerprint: [u8; 32],
    projection: &Projection,
) -> Result<(), Error> {
    let parameters = params![
        projection.fence.fenced_at.get(),
        to_i64(projection.revision.get())?,
        fingerprint.as_slice()
    ];
    if transaction.execute("UPDATE node_wrapping_keys SET state = 3, retired_at = ?1, revision = ?2 WHERE key_fingerprint = ?3", parameters)? != 1
        || transaction.execute("UPDATE secret_wrapping_recipients SET state = 3, retired_at = ?1, revision = ?2
            WHERE key_fingerprint = ?3 AND recipient_kind = 1", parameters)? != 1 {
        return Err(Error::CorruptState);
    }
    Ok(())
}
