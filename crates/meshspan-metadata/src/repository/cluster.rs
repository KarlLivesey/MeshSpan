// SPDX-License-Identifier: GPL-2.0-only

//! Administrator join grants and certificate-bound node enrolment.

use meshspan_domain::{JoinGrantId, PrincipalId, Revision, UnixMicros};
use meshspan_secret_envelope::WrappingPublicKey;
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, ConsumeJoinGrant, IssueJoinGrant, JoinRoles};

const MAXIMUM_CERTIFICATE_BYTES: usize = 64 * 1_024;
const MAXIMUM_PRIVATE_ENDPOINT_BYTES: usize = 512;

/// Current immutable issuance facts for one node join grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinGrantRecord {
    /// Stable public grant identity.
    pub join_grant_id: JoinGrantId,
    /// Administrator that issued and owns the grant.
    pub issued_by: PrincipalId,
    /// Exact admitted role ceiling.
    pub allowed_roles: JoinRoles,
    /// Total successful-consumption ceiling.
    pub maximum_uses: u16,
    /// Authoritative issuance instant.
    pub created_at: UnixMicros,
    /// Exclusive authoritative expiry.
    pub expires_at: UnixMicros,
    /// Revision last affecting this grant.
    pub revision: Revision,
}

/// Durable admitted-node facts needed to exactly replay an enrolment response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeEnrolmentRecord {
    /// Permanent admitted node identity.
    pub node_id: meshspan_domain::NodeId,
    /// Mesh-signed leaf certificate.
    pub certificate_der: Vec<u8>,
    /// Exact leaf certificate fingerprint.
    pub certificate_fingerprint: [u8; 32],
    /// Conservative metadata certificate fence.
    pub certificate_valid_until: UnixMicros,
    /// Staged private endpoint awaiting authenticated activation.
    pub private_endpoint: String,
    /// Original authoritative admission instant.
    pub admitted_at: UnixMicros,
    /// Admission revision.
    pub revision: Revision,
}

pub(super) fn join_grant(
    database: &crate::PartitionDatabase,
    join_grant_id: JoinGrantId,
) -> Result<Option<JoinGrantRecord>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT issued_by, allowed_roles, maximum_uses, created_at, expires_at, revision
             FROM join_grants WHERE join_grant_id = ?1",
            [join_grant_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u8>(1)?,
                    row.get::<_, u16>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    stored.map_or(Ok(None), |stored| {
        decode_join_grant(join_grant_id, stored).map(Some)
    })
}

pub(super) fn node_enrolment(
    database: &crate::PartitionDatabase,
    node_id: meshspan_domain::NodeId,
) -> Result<Option<NodeEnrolmentRecord>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT certificate.certificate_der, certificate.certificate_fingerprint,
                    certificate.valid_until, pending.private_endpoint, node.admitted_at,
                    node.revision
             FROM nodes AS node
             JOIN node_certificates AS certificate
               ON certificate.node_id = node.node_id AND certificate.generation = 1
             JOIN pending_node_activations AS pending ON pending.node_id = node.node_id
             WHERE node.node_id = ?1 AND node.state = 1 AND certificate.state = 1",
            [node_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((certificate_der, fingerprint, valid_until, private_endpoint, admitted_at, revision)) =
        stored
    else {
        return Ok(None);
    };
    let certificate_fingerprint: [u8; 32] = fingerprint
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    if certificate_der.is_empty()
        || certificate_fingerprint != <[u8; 32]>::from(Sha256::digest(&certificate_der))
        || !valid_private_endpoint(&private_endpoint)
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(NodeEnrolmentRecord {
        node_id,
        certificate_der,
        certificate_fingerprint,
        certificate_valid_until: UnixMicros::new(valid_until),
        private_endpoint,
        admitted_at: UnixMicros::new(admitted_at),
        revision: Revision::new(
            u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?,
        ),
    }))
}

fn decode_join_grant(
    join_grant_id: JoinGrantId,
    stored: (Vec<u8>, u8, u16, i64, i64, i64),
) -> Result<JoinGrantRecord, RepositoryError> {
    let (issued_by, allowed_roles, maximum_uses, created_at, expires_at, revision) = stored;
    let issued_by = PrincipalId::from_bytes(
        issued_by
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    let allowed_roles = JoinRoles::new(allowed_roles).map_err(|_| RepositoryError::CorruptState)?;
    let created_at = UnixMicros::new(created_at);
    let expires_at = UnixMicros::new(expires_at);
    let revision =
        Revision::new(u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?);
    if maximum_uses == 0 || expires_at <= created_at || revision == Revision::ZERO {
        return Err(RepositoryError::CorruptState);
    }
    Ok(JoinGrantRecord {
        join_grant_id,
        issued_by,
        allowed_roles,
        maximum_uses,
        created_at,
        expires_at,
        revision,
    })
}

pub(super) fn issue_join_grant(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: IssueJoinGrant,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.maximum_uses == 0
        || command.maximum_uses > 1_000
        || command.expires_at <= context.occurred_at
        || command.secret_digest == [0; 32]
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let grant = command.join_grant_id.as_bytes();
    let issuer = context.actor_principal_id.as_bytes();
    transaction.execute(
        "INSERT INTO join_grants(
            join_grant_id, secret_digest, issued_by, allowed_roles, maximum_uses, used_count,
            created_at, expires_at, revoked_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, NULL, ?8)",
        params![
            grant.as_slice(),
            command.secret_digest.as_slice(),
            issuer.as_slice(),
            command.allowed_roles.bits(),
            command.maximum_uses,
            context.occurred_at.get(),
            command.expires_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::JoinGrant,
        id: grant,
    })
}

pub(super) fn consume_join_grant(
    transaction: &Transaction<'_>,
    partition_id: [u8; 16],
    context: CommandContext,
    command: &ConsumeJoinGrant,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_enrolment(context, command)?;
    let grant = command.join_grant_id.as_bytes();
    let stored = transaction
        .query_row(
            "SELECT issued_by, allowed_roles, maximum_uses, used_count, expires_at, revoked_at
             FROM join_grants
             WHERE join_grant_id = ?1 AND secret_digest = ?2",
            params![grant.as_slice(), command.secret_digest.as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u8>(1)?,
                    row.get::<_, u16>(2)?,
                    row.get::<_, u16>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    let actor = context.actor_principal_id.as_bytes();
    let (issuer, allowed_roles, maximum_uses, used_count, expires_at, revoked_at) = stored;
    if issuer.as_slice() != actor
        || revoked_at.is_some()
        || expires_at <= context.occurred_at.get()
        || used_count >= maximum_uses
        || command.requested_roles.bits() & !allowed_roles != 0
    {
        return Err(RepositoryError::InvalidCommand);
    }
    persist_host(transaction, context, command, revision)?;
    persist_node(transaction, partition_id, context, command, revision)?;
    persist_pending_activation(transaction, context, command, revision)?;
    let updated = transaction.execute(
        "UPDATE join_grants SET used_count = used_count + 1, revision = ?1
         WHERE join_grant_id = ?2 AND used_count < maximum_uses AND revoked_at IS NULL",
        params![to_i64(revision.get())?, grant.as_slice()],
    )?;
    if updated != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    let node = command.node_id.as_bytes();
    transaction.execute(
        "INSERT INTO join_grant_consumptions(
            join_grant_id, node_id, certificate_fingerprint, consumed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            grant.as_slice(),
            node.as_slice(),
            command.certificate_fingerprint.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::Node,
        id: node,
    })
}

fn persist_pending_activation(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ConsumeJoinGrant,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let wrapping_key = WrappingPublicKey::from_bytes(command.wrapping_public_key)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    if !valid_private_endpoint(&command.private_endpoint) {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO pending_node_activations(
            node_id, wrapping_public_key, wrapping_key_fingerprint, private_endpoint,
            admitted_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            command.node_id.as_bytes().as_slice(),
            wrapping_key.as_bytes().as_slice(),
            wrapping_key.fingerprint().as_slice(),
            command.private_endpoint,
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn valid_private_endpoint(value: &str) -> bool {
    (3..=MAXIMUM_PRIVATE_ENDPOINT_BYTES).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b':' | b'[' | b']' | b'-')
        })
}

fn validate_enrolment(
    context: CommandContext,
    command: &ConsumeJoinGrant,
) -> Result<(), RepositoryError> {
    if command.incarnation == 0
        || command.certificate_der.is_empty()
        || command.certificate_der.len() > MAXIMUM_CERTIFICATE_BYTES
        || command.certificate_valid_until <= context.occurred_at
        || command.secret_digest == [0; 32]
        || command.certificate_fingerprint
            != <[u8; 32]>::from(Sha256::digest(&command.certificate_der))
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn persist_host(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ConsumeJoinGrant,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let host = command.host_id.as_bytes();
    if let Some(name) = &command.new_host_name {
        transaction.execute(
            "INSERT INTO hosts(
                host_id, display_name, canonical_name, state, created_at, retired_at, revision
             ) VALUES (?1, ?2, ?3, 1, ?4, NULL, ?5)",
            params![
                host.as_slice(),
                name.display(),
                name.canonical(),
                context.occurred_at.get(),
                to_i64(revision.get())?,
            ],
        )?;
        return Ok(());
    }
    let active: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM hosts WHERE host_id = ?1 AND state = 1)",
        [host.as_slice()],
        |row| row.get(0),
    )?;
    if active == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn persist_node(
    transaction: &Transaction<'_>,
    partition_id: [u8; 16],
    context: CommandContext,
    command: &ConsumeJoinGrant,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let node = command.node_id.as_bytes();
    let host = command.host_id.as_bytes();
    let stored_revision = to_i64(revision.get())?;
    transaction.execute(
        "INSERT INTO nodes(
            node_id, host_id, display_name, canonical_name, state, current_incarnation,
            admitted_at, activated_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, NULL, NULL, ?7)",
        params![
            node.as_slice(),
            host.as_slice(),
            command.node_name.display(),
            command.node_name.canonical(),
            to_i64(command.incarnation)?,
            context.occurred_at.get(),
            stored_revision,
        ],
    )?;
    persist_roles(transaction, node, command.requested_roles, stored_revision)?;
    transaction.execute(
        "INSERT INTO node_certificates(
            node_id, generation, certificate_der, certificate_fingerprint, valid_from,
            valid_until, state, revision
         ) VALUES (?1, 1, ?2, ?3, ?4, ?5, 1, ?6)",
        params![
            node.as_slice(),
            command.certificate_der,
            command.certificate_fingerprint.as_slice(),
            context.occurred_at.get(),
            command.certificate_valid_until.get(),
            stored_revision,
        ],
    )?;
    if command.requested_roles.metadata_eligible() {
        let membership_revision: i64 = transaction.query_row(
            "SELECT current_membership_revision FROM metadata_partitions
             WHERE partition_id = ?1 AND state = 1",
            [partition_id.as_slice()],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO partition_voters(
                partition_id, node_id, membership_revision, member_role, state, revision
             ) VALUES (?1, ?2, ?3, 2, 2, ?4)",
            params![
                partition_id.as_slice(),
                node.as_slice(),
                membership_revision,
                stored_revision,
            ],
        )?;
    }
    Ok(())
}

fn persist_roles(
    transaction: &Transaction<'_>,
    node: [u8; 16],
    roles: JoinRoles,
    revision: i64,
) -> Result<(), RepositoryError> {
    for (bit, code) in [
        (JoinRoles::STORAGE, 1_u8),
        (JoinRoles::GATEWAY, 2),
        (JoinRoles::METADATA_ELIGIBLE, 3),
    ] {
        if roles.bits() & bit != 0 {
            transaction.execute(
                "INSERT INTO node_roles(node_id, role_code, revision) VALUES (?1, ?2, ?3)",
                params![node.as_slice(), code, revision],
            )?;
        }
    }
    Ok(())
}
