// SPDX-License-Identifier: GPL-2.0-only

//! Root-authoritative current presentation, separate from immutable activation history.

use super::{EntityKind, EntityReference, RepositoryError};
use crate::{NodeCapabilityPrior, NodeCommandContext, RefreshNodeCapabilities};
use meshspan_domain::{NodeId, Revision};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

/// Current capability presentation committed by the root authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeCapabilityPresentation {
    /// Exact admitted node.
    pub node_id: NodeId,
    /// Incarnation which made the presentation.
    pub incarnation: u64,
    /// Current certificate generation observed at commit.
    pub certificate_generation: u64,
    /// Current certificate fingerprint observed at commit.
    pub certificate_fingerprint: [u8; 32],
    /// Validated Hello digest; its preimage is a bounded local cache, not authority.
    pub capability_digest: [u8; 32],
    /// Revision used to fence the next refresh.
    pub revision: Revision,
}

pub(super) fn read(
    connection: &Connection,
    node_id: NodeId,
) -> Result<Option<NodeCapabilityPresentation>, RepositoryError> {
    let stored = connection.query_row("SELECT incarnation, certificate_generation, certificate_fingerprint, capability_digest, revision FROM node_capability_presentations WHERE node_id = ?1", [node_id.as_bytes().as_slice()], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,Vec<u8>>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,i64>(4)?))).optional()?;
    let Some((incarnation, generation, fingerprint, digest, revision)) = stored else {
        return Ok(None);
    };
    let record = NodeCapabilityPresentation {
        node_id,
        incarnation: positive(incarnation)?,
        certificate_generation: positive(generation)?,
        certificate_fingerprint: fingerprint
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
        capability_digest: digest
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
        revision: Revision::new(positive(revision)?),
    };
    if record.certificate_fingerprint == [0; 32] || record.capability_digest == [0; 32] {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(record))
}

pub(super) fn refresh(
    transaction: &Transaction<'_>,
    context: NodeCommandContext,
    command: &RefreshNodeCapabilities,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if context.actor_node_id != command.node_id || command.capability_digest == [0; 32] {
        return Err(RepositoryError::InvalidCommand);
    }
    let certificate_revision = validate_current_certificate(transaction, context, command)?;
    validate_prior(transaction, command, certificate_revision)?;
    transaction.execute("INSERT INTO node_capability_presentations(node_id, incarnation, certificate_generation, certificate_fingerprint, capability_digest, revision) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT(node_id) DO UPDATE SET incarnation=excluded.incarnation, certificate_generation=excluded.certificate_generation, certificate_fingerprint=excluded.certificate_fingerprint, capability_digest=excluded.capability_digest, revision=excluded.revision", params![command.node_id.as_bytes().as_slice(), to_i64(command.incarnation)?, to_i64(command.certificate_generation)?, command.certificate_fingerprint.as_slice(), command.capability_digest.as_slice(), to_i64(revision.get())?])?;
    Ok(EntityReference {
        kind: EntityKind::Node,
        id: command.node_id.as_bytes(),
    })
}

fn validate_current_certificate(
    transaction: &Transaction<'_>,
    context: NodeCommandContext,
    command: &RefreshNodeCapabilities,
) -> Result<Revision, RepositoryError> {
    let stored = transaction.query_row("SELECT node.current_incarnation, certificate.generation, certificate.certificate_fingerprint, certificate.certificate_der, certificate.valid_until, certificate.revision FROM nodes AS node JOIN node_certificates AS certificate ON certificate.node_id=node.node_id WHERE node.node_id=?1 AND node.state=2 AND certificate.state=1 ORDER BY certificate.generation DESC LIMIT 1", [command.node_id.as_bytes().as_slice()], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,Vec<u8>>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,i64>(4)?,row.get::<_,i64>(5)?))).optional()?.ok_or(RepositoryError::InvalidCommand)?;
    let (incarnation, generation, fingerprint, der, valid_until, revision) = stored;
    if positive(incarnation)? != command.incarnation
        || positive(generation)? != command.certificate_generation
        || fingerprint.as_slice() != command.certificate_fingerprint
        || <[u8; 32]>::from(Sha256::digest(&der)) != command.certificate_fingerprint
        || valid_until <= context.occurred_at.get()
    {
        return Err(RepositoryError::StaleRevision);
    }
    Ok(Revision::new(positive(revision)?))
}

fn validate_prior(
    transaction: &Transaction<'_>,
    command: &RefreshNodeCapabilities,
    certificate_revision: Revision,
) -> Result<(), RepositoryError> {
    let current = read(transaction, command.node_id)?;
    let activation = transaction.query_row("SELECT incarnation, capability_digest, revision FROM node_activations WHERE node_id=?1", [command.node_id.as_bytes().as_slice()], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,i64>(2)?))).optional()?;
    let valid = match command.prior {
        NodeCapabilityPrior::ExistingPresentation {
            revision,
            capability_digest,
        } => current.is_some_and(|record| {
            record.revision == revision && record.capability_digest == capability_digest
        }),
        NodeCapabilityPrior::InitialActivation {
            revision,
            capability_digest,
        } => {
            current.is_none()
                && match activation {
                    Some((incarnation, digest, stored_revision)) => {
                        // Activation is immutable historical evidence. Current incarnation and
                        // certificate authority were checked separately before this prior CAS.
                        positive(incarnation)? <= command.incarnation
                            && digest.as_slice() == capability_digest
                            && positive(stored_revision)? == revision.get()
                    }
                    None => false,
                }
        }
        NodeCapabilityPrior::InitialAdmittedCertificate {
            revision,
            generation,
            certificate_fingerprint,
        } => {
            current.is_none()
                && activation.is_none()
                && revision == certificate_revision
                && generation == command.certificate_generation
                && certificate_fingerprint == command.certificate_fingerprint
        }
    };
    if valid {
        Ok(())
    } else {
        Err(RepositoryError::StaleRevision)
    }
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    let value = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(value)
}
fn to_i64(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::CapacityExceeded)
}
