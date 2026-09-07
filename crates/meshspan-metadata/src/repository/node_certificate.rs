// SPDX-License-Identifier: GPL-2.0-only

//! Atomic stage/install/retire transitions for private node certificates.

use meshspan_certificates::{
    NodeCertificateRequest, NodePublicIdentity, validate_node_certificate_renewal,
};
use meshspan_domain::{NodeId, Revision, UnixMicros};
use rusqlite::{OptionalExtension as _, Transaction, params};
use sha2::{Digest as _, Sha256};

use super::{AuthoritativeRepository, EntityKind, EntityReference, RepositoryError, apply::to_i64};
use crate::{
    AcknowledgeNodeCertificateInstallation, CommandContext, RetireNodeCertificate,
    StageNodeCertificate,
};

const MICROS_PER_SECOND: i64 = 1_000_000;
const OVERLAP_MICROS: i64 = 3_600 * MICROS_PER_SECOND;

/// Durable progress of a private certificate renewal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeCertificateRotationState {
    /// Peers may trust the staged certificate; the owner has not acknowledged installation.
    Staged,
    /// The owner selected the replacement; the prior leaf is temporarily accepted.
    Installed,
    /// The previous leaf is no longer accepted.
    Retired,
    /// The candidate expired without installation; the prior active leaf was not changed.
    Abandoned,
}

/// Exact public material needed to resume one private certificate rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeCertificateRotation {
    /// Owning node identity.
    pub node_id: NodeId,
    /// Incarnation which staged this renewal.
    pub incarnation: u64,
    /// Replacement certificate generation.
    pub generation: u64,
    /// Exact staged public leaf DER.
    pub certificate_der: Vec<u8>,
    /// Exact previous leaf retained for overlap.
    pub previous_certificate_der: Vec<u8>,
    /// Exact issuer, not whichever authority happens to be newest later.
    pub issuer_certificate_der: Vec<u8>,
    /// Immutable stage revision.
    pub staged_revision: Revision,
    /// Current lifecycle phase.
    pub state: NodeCertificateRotationState,
    /// Earliest prior-certificate retirement instant after installation acknowledgement.
    pub retire_after: Option<UnixMicros>,
    /// Exact exclusive candidate expiry, also used to abandon uninstalled work.
    pub valid_until: UnixMicros,
}

pub(super) fn stage(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &StageNodeCertificate,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_node(transaction, value.node_id, value.incarnation)?;
    let generation = value.generation;
    if generation <= value.previous_generation {
        return Err(RepositoryError::InvalidCommand);
    }
    let (previous, previous_until): (Vec<u8>, i64) = transaction.query_row(
        "SELECT certificate_der, valid_until FROM node_certificates
         WHERE node_id = ?1 AND generation = ?2 AND state = 1
           AND NOT EXISTS (SELECT 1 FROM node_certificate_rotations WHERE node_id = ?1 AND state IN (1, 2))
           AND (SELECT max(generation) + 1 FROM node_certificates WHERE node_id = ?1) = ?3",
        params![value.node_id.as_bytes().as_slice(), to_i64(value.previous_generation)?, to_i64(generation)?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?.ok_or(RepositoryError::InvalidCommand)?;
    let issuer: Vec<u8> = transaction
        .query_row(
            "SELECT certificate_der FROM online_certificate_authorities
         WHERE generation = ?1 AND state = 1 AND retired_at IS NULL
           AND (SELECT count(*) FROM meshes) = 1",
            [to_i64(value.issuer_generation)?],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    if value.valid_from.get() % MICROS_PER_SECOND != 0
        || value.valid_until.get() % MICROS_PER_SECOND != 0
        || value.valid_from > context.occurred_at
        || value.valid_until <= context.occurred_at
        || value.valid_until.get() <= previous_until
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let dns_name = format!(
        "node-{}.meshspan.internal",
        value.node_id.to_string().replace('-', "")
    );
    validate_node_certificate_renewal(
        &value.certificate_der,
        &previous,
        &issuer,
        NodeCertificateRequest {
            dns_name: &dns_name,
            generation,
            not_before: value.valid_from.get() / MICROS_PER_SECOND,
            not_after: value.valid_until.get() / MICROS_PER_SECOND,
        },
    )
    .map_err(|_| RepositoryError::InvalidCommand)?;
    transaction.execute(
        "INSERT INTO node_certificates(node_id, generation, certificate_der,
            certificate_fingerprint, valid_from, valid_until, state, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 2, ?7)",
        params![
            value.node_id.as_bytes().as_slice(),
            to_i64(generation)?,
            &value.certificate_der,
            Sha256::digest(&value.certificate_der).as_slice(),
            value.valid_from.get(),
            value.valid_until.get(),
            to_i64(revision.get())?
        ],
    )?;
    transaction.execute(
        "INSERT INTO node_certificate_rotations(node_id, generation, previous_generation,
            incarnation, issuer_generation, issuer_certificate_der, staged_revision, state)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
        params![
            value.node_id.as_bytes().as_slice(),
            to_i64(generation)?,
            to_i64(value.previous_generation)?,
            to_i64(value.incarnation)?,
            to_i64(value.issuer_generation)?,
            issuer,
            to_i64(revision.get())?
        ],
    )?;
    Ok(entity(value.node_id))
}

pub(super) fn acknowledge(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &AcknowledgeNodeCertificateInstallation,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_node(transaction, value.node_id, value.incarnation)?;
    let retire_after = context
        .occurred_at
        .get()
        .checked_add(OVERLAP_MICROS)
        .ok_or(RepositoryError::InvalidCommand)?;
    let certificate: Vec<u8> = transaction
        .query_row(
            "SELECT certificate.certificate_der FROM node_certificate_rotations rotation
         JOIN node_certificates certificate USING (node_id, generation)
         WHERE rotation.node_id = ?1 AND rotation.generation = ?2 AND rotation.incarnation = ?3
           AND rotation.staged_revision = ?4 AND rotation.state = 1 AND certificate.state = 2
           AND certificate.certificate_fingerprint = ?5
           AND certificate.valid_from <= ?6 AND certificate.valid_until > ?7",
            params![
                value.node_id.as_bytes().as_slice(),
                to_i64(value.generation)?,
                to_i64(value.incarnation)?,
                to_i64(value.staged_revision.get())?,
                value.certificate_fingerprint.as_slice(),
                context.occurred_at.get(),
                retire_after
            ],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    NodePublicIdentity::from_certificate(&certificate)
        .and_then(|identity| {
            identity.verify_enrolment_transcript(&value.signing_transcript(), &value.signature)
        })
        .map_err(|_| RepositoryError::InvalidCommand)?;
    transaction.execute(
        "UPDATE node_certificates SET state = CASE generation WHEN ?2 THEN 1 ELSE 2 END,
            revision = ?3 WHERE node_id = ?1 AND (generation = ?2 OR generation =
                (SELECT previous_generation FROM node_certificate_rotations WHERE node_id = ?1 AND generation = ?2))",
        params![
            value.node_id.as_bytes().as_slice(),
            to_i64(value.generation)?,
            to_i64(revision.get())?
        ],
    )?;
    transaction.execute(
        "UPDATE node_certificate_rotations SET state = 2, installed_at = ?3,
            installed_revision = ?4, retire_after = ?5, installation_signature = ?6
         WHERE node_id = ?1 AND generation = ?2",
        params![
            value.node_id.as_bytes().as_slice(),
            to_i64(value.generation)?,
            context.occurred_at.get(),
            to_i64(revision.get())?,
            retire_after,
            &value.signature
        ],
    )?;
    Ok(entity(value.node_id))
}

pub(super) fn retire(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: RetireNodeCertificate,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_node(transaction, value.node_id, value.incarnation)?;
    let abandoned = transaction.execute(
        "UPDATE node_certificate_rotations SET state = 4
         WHERE node_id = ?1 AND generation = ?2 AND incarnation = ?3 AND state = 1
           AND EXISTS (SELECT 1 FROM node_certificates certificate
                WHERE certificate.node_id = ?1 AND certificate.generation = ?2
                  AND certificate.state = 2 AND certificate.valid_until <= ?4)",
        params![
            value.node_id.as_bytes().as_slice(),
            to_i64(value.generation)?,
            to_i64(value.incarnation)?,
            context.occurred_at.get()
        ],
    )?;
    if abandoned == 1 {
        transaction.execute(
            "UPDATE node_certificates SET state = 3, revision = ?3 WHERE node_id = ?1 AND generation = ?2",
            params![value.node_id.as_bytes().as_slice(), to_i64(value.generation)?, to_i64(revision.get())?],
        )?;
        return Ok(entity(value.node_id));
    }
    let changed = transaction.execute(
        "UPDATE node_certificate_rotations SET state = 3
         WHERE node_id = ?1 AND generation = ?2 AND incarnation = ?3 AND state = 2
           AND retire_after <= ?4
           AND EXISTS (SELECT 1 FROM node_certificates certificate
                       WHERE certificate.node_id = ?1 AND certificate.generation = ?2
                         AND certificate.state = 1 AND certificate.valid_until > ?4)",
        params![
            value.node_id.as_bytes().as_slice(),
            to_i64(value.generation)?,
            to_i64(value.incarnation)?,
            context.occurred_at.get()
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "UPDATE node_certificates SET state = 3, revision = ?3 WHERE node_id = ?1 AND generation =
            (SELECT previous_generation FROM node_certificate_rotations WHERE node_id = ?1 AND generation = ?2)",
        params![value.node_id.as_bytes().as_slice(), to_i64(value.generation)?, to_i64(revision.get())?],
    )?;
    Ok(entity(value.node_id))
}

impl AuthoritativeRepository {
    /// Loads the latest exact rotation, including its issuer and current overlap phase.
    ///
    /// # Errors
    ///
    /// Rejects invalid stored identities, revisions or lifecycle states and database errors.
    pub fn node_certificate_rotation(
        &self,
        node_id: NodeId,
    ) -> Result<Option<NodeCertificateRotation>, RepositoryError> {
        self.database
            .connection()
            .query_row(
                "SELECT rotation.incarnation, rotation.generation, certificate.certificate_der,
                    previous.certificate_der, rotation.issuer_certificate_der,
                    rotation.staged_revision, rotation.state, rotation.retire_after, certificate.valid_until
             FROM node_certificate_rotations rotation
             JOIN node_certificates certificate USING (node_id, generation)
             JOIN node_certificates previous ON previous.node_id = rotation.node_id
                  AND previous.generation = rotation.previous_generation
             WHERE rotation.node_id = ?1 ORDER BY rotation.generation DESC LIMIT 1",
                [node_id.as_bytes().as_slice()],
                |row| {
                    Ok(NodeCertificateRotation {
                        node_id,
                        incarnation: positive_column(row, 0)?,
                        generation: positive_column(row, 1)?,
                        certificate_der: row.get(2)?,
                        previous_certificate_der: row.get(3)?,
                        issuer_certificate_der: row.get(4)?,
                        staged_revision: Revision::new(positive_column(row, 5)?),
                        state: match row.get::<_, i64>(6)? {
                            1 => NodeCertificateRotationState::Staged,
                            2 => NodeCertificateRotationState::Installed,
                            3 => NodeCertificateRotationState::Retired,
                            4 => NodeCertificateRotationState::Abandoned,
                            _ => return Err(rusqlite::Error::InvalidQuery),
                        },
                    retire_after: row.get::<_, Option<i64>>(7)?.map(UnixMicros::new),
                    valid_until: UnixMicros::new(row.get(8)?),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }
}

fn validate_node(
    transaction: &Transaction<'_>,
    node_id: NodeId,
    incarnation: u64,
) -> Result<(), RepositoryError> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM nodes WHERE node_id = ?1 AND current_incarnation = ?2
            AND state = 2 AND retired_at IS NULL)",
        params![node_id.as_bytes().as_slice(), to_i64(incarnation)?],
        |row| row.get(0),
    )?;
    if incarnation == 0 || !exists {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn entity(node_id: NodeId) -> EntityReference {
    EntityReference {
        kind: EntityKind::Node,
        id: node_id.as_bytes(),
    }
}

fn positive_column(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(column)?;
    if value <= 0 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}
