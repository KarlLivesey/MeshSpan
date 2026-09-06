// SPDX-License-Identifier: GPL-2.0-only

//! Fenced authoritative persistence for resumable ACME order state.

use meshspan_domain::{CertificateOrderId, NodeId, Revision};
use rusqlite::{OptionalExtension, Row, Transaction, params};
use sha2::{Digest as _, Sha256};

use super::{
    AuthoritativeRepository, EntityReference, RepositoryError, exact, exactly_one, order_entity,
    positive, require_live_claim, require_secret, update_order_revision, validate_worker,
};
use crate::repository::apply::to_i64;
use crate::{
    CheckpointCertificateOrder, CommandContext, MAXIMUM_CERTIFICATE_ORDER_CHECKPOINT_BYTES,
    PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND, SecretGenerationReference,
};

/// Validated restart point for one in-flight certificate order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateOrderCheckpointRecord {
    /// Stable order identity.
    pub order_id: CertificateOrderId,
    /// Claim generation which last advanced the checkpoint.
    pub claim_generation: u64,
    /// Worker which last advanced the checkpoint.
    pub worker_node_id: NodeId,
    /// Exact worker process incarnation.
    pub worker_incarnation: u64,
    /// Order-wide fence also bound into the ACME checkpoint.
    pub fence: u64,
    /// Encrypted leaf-key generation shared by replacement workers.
    pub certificate_key: SecretGenerationReference,
    /// Complete validated `meshspan-acme` checkpoint bytes.
    pub checkpoint: Vec<u8>,
    /// SHA-256 digest of `checkpoint`.
    pub checkpoint_digest: [u8; 32],
    /// Original publication claim's retained lease end, if old checkpoint material is missing.
    /// This read-only candidate may reflect a renewal; verify the exact receipt before using it.
    pub legacy_lease_expiry_candidate: Option<meshspan_domain::UnixMicros>,
    /// Latest authoritative revision.
    pub revision: Revision,
}

pub(crate) fn checkpoint(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &CheckpointCertificateOrder,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_worker(transaction, value.worker_node_id, value.worker_incarnation)?;
    require_live_claim(
        transaction,
        context,
        value.order_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    validate_checkpoint_binding(transaction, value)?;
    require_secret(
        transaction,
        PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND,
        value.certificate_key,
    )?;
    let checkpoint_digest: [u8; 32] = Sha256::digest(&value.checkpoint).into();
    let changed = transaction.execute(
        "INSERT INTO certificate_order_checkpoints(
            order_id, claim_generation, worker_node_id, worker_incarnation, fence,
            certificate_key_secret_kind, certificate_key_secret_id,
            certificate_key_secret_generation, checkpoint, checkpoint_digest, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(order_id) DO UPDATE SET
            claim_generation = excluded.claim_generation,
            worker_node_id = excluded.worker_node_id,
            worker_incarnation = excluded.worker_incarnation,
            fence = excluded.fence,
            checkpoint = excluded.checkpoint,
            checkpoint_digest = excluded.checkpoint_digest,
            revision = excluded.revision
         WHERE certificate_order_checkpoints.certificate_key_secret_kind
                   = excluded.certificate_key_secret_kind
           AND certificate_order_checkpoints.certificate_key_secret_id
                   = excluded.certificate_key_secret_id
           AND certificate_order_checkpoints.certificate_key_secret_generation
                   = excluded.certificate_key_secret_generation",
        params![
            value.order_id.as_bytes().as_slice(),
            to_i64(value.claim_generation)?,
            value.worker_node_id.as_bytes().as_slice(),
            to_i64(value.worker_incarnation)?,
            to_i64(value.fence)?,
            i64::from(PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND),
            value.certificate_key.secret_id.as_slice(),
            to_i64(value.certificate_key.generation)?,
            value.checkpoint,
            checkpoint_digest.as_slice(),
            to_i64(revision.get())?,
        ],
    )?;
    exactly_one(changed)?;
    update_order_revision(transaction, value.order_id, revision)?;
    Ok(order_entity(value.order_id))
}

impl AuthoritativeRepository {
    /// Returns the validated restart point for one in-flight certificate order.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed identity, secret reference, digest or ACME state.
    pub fn certificate_order_checkpoint(
        &self,
        order_id: CertificateOrderId,
    ) -> Result<Option<CertificateOrderCheckpointRecord>, RepositoryError> {
        load_checkpoint(self.database.connection(), order_id)
    }
}

pub(in crate::repository) fn load_checkpoint(
    connection: &rusqlite::Connection,
    order_id: CertificateOrderId,
) -> Result<Option<CertificateOrderCheckpointRecord>, RepositoryError> {
    let mut record = connection
        .query_row(
            "SELECT order_id, claim_generation, worker_node_id, worker_incarnation, fence,
                        certificate_key_secret_kind, certificate_key_secret_id,
                        certificate_key_secret_generation, checkpoint, checkpoint_digest, revision
                 FROM certificate_order_checkpoints WHERE order_id = ?1",
            [order_id.as_bytes().as_slice()],
            decode_checkpoint,
        )
        .optional()
        .map_err(RepositoryError::from)?;
    if let Some(value) = &mut record {
        let machine = validate_checkpoint_record_binding(connection, value)?;
        value.legacy_lease_expiry_candidate =
            legacy_lease_candidate(connection, value.order_id, &machine)?;
    }
    Ok(record)
}

fn validate_checkpoint_binding(
    connection: &rusqlite::Connection,
    value: &CheckpointCertificateOrder,
) -> Result<(), RepositoryError> {
    if value.checkpoint.is_empty()
        || value.checkpoint.len() > MAXIMUM_CERTIFICATE_ORDER_CHECKPOINT_BYTES
        || value.certificate_key.secret_id != value.order_id.as_bytes()
        || value.certificate_key.generation != 1
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let machine = meshspan_acme::AcmeOrderMachine::decode_checkpoint(&value.checkpoint)
        .map_err(|_| RepositoryError::InvalidCommand)?;
    if machine.order_epoch() != value.fence {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_machine_configuration(connection, value.order_id, &machine)
        .map_err(|_| RepositoryError::InvalidCommand)
}

fn validate_checkpoint_record_binding(
    connection: &rusqlite::Connection,
    value: &CertificateOrderCheckpointRecord,
) -> Result<meshspan_acme::AcmeOrderMachine, RepositoryError> {
    let machine = meshspan_acme::AcmeOrderMachine::decode_checkpoint(&value.checkpoint)
        .map_err(|_| RepositoryError::CorruptState)?;
    if machine.order_epoch() != value.fence {
        return Err(RepositoryError::CorruptState);
    }
    validate_machine_configuration(connection, value.order_id, &machine)?;
    Ok(machine)
}

fn legacy_lease_candidate(
    connection: &rusqlite::Connection,
    order_id: CertificateOrderId,
    machine: &meshspan_acme::AcmeOrderMachine,
) -> Result<Option<meshspan_domain::UnixMicros>, RepositoryError> {
    if machine.publication().is_some() {
        return Ok(None);
    }
    let Some(epoch) = machine.publication_epoch() else {
        return Ok(None);
    };
    let (expires_at, claimed_at): (i64, i64) = connection
        .query_row(
            "SELECT lease_expires_at, claimed_at FROM certificate_order_claims
         WHERE order_id = ?1 AND fence = ?2",
            params![order_id.as_bytes().as_slice(), to_i64(epoch)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    if claimed_at < 0 || expires_at <= claimed_at {
        return Err(RepositoryError::CorruptState);
    }
    // This projection is not part of the retained checkpoint or its digest. Only a matching
    // original provider receipt can prove that the lease end was the publication's lifetime.
    Ok(Some(meshspan_domain::UnixMicros::new(expires_at)))
}

fn validate_machine_configuration(
    connection: &rusqlite::Connection,
    order_id: CertificateOrderId,
    machine: &meshspan_acme::AcmeOrderMachine,
) -> Result<(), RepositoryError> {
    let directory_url: String = connection.query_row(
        "SELECT c.directory_url FROM certificate_orders o
         JOIN acme_configurations c ON c.config_id = o.config_id
         WHERE o.order_id = ?1",
        [order_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let mut statement = connection.prepare(
        "SELECT n.dns_name FROM certificate_orders o
         JOIN acme_configuration_names n ON n.config_id = o.config_id
         WHERE o.order_id = ?1 ORDER BY n.ordinal",
    )?;
    let names = statement
        .query_map([order_id.as_bytes().as_slice()], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if directory_url == machine.directory_url() && names == machine.dns_names() {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn decode_checkpoint(row: &Row<'_>) -> rusqlite::Result<CertificateOrderCheckpointRecord> {
    decode_checkpoint_inner(row).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_checkpoint_inner(
    row: &Row<'_>,
) -> Result<CertificateOrderCheckpointRecord, RepositoryError> {
    let order_id = CertificateOrderId::from_bytes(exact(row.get(0)?)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let certificate_key_kind = row.get::<_, i64>(5)?;
    let certificate_key = SecretGenerationReference {
        secret_id: exact(row.get(6)?)?,
        generation: positive(row.get(7)?)?,
    };
    let checkpoint: Vec<u8> = row.get(8)?;
    let checkpoint_digest: [u8; 32] = exact(row.get(9)?)?;
    let fence = positive(row.get(4)?)?;
    let checkpoint_matches_fence = matches!(
        meshspan_acme::AcmeOrderMachine::decode_checkpoint(&checkpoint),
        Ok(machine) if machine.order_epoch() == fence
    );
    if certificate_key_kind != i64::from(PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND)
        || certificate_key.secret_id != order_id.as_bytes()
        || certificate_key.generation != 1
        || checkpoint.is_empty()
        || checkpoint.len() > MAXIMUM_CERTIFICATE_ORDER_CHECKPOINT_BYTES
        || <[u8; 32]>::from(Sha256::digest(&checkpoint)) != checkpoint_digest
        || !checkpoint_matches_fence
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(CertificateOrderCheckpointRecord {
        order_id,
        claim_generation: positive(row.get(1)?)?,
        worker_node_id: NodeId::from_bytes(exact(row.get(2)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        worker_incarnation: positive(row.get(3)?)?,
        fence,
        certificate_key,
        checkpoint,
        checkpoint_digest,
        legacy_lease_expiry_candidate: None,
        revision: Revision::new(positive(row.get(10)?)?),
    })
}
