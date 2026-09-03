// SPDX-License-Identifier: GPL-2.0-only

//! Shared append-only evidence for certificate delivery generations.

use meshspan_domain::{NodeId, Revision, UnixMicros};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};

use super::RepositoryError;
use super::apply::to_i64;
use crate::{PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, SecretGenerationReference};

pub(super) const ACME_SOURCE: i64 = 1;
pub(super) const EXTERNAL_SOURCE: i64 = 2;
pub(super) const MESH_LOCAL_SOURCE: i64 = 3;

#[derive(Clone, Copy)]
pub(super) struct DeliveryInstallation {
    pub(super) gateway_node_id: NodeId,
    pub(super) gateway_incarnation: u64,
    pub(super) certificate: SecretGenerationReference,
    pub(super) bundle_digest: [u8; 32],
    pub(super) installed_at: UnixMicros,
    pub(super) revision: Revision,
}

pub(super) fn validate_latest_recipient(
    transaction: &Transaction<'_>,
    gateway_node_id: NodeId,
    certificate: SecretGenerationReference,
) -> Result<(), RepositoryError> {
    let matches = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM secret_generations g
            JOIN secret_recipient_envelopes e
              ON e.secret_kind = g.secret_kind AND e.secret_id = g.secret_id
             AND e.secret_generation = g.generation
            JOIN secret_wrapping_recipients r
              ON r.key_fingerprint = e.recipient_key_fingerprint
            WHERE g.secret_kind = ?1 AND g.secret_id = ?2 AND g.generation = ?3
              AND g.generation = (
                SELECT max(latest.generation) FROM secret_generations latest
                WHERE latest.secret_kind = g.secret_kind AND latest.secret_id = g.secret_id
              )
              AND r.recipient_kind = 1 AND r.owner_id = ?4
         )",
        params![
            i64::from(PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND),
            certificate.secret_id.as_slice(),
            to_i64(certificate.generation)?,
            gateway_node_id.as_bytes().as_slice(),
        ],
        |row| row.get::<_, i64>(0),
    )?;
    if matches == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn record(
    transaction: &Transaction<'_>,
    source_kind: i64,
    source_id: [u8; 16],
    installation: DeliveryInstallation,
) -> Result<(), RepositoryError> {
    let inserted = transaction.execute(
        "INSERT INTO public_certificate_delivery_installations(
            source_kind, source_id, gateway_node_id, gateway_incarnation,
            certificate_secret_kind, certificate_secret_id, certificate_secret_generation,
            bundle_digest, installed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(
            source_kind, source_id, gateway_node_id, certificate_secret_generation
         ) DO NOTHING",
        params![
            source_kind,
            source_id.as_slice(),
            installation.gateway_node_id.as_bytes().as_slice(),
            to_i64(installation.gateway_incarnation)?,
            i64::from(PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND),
            installation.certificate.secret_id.as_slice(),
            to_i64(installation.certificate.generation)?,
            installation.bundle_digest.as_slice(),
            installation.installed_at.get(),
            to_i64(installation.revision.get())?,
        ],
    )?;
    if inserted == 1
        || existing(
            transaction,
            source_kind,
            source_id,
            installation.gateway_node_id,
        )?
        .is_some_and(|existing| same_installation(existing, installation))
    {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

pub(super) fn existing(
    connection: &Connection,
    source_kind: i64,
    source_id: [u8; 16],
    gateway_node_id: NodeId,
) -> Result<Option<DeliveryInstallation>, RepositoryError> {
    connection
        .query_row(
            "SELECT gateway_node_id, gateway_incarnation, certificate_secret_id,
                    certificate_secret_generation, bundle_digest, installed_at, revision
             FROM public_certificate_delivery_installations
             WHERE source_kind = ?1 AND source_id = ?2 AND gateway_node_id = ?3
             ORDER BY certificate_secret_generation DESC LIMIT 1",
            params![
                source_kind,
                source_id.as_slice(),
                gateway_node_id.as_bytes().as_slice(),
            ],
            decode,
        )
        .optional()
        .map_err(RepositoryError::from)
}

fn same_installation(left: DeliveryInstallation, right: DeliveryInstallation) -> bool {
    left.gateway_incarnation == right.gateway_incarnation
        && left.certificate == right.certificate
        && left.bundle_digest == right.bundle_digest
}

fn decode(row: &Row<'_>) -> rusqlite::Result<DeliveryInstallation> {
    decode_inner(row).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_inner(row: &Row<'_>) -> Result<DeliveryInstallation, RepositoryError> {
    Ok(DeliveryInstallation {
        gateway_node_id: NodeId::from_bytes(exact(row.get(0)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        gateway_incarnation: positive(row.get(1)?)?,
        certificate: SecretGenerationReference {
            secret_id: exact(row.get(2)?)?,
            generation: positive(row.get(3)?)?,
        },
        bundle_digest: exact(row.get(4)?)?,
        installed_at: UnixMicros::new(row.get(5)?),
        revision: Revision::new(positive(row.get(6)?)?),
    })
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(RepositoryError::CorruptState)
}

fn exact<const LENGTH: usize>(value: Vec<u8>) -> Result<[u8; LENGTH], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}
