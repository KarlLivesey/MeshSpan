// SPDX-License-Identifier: GPL-2.0-only

//! Immutable externally issued public-certificate generations and installation proofs.

use meshspan_domain::{
    ExternalCertificatePublicationId, NodeId, PrincipalId, PublicCertificateId, Revision,
    UnixMicros,
};
use rusqlite::{OptionalExtension, Row, Transaction, params};

use super::acme::validate_worker;
use super::acme::{PublicCertificateSelection, PublicCertificateSource};
use super::apply::to_i64;
use super::{AuthoritativeRepository, EntityKind, EntityReference, RepositoryError};
use crate::{
    AcknowledgeExternalCertificateInstallation, CommandContext, MAXIMUM_EXTERNAL_CERTIFICATE_NAMES,
    PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, PublishExternalCertificate, SecretGenerationReference,
};

/// Exact durable external certificate publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalCertificatePublicationRecord {
    /// Stable publication identity.
    pub publication_id: ExternalCertificatePublicationId,
    /// Stable certificate identity and secret identity.
    pub certificate_id: PublicCertificateId,
    /// Strictly increasing publisher generation.
    pub generation: u64,
    /// Principal which authorised the publication.
    pub publisher_principal_id: PrincipalId,
    /// Canonical requested and validated DNS names.
    pub certificate_names: Vec<String>,
    /// Exact encrypted bundle generation.
    pub certificate: SecretGenerationReference,
    /// Digest of the canonical decrypted bundle.
    pub bundle_digest: [u8; 32],
    /// Digest of the canonical certificate chain.
    pub chain_digest: [u8; 32],
    /// Fingerprint of the matching leaf public key.
    pub public_key_fingerprint: [u8; 32],
    /// Validated certificate lower validity bound.
    pub not_before: UnixMicros,
    /// Validated certificate upper validity bound.
    pub not_after: UnixMicros,
    /// Authority-agreed publication instant.
    pub created_at: UnixMicros,
    /// Immutable publication revision.
    pub revision: Revision,
}

/// Durable proof that one gateway selected an externally published generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalCertificateInstallationRecord {
    /// Publication whose bundle was installed.
    pub publication_id: ExternalCertificatePublicationId,
    /// Gateway which loaded and selected the bundle.
    pub gateway_node_id: NodeId,
    /// Gateway process incarnation which performed the installation.
    pub gateway_incarnation: u64,
    /// Exact encrypted certificate generation installed.
    pub certificate: SecretGenerationReference,
    /// Digest of the decrypted canonical bundle.
    pub bundle_digest: [u8; 32],
    /// Authority-agreed acknowledgement instant.
    pub installed_at: UnixMicros,
    /// Revision which committed the acknowledgement.
    pub revision: Revision,
}

pub(super) fn publish(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &PublishExternalCertificate,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_publication(transaction, context, value)?;
    super::secret_generation::commit(transaction, context, &value.certificate, revision)?;
    transaction.execute(
        "INSERT INTO external_certificate_publications(
            publication_id, certificate_id, generation, publisher_principal_id,
            certificate_secret_kind, certificate_secret_id, certificate_secret_generation,
            bundle_digest, chain_digest, public_key_fingerprint, not_before, not_after,
            created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            value.publication_id.as_bytes().as_slice(),
            value.certificate_id.as_bytes().as_slice(),
            to_i64(value.generation)?,
            context.actor_principal_id.as_bytes().as_slice(),
            i64::from(PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND),
            value.certificate_id.as_bytes().as_slice(),
            to_i64(value.generation)?,
            value.bundle_digest.as_slice(),
            value.chain_digest.as_slice(),
            value.public_key_fingerprint.as_slice(),
            value.not_before.get(),
            value.not_after.get(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    for (ordinal, name) in value.certificate_names.as_slice().iter().enumerate() {
        transaction.execute(
            "INSERT INTO external_certificate_publication_names(publication_id, ordinal, dns_name)
             VALUES (?1, ?2, ?3)",
            params![
                value.publication_id.as_bytes().as_slice(),
                i64::try_from(ordinal).map_err(|_| RepositoryError::CapacityExceeded)?,
                name,
            ],
        )?;
    }
    Ok(publication_entity(value.publication_id))
}

pub(super) fn acknowledge_installation(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: AcknowledgeExternalCertificateInstallation,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_worker(
        transaction,
        value.gateway_node_id,
        value.gateway_incarnation,
    )?;
    validate_installation(transaction, value)?;
    if let Some(existing) =
        existing_installation(transaction, value.publication_id, value.gateway_node_id)?
    {
        if existing.gateway_incarnation == value.gateway_incarnation
            && existing.certificate == value.certificate
            && existing.bundle_digest == value.bundle_digest
        {
            return Ok(publication_entity(value.publication_id));
        }
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO external_public_certificate_installations(
            publication_id, gateway_node_id, gateway_incarnation, certificate_secret_kind,
            certificate_secret_id, certificate_secret_generation, bundle_digest, installed_at,
            revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            value.publication_id.as_bytes().as_slice(),
            value.gateway_node_id.as_bytes().as_slice(),
            to_i64(value.gateway_incarnation)?,
            i64::from(PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND),
            value.certificate.secret_id.as_slice(),
            to_i64(value.certificate.generation)?,
            value.bundle_digest.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(publication_entity(value.publication_id))
}

pub(super) fn latest_public_certificate(
    database: &crate::PartitionDatabase,
) -> Result<Option<PublicCertificateSelection>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT publication_id, certificate_secret_id, certificate_secret_generation,
                    bundle_digest, publisher_principal_id, created_at, revision
             FROM external_certificate_publications
             ORDER BY created_at DESC, publication_id DESC
             LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let publication_id = ExternalCertificatePublicationId::from_bytes(exact(stored.0)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let selection = PublicCertificateSelection {
        source: PublicCertificateSource::ExternalPublication(publication_id),
        certificate: SecretGenerationReference {
            secret_id: exact(stored.1)?,
            generation: positive(stored.2)?,
        },
        bundle_digest: exact(stored.3)?,
        configured_by: PrincipalId::from_bytes(exact(stored.4)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        completed_at: UnixMicros::new(stored.5),
        source_revision: Revision::new(positive(stored.6)?),
    };
    if selection.bundle_digest == [0; 32] || selection.completed_at.get() < 0 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(selection))
}

pub(super) fn newest_selection(
    acme: Option<PublicCertificateSelection>,
    external: Option<PublicCertificateSelection>,
) -> Option<PublicCertificateSelection> {
    match (acme, external) {
        (None, None) => None,
        (Some(selection), None) | (None, Some(selection)) => Some(selection),
        (Some(acme), Some(external)) => {
            if selection_key(external) > selection_key(acme) {
                Some(external)
            } else {
                Some(acme)
            }
        }
    }
}

fn selection_key(selection: PublicCertificateSelection) -> (i64, u8, [u8; 16]) {
    match selection.source {
        PublicCertificateSource::AcmeOrder(order_id) => {
            (selection.completed_at.get(), 1, order_id.as_bytes())
        }
        PublicCertificateSource::ExternalPublication(publication_id) => {
            (selection.completed_at.get(), 2, publication_id.as_bytes())
        }
    }
}

impl AuthoritativeRepository {
    /// Returns one immutable external certificate publication and all canonical names.
    ///
    /// # Errors
    ///
    /// Fails closed when persisted identity, secret, validity, digest or name state is malformed.
    pub fn external_certificate_publication(
        &self,
        publication_id: ExternalCertificatePublicationId,
    ) -> Result<Option<ExternalCertificatePublicationRecord>, RepositoryError> {
        publication(&self.database, publication_id)
    }

    /// Returns one gateway's exact external certificate installation proof.
    ///
    /// # Errors
    ///
    /// Fails closed when persisted identity, generation or digest fields are malformed.
    pub fn external_certificate_installation(
        &self,
        publication_id: ExternalCertificatePublicationId,
        gateway_node_id: NodeId,
    ) -> Result<Option<ExternalCertificateInstallationRecord>, RepositoryError> {
        existing_installation(self.database.connection(), publication_id, gateway_node_id)
    }
}

fn validate_publication(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &PublishExternalCertificate,
) -> Result<(), RepositoryError> {
    let secret_context = value.certificate.secret.context;
    if value.generation == 0
        || value.certificate_names.is_empty()
        || value.certificate_names.len() > MAXIMUM_EXTERNAL_CERTIFICATE_NAMES
        || secret_context.kind() != PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND
        || secret_context.id() != value.certificate_id.as_bytes()
        || secret_context.generation() != value.generation
        || value.bundle_digest == [0; 32]
        || value.chain_digest == [0; 32]
        || value.public_key_fingerprint == [0; 32]
        || value.not_before.get() < 0
        || value.not_after <= context.occurred_at
        || value.not_after <= value.not_before
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let latest: Option<i64> = transaction.query_row(
        "SELECT max(generation) FROM external_certificate_publications",
        [],
        |row| row.get(0),
    )?;
    let generation =
        i64::try_from(value.generation).map_err(|_| RepositoryError::CapacityExceeded)?;
    if latest.is_some_and(|latest| latest >= generation) {
        return Err(RepositoryError::StaleRevision);
    }
    Ok(())
}

fn validate_installation(
    transaction: &Transaction<'_>,
    value: AcknowledgeExternalCertificateInstallation,
) -> Result<(), RepositoryError> {
    if value.gateway_incarnation == 0
        || value.certificate.secret_id == [0; 16]
        || value.certificate.generation == 0
        || value.bundle_digest == [0; 32]
        || value.observed_publication_revision == Revision::ZERO
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let matches = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM external_certificate_publications p
            JOIN secret_recipient_envelopes e
              ON e.secret_kind = ?1
             AND e.secret_id = p.certificate_secret_id
             AND e.secret_generation = p.certificate_secret_generation
            JOIN secret_wrapping_recipients r
              ON r.key_fingerprint = e.recipient_key_fingerprint
            WHERE p.publication_id = ?2
              AND p.certificate_secret_id = ?3 AND p.certificate_secret_generation = ?4
              AND p.bundle_digest = ?5 AND p.revision = ?6
              AND r.recipient_kind = 1 AND r.owner_id = ?7
         )",
        params![
            i64::from(PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND),
            value.publication_id.as_bytes().as_slice(),
            value.certificate.secret_id.as_slice(),
            to_i64(value.certificate.generation)?,
            value.bundle_digest.as_slice(),
            to_i64(value.observed_publication_revision.get())?,
            value.gateway_node_id.as_bytes().as_slice(),
        ],
        |row| row.get::<_, i64>(0),
    )?;
    if matches == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn publication(
    database: &crate::PartitionDatabase,
    publication_id: ExternalCertificatePublicationId,
) -> Result<Option<ExternalCertificatePublicationRecord>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT publication_id, certificate_id, generation, publisher_principal_id,
                    certificate_secret_id, certificate_secret_generation, bundle_digest,
                    chain_digest, public_key_fingerprint, not_before, not_after, created_at,
                    revision
             FROM external_certificate_publications WHERE publication_id = ?1",
            [publication_id.as_bytes().as_slice()],
            decode_publication,
        )
        .optional()?;
    stored
        .map(|record| with_names(database, record))
        .transpose()
}

fn decode_publication(row: &Row<'_>) -> rusqlite::Result<ExternalCertificatePublicationRecord> {
    decode_publication_inner(row).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_publication_inner(
    row: &Row<'_>,
) -> Result<ExternalCertificatePublicationRecord, RepositoryError> {
    let certificate_id = PublicCertificateId::from_bytes(exact(row.get(1)?)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let record = ExternalCertificatePublicationRecord {
        publication_id: ExternalCertificatePublicationId::from_bytes(exact(row.get(0)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        certificate_id,
        generation: positive(row.get(2)?)?,
        publisher_principal_id: PrincipalId::from_bytes(exact(row.get(3)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        certificate_names: Vec::new(),
        certificate: SecretGenerationReference {
            secret_id: exact(row.get(4)?)?,
            generation: positive(row.get(5)?)?,
        },
        bundle_digest: exact(row.get(6)?)?,
        chain_digest: exact(row.get(7)?)?,
        public_key_fingerprint: exact(row.get(8)?)?,
        not_before: UnixMicros::new(row.get(9)?),
        not_after: UnixMicros::new(row.get(10)?),
        created_at: UnixMicros::new(row.get(11)?),
        revision: Revision::new(positive(row.get(12)?)?),
    };
    if record.certificate.secret_id != certificate_id.as_bytes()
        || record.certificate.generation != record.generation
        || record.bundle_digest == [0; 32]
        || record.chain_digest == [0; 32]
        || record.public_key_fingerprint == [0; 32]
        || record.not_before.get() < 0
        || record.not_after <= record.not_before
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(record)
}

fn with_names(
    database: &crate::PartitionDatabase,
    mut record: ExternalCertificatePublicationRecord,
) -> Result<ExternalCertificatePublicationRecord, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT dns_name FROM external_certificate_publication_names
         WHERE publication_id = ?1 ORDER BY ordinal LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            record.publication_id.as_bytes().as_slice(),
            i64::try_from(MAXIMUM_EXTERNAL_CERTIFICATE_NAMES.saturating_add(1))
                .map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        |row| row.get::<_, String>(0),
    )?;
    record.certificate_names = rows.collect::<Result<Vec<_>, _>>()?;
    if record.certificate_names.is_empty()
        || record.certificate_names.len() > MAXIMUM_EXTERNAL_CERTIFICATE_NAMES
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(record)
}

fn existing_installation(
    transaction: &rusqlite::Connection,
    publication_id: ExternalCertificatePublicationId,
    gateway_node_id: NodeId,
) -> Result<Option<ExternalCertificateInstallationRecord>, RepositoryError> {
    transaction
        .query_row(
            "SELECT publication_id, gateway_node_id, gateway_incarnation,
                    certificate_secret_id, certificate_secret_generation, bundle_digest,
                    installed_at, revision
             FROM external_public_certificate_installations
             WHERE publication_id = ?1 AND gateway_node_id = ?2",
            params![
                publication_id.as_bytes().as_slice(),
                gateway_node_id.as_bytes().as_slice()
            ],
            |row| decode_installation_inner(row).map_err(|_| rusqlite::Error::InvalidQuery),
        )
        .optional()
        .map_err(RepositoryError::from)
}

fn decode_installation_inner(
    row: &Row<'_>,
) -> Result<ExternalCertificateInstallationRecord, RepositoryError> {
    Ok(ExternalCertificateInstallationRecord {
        publication_id: ExternalCertificatePublicationId::from_bytes(exact(row.get(0)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        gateway_node_id: NodeId::from_bytes(exact(row.get(1)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        gateway_incarnation: positive(row.get(2)?)?,
        certificate: SecretGenerationReference {
            secret_id: exact(row.get(3)?)?,
            generation: positive(row.get(4)?)?,
        },
        bundle_digest: exact(row.get(5)?)?,
        installed_at: UnixMicros::new(row.get(6)?),
        revision: Revision::new(positive(row.get(7)?)?),
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

const fn publication_entity(publication_id: ExternalCertificatePublicationId) -> EntityReference {
    EntityReference {
        kind: EntityKind::ExternalCertificatePublication,
        id: publication_id.as_bytes(),
    }
}
