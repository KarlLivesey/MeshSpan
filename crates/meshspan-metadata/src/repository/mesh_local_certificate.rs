// SPDX-License-Identifier: GPL-2.0-only

//! Immutable encrypted mesh-local HTTPS signing authority.

use meshspan_domain::{
    MeshLocalCertificateAuthorityId, MeshLocalCertificateIssuanceId, PrincipalId,
    PublicCertificateId, Revision, UnixMicros,
};
use rusqlite::{OptionalExtension, Row, Transaction, params};
use sha2::{Digest as _, Sha256};

use super::acme::validate_worker;
use super::acme::{PublicCertificateSelection, PublicCertificateSource};
use super::apply::to_i64;
use super::{AuthoritativeRepository, EntityKind, EntityReference, RepositoryError};
use crate::{
    AcknowledgeMeshLocalCertificateInstallation, CommandContext,
    CreateMeshLocalCertificateAuthority, IssueMeshLocalCertificate,
    MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES, MAXIMUM_MESH_LOCAL_CERTIFICATE_NAMES,
    MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND, PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
    SecretGenerationReference,
};

/// Exact durable mesh-local HTTPS authority record without plaintext private material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshLocalCertificateAuthorityRecord {
    /// Stable authority identity.
    pub authority_id: MeshLocalCertificateAuthorityId,
    /// Current immutable generation.
    pub generation: u64,
    /// Public self-signed trust anchor in DER form.
    pub certificate_der: Vec<u8>,
    /// Digest of the exact trust anchor.
    pub certificate_digest: [u8; 32],
    /// Encrypted authority-key generation.
    pub authority_key: SecretGenerationReference,
    /// Principal which authorised local trust.
    pub created_by: PrincipalId,
    /// Inclusive authority validity start.
    pub not_before: UnixMicros,
    /// Exclusive authority validity end.
    pub not_after: UnixMicros,
    /// Authority-agreed creation instant.
    pub created_at: UnixMicros,
    /// Immutable creation revision.
    pub revision: Revision,
}

/// Exact durable endpoint generation issued by the mesh-local authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeshLocalCertificateIssuanceRecord {
    /// Stable issuance identity.
    pub issuance_id: MeshLocalCertificateIssuanceId,
    /// Exact signing authority identity.
    pub authority_id: MeshLocalCertificateAuthorityId,
    /// Exact signing authority generation.
    pub authority_generation: u64,
    /// Digest of the trust anchor which signed the endpoint.
    pub authority_certificate_digest: [u8; 32],
    /// Stable endpoint certificate identity.
    pub certificate_id: PublicCertificateId,
    /// Strictly increasing endpoint generation.
    pub generation: u64,
    /// Canonical DNS names.
    pub certificate_names: Vec<String>,
    /// Exact encrypted endpoint bundle generation.
    pub certificate: SecretGenerationReference,
    /// Digest of the canonical decrypted endpoint bundle.
    pub bundle_digest: [u8; 32],
    /// Fingerprint of the endpoint public key.
    pub public_key_fingerprint: [u8; 32],
    /// Inclusive endpoint validity start.
    pub not_before: UnixMicros,
    /// Exclusive endpoint validity end.
    pub not_after: UnixMicros,
    /// Principal which authorised the issuance.
    pub created_by: PrincipalId,
    /// Authority-agreed issuance instant.
    pub created_at: UnixMicros,
    /// Immutable issuance revision.
    pub revision: Revision,
}

pub(super) fn create(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &CreateMeshLocalCertificateAuthority,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate(value, context)?;
    let exists = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM mesh_local_certificate_authorities WHERE singleton = 1)",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    if exists == 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    super::secret_generation::commit(transaction, context, &value.authority_key, revision)?;
    transaction.execute(
        "INSERT INTO mesh_local_certificate_authorities(
            singleton, authority_id, generation, certificate_der, certificate_digest,
            key_secret_kind, key_secret_id, key_secret_generation, created_by,
            not_before, not_after, created_at, revision
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            value.authority_id.as_bytes().as_slice(),
            to_i64(value.generation)?,
            &value.certificate_der,
            value.certificate_digest.as_slice(),
            i64::from(MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND),
            value.authority_id.as_bytes().as_slice(),
            to_i64(value.generation)?,
            context.actor_principal_id.as_bytes().as_slice(),
            value.not_before.get(),
            value.not_after.get(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::MeshLocalCertificateAuthority,
        id: value.authority_id.as_bytes(),
    })
}

pub(super) fn issue(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &IssueMeshLocalCertificate,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_issuance(transaction, context, value)?;
    super::secret_generation::commit(transaction, context, &value.certificate, revision)?;
    transaction.execute(
        "INSERT INTO mesh_local_certificate_issuances(
            issuance_id, authority_id, authority_generation, authority_certificate_digest,
            certificate_id, generation, certificate_secret_kind, certificate_secret_id,
            certificate_secret_generation, bundle_digest, public_key_fingerprint,
            not_before, not_after, created_by, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            value.issuance_id.as_bytes().as_slice(),
            value.authority_id.as_bytes().as_slice(),
            to_i64(value.authority_generation)?,
            value.authority_certificate_digest.as_slice(),
            value.certificate_id.as_bytes().as_slice(),
            to_i64(value.generation)?,
            i64::from(PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND),
            value.certificate_id.as_bytes().as_slice(),
            to_i64(value.generation)?,
            value.bundle_digest.as_slice(),
            value.public_key_fingerprint.as_slice(),
            value.not_before.get(),
            value.not_after.get(),
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    for (ordinal, name) in value.certificate_names.as_slice().iter().enumerate() {
        transaction.execute(
            "INSERT INTO mesh_local_certificate_issuance_names(issuance_id, ordinal, dns_name)
             VALUES (?1, ?2, ?3)",
            params![
                value.issuance_id.as_bytes().as_slice(),
                i64::try_from(ordinal).map_err(|_| RepositoryError::CapacityExceeded)?,
                name,
            ],
        )?;
    }
    Ok(issuance_entity(value.issuance_id))
}

pub(super) fn acknowledge_installation(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: AcknowledgeMeshLocalCertificateInstallation,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_worker(
        transaction,
        value.gateway_node_id,
        value.gateway_incarnation,
    )?;
    validate_installation(transaction, value)?;
    let inserted = transaction.execute(
        "INSERT INTO mesh_local_certificate_installations(
            issuance_id, gateway_node_id, gateway_incarnation, certificate_secret_kind,
            certificate_secret_id, certificate_secret_generation, bundle_digest,
            installed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(issuance_id, gateway_node_id) DO NOTHING",
        params![
            value.issuance_id.as_bytes().as_slice(),
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
    if inserted == 0 && !installation_matches(transaction, value)? {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(issuance_entity(value.issuance_id))
}

impl AuthoritativeRepository {
    /// Returns the current mesh-local HTTPS trust anchor and encrypted key reference.
    ///
    /// # Errors
    ///
    /// Fails closed when identity, digest, lifetime, revision or secret binding is malformed.
    pub fn mesh_local_certificate_authority(
        &self,
    ) -> Result<Option<MeshLocalCertificateAuthorityRecord>, RepositoryError> {
        self.database
            .connection()
            .query_row(
                "SELECT authority_id, generation, certificate_der, certificate_digest,
                        key_secret_id, key_secret_generation, created_by, not_before,
                        not_after, created_at, revision
                 FROM mesh_local_certificate_authorities WHERE singleton = 1",
                [],
                decode,
            )
            .optional()
            .map_err(RepositoryError::from)
    }

    /// Returns one immutable mesh-local endpoint issuance and all canonical names.
    ///
    /// # Errors
    ///
    /// Fails closed when stored identity, authority, secret, digest, lifetime or name state is
    /// malformed.
    pub fn mesh_local_certificate_issuance(
        &self,
        issuance_id: MeshLocalCertificateIssuanceId,
    ) -> Result<Option<MeshLocalCertificateIssuanceRecord>, RepositoryError> {
        let stored = self
            .database
            .connection()
            .query_row(
                "SELECT issuance_id, authority_id, authority_generation,
                        authority_certificate_digest, certificate_id, generation,
                        certificate_secret_id, certificate_secret_generation, bundle_digest,
                        public_key_fingerprint, not_before, not_after, created_by, created_at,
                        revision
                 FROM mesh_local_certificate_issuances WHERE issuance_id = ?1",
                [issuance_id.as_bytes().as_slice()],
                decode_issuance,
            )
            .optional()?;
        stored
            .map(|record| with_names(&self.database, record))
            .transpose()
    }
}

pub(super) fn latest_public_certificate(
    database: &crate::PartitionDatabase,
) -> Result<Option<PublicCertificateSelection>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT issuance_id, certificate_secret_id, certificate_secret_generation,
                    bundle_digest, created_by, created_at, revision
             FROM mesh_local_certificate_issuances
             ORDER BY created_at DESC, issuance_id DESC LIMIT 1",
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
    let issuance_id = MeshLocalCertificateIssuanceId::from_bytes(exact(stored.0)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let selection = PublicCertificateSelection {
        source: PublicCertificateSource::MeshLocalIssuance(issuance_id),
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
    if selection.bundle_digest == [0; 32]
        || selection.completed_at.get() < 0
        || selection.source_revision == Revision::ZERO
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(selection))
}

fn validate(
    value: &CreateMeshLocalCertificateAuthority,
    context: CommandContext,
) -> Result<(), RepositoryError> {
    let secret_context = value.authority_key.secret.context;
    let digest: [u8; 32] = Sha256::digest(&value.certificate_der).into();
    if value.generation != 1
        || value.certificate_der.is_empty()
        || value.certificate_der.len() > MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES
        || value.certificate_der.first() != Some(&0x30)
        || digest != value.certificate_digest
        || value.not_before.get() < 0
        || value.not_after <= context.occurred_at
        || value.not_after <= value.not_before
        || secret_context.kind() != MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND
        || secret_context.id() != value.authority_id.as_bytes()
        || secret_context.generation() != value.generation
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn validate_issuance(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &IssueMeshLocalCertificate,
) -> Result<(), RepositoryError> {
    let secret_context = value.certificate.secret.context;
    if value.authority_generation == 0
        || value.authority_certificate_digest == [0; 32]
        || value.generation == 0
        || value.certificate_names.is_empty()
        || value.certificate_names.len() > MAXIMUM_MESH_LOCAL_CERTIFICATE_NAMES
        || value.bundle_digest == [0; 32]
        || value.public_key_fingerprint == [0; 32]
        || value.not_before.get() < 0
        || value.not_after <= context.occurred_at
        || value.not_after <= value.not_before
        || secret_context.kind() != PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND
        || secret_context.id() != value.certificate_id.as_bytes()
        || secret_context.generation() != value.generation
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let authority_matches = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM mesh_local_certificate_authorities
            WHERE authority_id = ?1 AND generation = ?2 AND certificate_digest = ?3
              AND not_before <= ?4 AND not_after >= ?5
         )",
        params![
            value.authority_id.as_bytes().as_slice(),
            to_i64(value.authority_generation)?,
            value.authority_certificate_digest.as_slice(),
            value.not_before.get(),
            value.not_after.get(),
        ],
        |row| row.get::<_, i64>(0),
    )?;
    let latest: Option<i64> = transaction.query_row(
        "SELECT max(generation) FROM mesh_local_certificate_issuances",
        [],
        |row| row.get(0),
    )?;
    let generation = to_i64(value.generation)?;
    if authority_matches != 1 || latest.is_some_and(|latest| latest >= generation) {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn validate_installation(
    transaction: &Transaction<'_>,
    value: AcknowledgeMeshLocalCertificateInstallation,
) -> Result<(), RepositoryError> {
    if value.gateway_incarnation == 0
        || value.certificate.secret_id == [0; 16]
        || value.certificate.generation == 0
        || value.bundle_digest == [0; 32]
        || value.observed_issuance_revision == Revision::ZERO
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let matches = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM mesh_local_certificate_issuances i
            JOIN secret_recipient_envelopes e
              ON e.secret_kind = ?1 AND e.secret_id = i.certificate_secret_id
             AND e.secret_generation = i.certificate_secret_generation
            JOIN secret_wrapping_recipients r ON r.key_fingerprint = e.recipient_key_fingerprint
            WHERE i.issuance_id = ?2 AND i.certificate_secret_id = ?3
              AND i.certificate_secret_generation = ?4 AND i.bundle_digest = ?5
              AND i.revision = ?6 AND r.recipient_kind = 1 AND r.owner_id = ?7
         )",
        params![
            i64::from(PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND),
            value.issuance_id.as_bytes().as_slice(),
            value.certificate.secret_id.as_slice(),
            to_i64(value.certificate.generation)?,
            value.bundle_digest.as_slice(),
            to_i64(value.observed_issuance_revision.get())?,
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

fn installation_matches(
    transaction: &Transaction<'_>,
    value: AcknowledgeMeshLocalCertificateInstallation,
) -> Result<bool, RepositoryError> {
    let matches = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM mesh_local_certificate_installations
            WHERE issuance_id = ?1 AND gateway_node_id = ?2 AND gateway_incarnation = ?3
              AND certificate_secret_id = ?4 AND certificate_secret_generation = ?5
              AND bundle_digest = ?6
         )",
        params![
            value.issuance_id.as_bytes().as_slice(),
            value.gateway_node_id.as_bytes().as_slice(),
            to_i64(value.gateway_incarnation)?,
            value.certificate.secret_id.as_slice(),
            to_i64(value.certificate.generation)?,
            value.bundle_digest.as_slice(),
        ],
        |row| row.get::<_, i64>(0),
    )?;
    Ok(matches == 1)
}

fn decode(row: &Row<'_>) -> rusqlite::Result<MeshLocalCertificateAuthorityRecord> {
    decode_inner(row).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_inner(row: &Row<'_>) -> Result<MeshLocalCertificateAuthorityRecord, RepositoryError> {
    let authority_id = MeshLocalCertificateAuthorityId::from_bytes(exact(row.get(0)?)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let record = MeshLocalCertificateAuthorityRecord {
        authority_id,
        generation: positive(row.get(1)?)?,
        certificate_der: row.get(2)?,
        certificate_digest: exact(row.get(3)?)?,
        authority_key: SecretGenerationReference {
            secret_id: exact(row.get(4)?)?,
            generation: positive(row.get(5)?)?,
        },
        created_by: PrincipalId::from_bytes(exact(row.get(6)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        not_before: UnixMicros::new(row.get(7)?),
        not_after: UnixMicros::new(row.get(8)?),
        created_at: UnixMicros::new(row.get(9)?),
        revision: Revision::new(positive(row.get(10)?)?),
    };
    let digest: [u8; 32] = Sha256::digest(&record.certificate_der).into();
    if record.generation != 1
        || record.certificate_der.is_empty()
        || record.certificate_der.len() > MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES
        || digest != record.certificate_digest
        || record.authority_key.secret_id != authority_id.as_bytes()
        || record.authority_key.generation != record.generation
        || record.not_before.get() < 0
        || record.not_after <= record.not_before
        || record.revision == Revision::ZERO
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(record)
}

fn decode_issuance(row: &Row<'_>) -> rusqlite::Result<MeshLocalCertificateIssuanceRecord> {
    decode_issuance_inner(row).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_issuance_inner(
    row: &Row<'_>,
) -> Result<MeshLocalCertificateIssuanceRecord, RepositoryError> {
    let certificate_id = PublicCertificateId::from_bytes(exact(row.get(4)?)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let record = MeshLocalCertificateIssuanceRecord {
        issuance_id: MeshLocalCertificateIssuanceId::from_bytes(exact(row.get(0)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        authority_id: MeshLocalCertificateAuthorityId::from_bytes(exact(row.get(1)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        authority_generation: positive(row.get(2)?)?,
        authority_certificate_digest: exact(row.get(3)?)?,
        certificate_id,
        generation: positive(row.get(5)?)?,
        certificate_names: Vec::new(),
        certificate: SecretGenerationReference {
            secret_id: exact(row.get(6)?)?,
            generation: positive(row.get(7)?)?,
        },
        bundle_digest: exact(row.get(8)?)?,
        public_key_fingerprint: exact(row.get(9)?)?,
        not_before: UnixMicros::new(row.get(10)?),
        not_after: UnixMicros::new(row.get(11)?),
        created_by: PrincipalId::from_bytes(exact(row.get(12)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        created_at: UnixMicros::new(row.get(13)?),
        revision: Revision::new(positive(row.get(14)?)?),
    };
    if record.authority_generation == 0
        || record.authority_certificate_digest == [0; 32]
        || record.certificate.secret_id != certificate_id.as_bytes()
        || record.certificate.generation != record.generation
        || record.bundle_digest == [0; 32]
        || record.public_key_fingerprint == [0; 32]
        || record.not_before.get() < 0
        || record.not_after <= record.not_before
        || record.revision == Revision::ZERO
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(record)
}

fn with_names(
    database: &crate::PartitionDatabase,
    mut record: MeshLocalCertificateIssuanceRecord,
) -> Result<MeshLocalCertificateIssuanceRecord, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT dns_name FROM mesh_local_certificate_issuance_names
         WHERE issuance_id = ?1 ORDER BY ordinal LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            record.issuance_id.as_bytes().as_slice(),
            i64::try_from(MAXIMUM_MESH_LOCAL_CERTIFICATE_NAMES.saturating_add(1))
                .map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        |row| row.get::<_, String>(0),
    )?;
    record.certificate_names = rows.collect::<Result<Vec<_>, _>>()?;
    if record.certificate_names.is_empty()
        || record.certificate_names.len() > MAXIMUM_MESH_LOCAL_CERTIFICATE_NAMES
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(record)
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

const fn issuance_entity(issuance_id: MeshLocalCertificateIssuanceId) -> EntityReference {
    EntityReference {
        kind: EntityKind::MeshLocalCertificateIssuance,
        id: issuance_id.as_bytes(),
    }
}
