// SPDX-License-Identifier: GPL-2.0-only

//! Immutable encrypted mesh-local HTTPS signing authority.

use meshspan_domain::{MeshLocalCertificateAuthorityId, PrincipalId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Row, Transaction, params};
use sha2::{Digest as _, Sha256};

use super::apply::to_i64;
use super::{AuthoritativeRepository, EntityKind, EntityReference, RepositoryError};
use crate::{
    CommandContext, CreateMeshLocalCertificateAuthority, MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES,
    MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND, SecretGenerationReference,
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

fn positive(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(RepositoryError::CorruptState)
}

fn exact<const LENGTH: usize>(value: Vec<u8>) -> Result<[u8; LENGTH], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}
