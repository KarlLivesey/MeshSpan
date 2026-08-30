// SPDX-License-Identifier: GPL-2.0-only

//! Indexed reads which independently verify persisted remote authority observations.

use meshspan_domain::{FederationGrantId, FederationRelationshipId, MeshId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use super::{
    CachedFederationGrantAuthority, CachedFederationRemoteAuthority,
    FederationRemoteAuthorityCacheError, positive,
};
use crate::{FederationGrantRecord, FederationTransportAuthority, LocalDatabase};

struct StoredRelationshipRow {
    local_mesh_id: Vec<u8>,
    remote_mesh_id: Vec<u8>,
    authority_epoch: i64,
    authority_revision: i64,
    relationship_bytes: Vec<u8>,
    relationship_digest: Vec<u8>,
    observed_at: i64,
}

struct CachedRelationship {
    authority_revision: Revision,
    authority: FederationTransportAuthority,
    observed_at: UnixMicros,
}

pub(super) fn load(
    database: &LocalDatabase,
    relationship_id: FederationRelationshipId,
) -> Result<Option<CachedFederationRemoteAuthority>, FederationRemoteAuthorityCacheError> {
    let Some(cached) = load_relationship(database, relationship_id)? else {
        return Ok(None);
    };
    let grants = load_grants(database, &cached.authority, cached.authority_revision)?;
    Ok(Some(CachedFederationRemoteAuthority {
        authority_revision: cached.authority_revision,
        relationship: cached.authority,
        grants,
        observed_at: cached.observed_at,
    }))
}

pub(super) fn load_exact_grant(
    database: &LocalDatabase,
    relationship_id: FederationRelationshipId,
    grant_id: FederationGrantId,
) -> Result<Option<CachedFederationGrantAuthority>, FederationRemoteAuthorityCacheError> {
    let Some(cached) = load_relationship(database, relationship_id)? else {
        return Ok(None);
    };
    let Some(grant) = load_grant(
        database,
        &cached.authority,
        cached.authority_revision,
        grant_id,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(CachedFederationGrantAuthority {
        authority_revision: cached.authority_revision,
        relationship: cached.authority,
        grant,
        observed_at: cached.observed_at,
    }))
}

pub(super) fn load_revision(
    database: &LocalDatabase,
    relationship_id: FederationRelationshipId,
) -> Result<Revision, FederationRemoteAuthorityCacheError> {
    Ok(load_relationship(database, relationship_id)?
        .map_or(Revision::ZERO, |cached| cached.authority_revision))
}

fn load_relationship(
    database: &LocalDatabase,
    relationship_id: FederationRelationshipId,
) -> Result<Option<CachedRelationship>, FederationRemoteAuthorityCacheError> {
    database
        .connection()
        .query_row(
            "SELECT local_mesh_id, remote_mesh_id, authority_epoch,
                    remote_authority_revision, relationship_bytes,
                    relationship_digest, observed_at
             FROM local_federation_authority_snapshots WHERE relationship_id = ?1",
            [relationship_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredRelationshipRow {
                    local_mesh_id: row.get(0)?,
                    remote_mesh_id: row.get(1)?,
                    authority_epoch: row.get(2)?,
                    authority_revision: row.get(3)?,
                    relationship_bytes: row.get(4)?,
                    relationship_digest: row.get(5)?,
                    observed_at: row.get(6)?,
                })
            },
        )
        .optional()?
        .map(|row| decode_relationship(relationship_id, &row))
        .transpose()
}

fn decode_relationship(
    relationship_id: FederationRelationshipId,
    row: &StoredRelationshipRow,
) -> Result<CachedRelationship, FederationRemoteAuthorityCacheError> {
    let authority_revision = Revision::new(positive(row.authority_revision)?);
    if Sha256::digest(&row.relationship_bytes).as_slice() != row.relationship_digest {
        return Err(FederationRemoteAuthorityCacheError::Corrupt);
    }
    let authority = FederationTransportAuthority::from_canonical_bytes(&row.relationship_bytes)
        .map_err(|_| FederationRemoteAuthorityCacheError::Corrupt)?;
    validate_stored_relationship(relationship_id, authority_revision, &authority, row)?;
    Ok(CachedRelationship {
        authority_revision,
        authority,
        observed_at: UnixMicros::new(row.observed_at),
    })
}

fn validate_stored_relationship(
    relationship_id: FederationRelationshipId,
    authority_revision: Revision,
    authority: &FederationTransportAuthority,
    row: &StoredRelationshipRow,
) -> Result<(), FederationRemoteAuthorityCacheError> {
    let relationship = &authority.relationship;
    if authority.authority_revision != authority_revision
        || relationship.relationship_id != relationship_id
        || relationship.local_mesh_id.as_bytes().as_slice() != row.local_mesh_id
        || relationship.remote_mesh_id.as_bytes().as_slice() != row.remote_mesh_id
        || relationship.authority_epoch != positive(row.authority_epoch)?
    {
        Err(FederationRemoteAuthorityCacheError::Corrupt)
    } else {
        Ok(())
    }
}

fn load_grants(
    database: &LocalDatabase,
    authority: &FederationTransportAuthority,
    authority_revision: Revision,
) -> Result<Vec<FederationGrantRecord>, FederationRemoteAuthorityCacheError> {
    let relationship = &authority.relationship;
    let relationship_id = relationship.relationship_id;
    let parties = [relationship.local_mesh_id, relationship.remote_mesh_id];
    let mut statement = database.connection().prepare(
        "SELECT grant_id, record_revision, record_bytes, record_digest
         FROM local_federation_authority_grants WHERE relationship_id = ?1
         ORDER BY record_revision, grant_id",
    )?;
    let rows = statement.query_map([relationship_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    let mut grants = Vec::new();
    for row in rows {
        let row = row?;
        grants.push(decode_grant(
            &row,
            relationship_id,
            relationship.authority_epoch,
            parties,
            authority_revision,
        )?);
    }
    Ok(grants)
}

fn load_grant(
    database: &LocalDatabase,
    authority: &FederationTransportAuthority,
    authority_revision: Revision,
    grant_id: FederationGrantId,
) -> Result<Option<FederationGrantRecord>, FederationRemoteAuthorityCacheError> {
    let relationship = &authority.relationship;
    database
        .connection()
        .query_row(
            "SELECT grant_id, record_revision, record_bytes, record_digest
             FROM local_federation_authority_grants
             WHERE relationship_id = ?1 AND grant_id = ?2",
            params![
                relationship.relationship_id.as_bytes().as_slice(),
                grant_id.as_bytes().as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            decode_grant(
                &row,
                relationship.relationship_id,
                relationship.authority_epoch,
                [relationship.local_mesh_id, relationship.remote_mesh_id],
                authority_revision,
            )
        })
        .transpose()
}

fn decode_grant(
    row: &(Vec<u8>, i64, Vec<u8>, Vec<u8>),
    relationship_id: FederationRelationshipId,
    authority_epoch: u64,
    parties: [MeshId; 2],
    authority_revision: Revision,
) -> Result<FederationGrantRecord, FederationRemoteAuthorityCacheError> {
    if Sha256::digest(&row.2).as_slice() != row.3 {
        return Err(FederationRemoteAuthorityCacheError::Corrupt);
    }
    let record = FederationGrantRecord::from_canonical_bytes(&row.2)
        .map_err(|_| FederationRemoteAuthorityCacheError::Corrupt)?;
    let grant_id = parse_grant(&row.0)?;
    let revision = Revision::new(positive(row.1)?);
    if record.grant.grant_id() != grant_id
        || record.grant.relationship_id() != relationship_id
        || record.grant.authority_epoch() != authority_epoch
        || !parties.contains(&record.grant.issuer_mesh_id())
        || !parties.contains(&record.grant.recipient_mesh_id())
        || !parties.contains(&record.grant.resource().authority_mesh_id())
        || record.revision != revision
        || revision > authority_revision
    {
        return Err(FederationRemoteAuthorityCacheError::Corrupt);
    }
    Ok(record)
}

fn parse_grant(value: &[u8]) -> Result<FederationGrantId, FederationRemoteAuthorityCacheError> {
    FederationGrantId::from_bytes(
        value
            .try_into()
            .map_err(|_| FederationRemoteAuthorityCacheError::Corrupt)?,
    )
    .map_err(|_| FederationRemoteAuthorityCacheError::Corrupt)
}
