// SPDX-License-Identifier: GPL-2.0-only

//! Atomic daemon-local cache for authenticated remote authority observations.

mod cache_read;

use meshspan_domain::{FederationGrantId, FederationRelationshipId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{FederationGrantRecord, FederationTransportAuthority, LocalDatabase};

/// One complete changed remote snapshot assembled from a stable authenticated page sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationRemoteAuthoritySnapshot {
    /// Exclusive remote revision floor used to fetch this update.
    pub after_revision: Revision,
    /// Peer committed revision shared by every page in the update.
    pub authority_revision: Revision,
    /// Current mirrored relationship and both active trust identities.
    pub relationship: FederationTransportAuthority,
    /// Stable ordered grant delta whose revisions are after `after_revision`.
    pub grants: Vec<FederationGrantRecord>,
}

/// Current restart-safe remote observation; never local permission authority by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedFederationRemoteAuthority {
    /// Latest fully installed peer authority revision.
    pub authority_revision: Revision,
    /// Current mirrored relationship and both active trust identities.
    pub relationship: FederationTransportAuthority,
    /// Latest observed record for every grant seen in the current authority epoch.
    pub grants: Vec<FederationGrantRecord>,
    /// Local authoritative mesh time at which the last update became durable.
    pub observed_at: UnixMicros,
}

/// One exact remote grant joined to the authenticated relationship observation which carries it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedFederationGrantAuthority {
    /// Latest fully installed peer authority revision.
    pub authority_revision: Revision,
    /// Current mirrored relationship and both active trust identities.
    pub relationship: FederationTransportAuthority,
    /// Exact current remote record for the requested grant.
    pub grant: FederationGrantRecord,
    /// Local authoritative mesh time at which the containing update became durable.
    pub observed_at: UnixMicros,
}

/// Idempotent result of one exact cache update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationRemoteAuthorityCacheDisposition {
    /// The complete delta became durable atomically.
    Applied,
    /// The exact same delta was already durable after a lost response.
    Replayed,
}

impl LocalDatabase {
    /// Atomically installs one fully authenticated remote relationship/grant delta.
    ///
    /// This cache is an observation only. Callers must still intersect it with current replicated
    /// local relationship and grant authority before any access or storage decision.
    ///
    /// # Errors
    ///
    /// Rejects stale/conflicting revisions, malformed records, changed replay input, corruption or
    /// a transaction failure. No partial relationship/grant update survives an error.
    pub fn install_remote_federation_authority(
        &mut self,
        snapshot: &FederationRemoteAuthoritySnapshot,
        observed_at: UnixMicros,
    ) -> Result<FederationRemoteAuthorityCacheDisposition, FederationRemoteAuthorityCacheError>
    {
        install(self, snapshot, observed_at, None)
    }

    /// Loads and independently verifies one complete cached remote observation.
    ///
    /// # Errors
    ///
    /// Rejects digest, identifier, revision, ordering or canonical-record corruption.
    pub fn remote_federation_authority(
        &self,
        relationship_id: FederationRelationshipId,
    ) -> Result<Option<CachedFederationRemoteAuthority>, FederationRemoteAuthorityCacheError> {
        cache_read::load(self, relationship_id)
    }

    /// Loads one exact grant through the indexed relationship/grant key and verifies its evidence.
    ///
    /// This read is suitable for an access path: it never scans or allocates the relationship's
    /// complete grant catalogue. The result remains an observation, not authority by itself.
    ///
    /// # Errors
    ///
    /// Rejects digest, identifier, revision or canonical-record corruption.
    pub fn remote_federation_grant_authority(
        &self,
        relationship_id: FederationRelationshipId,
        grant_id: FederationGrantId,
    ) -> Result<Option<CachedFederationGrantAuthority>, FederationRemoteAuthorityCacheError> {
        cache_read::load_exact_grant(self, relationship_id, grant_id)
    }

    /// Returns the latest independently verified remote authority revision, or zero if absent.
    ///
    /// # Errors
    ///
    /// Rejects persisted relationship bytes, digests, identifiers or revisions which disagree.
    pub fn remote_federation_authority_revision(
        &self,
        relationship_id: FederationRelationshipId,
    ) -> Result<Revision, FederationRemoteAuthorityCacheError> {
        cache_read::load_revision(self, relationship_id)
    }
}

struct EncodedSnapshot {
    relationship_bytes: Vec<u8>,
    relationship_digest: [u8; 32],
    grants: Vec<EncodedGrant>,
    update_digest: [u8; 32],
}

struct EncodedGrant {
    grant_id: FederationGrantId,
    revision: Revision,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

fn install(
    database: &mut LocalDatabase,
    snapshot: &FederationRemoteAuthoritySnapshot,
    observed_at: UnixMicros,
    fault: Option<CacheFault>,
) -> Result<FederationRemoteAuthorityCacheDisposition, FederationRemoteAuthorityCacheError> {
    let encoded = encode_and_validate(snapshot)?;
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if replay_or_validate_base(&transaction, snapshot, encoded.update_digest)? {
        return Ok(FederationRemoteAuthorityCacheDisposition::Replayed);
    }
    persist_relationship(&transaction, snapshot, &encoded, observed_at)?;
    inject(fault, CacheFault::AfterRelationship)?;
    persist_grants(&transaction, snapshot, &encoded.grants, observed_at)?;
    inject(fault, CacheFault::AfterGrants)?;
    transaction.commit()?;
    Ok(FederationRemoteAuthorityCacheDisposition::Applied)
}

fn encode_and_validate(
    snapshot: &FederationRemoteAuthoritySnapshot,
) -> Result<EncodedSnapshot, FederationRemoteAuthorityCacheError> {
    validate_snapshot(snapshot)?;
    let relationship_bytes = snapshot
        .relationship
        .canonical_bytes()
        .map_err(|_| FederationRemoteAuthorityCacheError::Invalid)?;
    let relationship_digest = Sha256::digest(&relationship_bytes).into();
    let mut grants = Vec::with_capacity(snapshot.grants.len());
    for record in &snapshot.grants {
        let bytes = record
            .canonical_bytes()
            .map_err(|_| FederationRemoteAuthorityCacheError::Invalid)?;
        grants.push(EncodedGrant {
            grant_id: record.grant.grant_id(),
            revision: record.revision,
            digest: Sha256::digest(&bytes).into(),
            bytes,
        });
    }
    let update_digest = update_digest(snapshot, &relationship_bytes, &grants)?;
    Ok(EncodedSnapshot {
        relationship_bytes,
        relationship_digest,
        grants,
        update_digest,
    })
}

fn validate_snapshot(
    snapshot: &FederationRemoteAuthoritySnapshot,
) -> Result<(), FederationRemoteAuthorityCacheError> {
    let relationship = &snapshot.relationship.relationship;
    if snapshot.after_revision >= snapshot.authority_revision
        || snapshot.relationship.authority_revision != snapshot.authority_revision
    {
        return Err(FederationRemoteAuthorityCacheError::Invalid);
    }
    let parties = [relationship.local_mesh_id, relationship.remote_mesh_id];
    let mut previous = None;
    for record in &snapshot.grants {
        let key = (record.revision, record.grant.grant_id());
        let valid = record.grant.relationship_id() == relationship.relationship_id
            && record.grant.authority_epoch() == relationship.authority_epoch
            && parties.contains(&record.grant.subject().home_mesh_id())
            && parties.contains(&record.grant.resource().authority_mesh_id())
            && record.revision > snapshot.after_revision
            && record.revision <= snapshot.authority_revision
            && previous.is_none_or(|value| value < key);
        if !valid {
            return Err(FederationRemoteAuthorityCacheError::Invalid);
        }
        previous = Some(key);
    }
    Ok(())
}

fn update_digest(
    snapshot: &FederationRemoteAuthoritySnapshot,
    relationship_bytes: &[u8],
    grants: &[EncodedGrant],
) -> Result<[u8; 32], FederationRemoteAuthorityCacheError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.federation.remote-authority-update.v1");
    digest.update(snapshot.after_revision.get().to_be_bytes());
    digest.update(snapshot.authority_revision.get().to_be_bytes());
    digest.update(length(relationship_bytes.len())?);
    digest.update(relationship_bytes);
    digest.update(length(grants.len())?);
    for grant in grants {
        digest.update(length(grant.bytes.len())?);
        digest.update(&grant.bytes);
    }
    Ok(digest.finalize().into())
}

fn replay_or_validate_base(
    transaction: &Transaction<'_>,
    snapshot: &FederationRemoteAuthoritySnapshot,
    update_digest: [u8; 32],
) -> Result<bool, FederationRemoteAuthorityCacheError> {
    let relationship_id = snapshot.relationship.relationship.relationship_id;
    let current = transaction
        .query_row(
            "SELECT remote_authority_revision, last_update_digest, local_mesh_id, remote_mesh_id
             FROM local_federation_authority_snapshots WHERE relationship_id = ?1",
            [relationship_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((current_revision, current_digest, local_mesh_id, remote_mesh_id)) = current else {
        return if snapshot.after_revision == Revision::ZERO {
            Ok(false)
        } else {
            Err(FederationRemoteAuthorityCacheError::StaleRevision)
        };
    };
    if current_digest.len() != 32 || local_mesh_id.len() != 16 || remote_mesh_id.len() != 16 {
        return Err(FederationRemoteAuthorityCacheError::Corrupt);
    }
    let relationship = &snapshot.relationship.relationship;
    if local_mesh_id != relationship.local_mesh_id.as_bytes()
        || remote_mesh_id != relationship.remote_mesh_id.as_bytes()
    {
        return Err(FederationRemoteAuthorityCacheError::Conflict);
    }
    let current_revision = Revision::new(positive(current_revision)?);
    if current_revision == snapshot.authority_revision {
        return if current_digest.as_slice() == update_digest {
            Ok(true)
        } else {
            Err(FederationRemoteAuthorityCacheError::Conflict)
        };
    }
    if current_revision == snapshot.after_revision {
        Ok(false)
    } else {
        Err(FederationRemoteAuthorityCacheError::StaleRevision)
    }
}

fn persist_relationship(
    transaction: &Transaction<'_>,
    snapshot: &FederationRemoteAuthoritySnapshot,
    encoded: &EncodedSnapshot,
    observed_at: UnixMicros,
) -> Result<(), FederationRemoteAuthorityCacheError> {
    let relationship = &snapshot.relationship.relationship;
    transaction.execute(
        "DELETE FROM local_federation_authority_grants
         WHERE relationship_id = ?1
           AND EXISTS (
               SELECT 1 FROM local_federation_authority_snapshots
               WHERE relationship_id = ?1 AND authority_epoch <> ?2
           )",
        params![
            relationship.relationship_id.as_bytes().as_slice(),
            to_i64(relationship.authority_epoch)?,
        ],
    )?;
    transaction.execute(
        "INSERT INTO local_federation_authority_snapshots(
            relationship_id, local_mesh_id, remote_mesh_id, authority_epoch,
            remote_authority_revision, relationship_bytes, relationship_digest,
            last_update_digest, observed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(relationship_id) DO UPDATE SET
            local_mesh_id = excluded.local_mesh_id,
            remote_mesh_id = excluded.remote_mesh_id,
            authority_epoch = excluded.authority_epoch,
            remote_authority_revision = excluded.remote_authority_revision,
            relationship_bytes = excluded.relationship_bytes,
            relationship_digest = excluded.relationship_digest,
            last_update_digest = excluded.last_update_digest,
            observed_at = excluded.observed_at",
        params![
            relationship.relationship_id.as_bytes().as_slice(),
            relationship.local_mesh_id.as_bytes().as_slice(),
            relationship.remote_mesh_id.as_bytes().as_slice(),
            to_i64(relationship.authority_epoch)?,
            to_i64(snapshot.authority_revision.get())?,
            &encoded.relationship_bytes,
            encoded.relationship_digest.as_slice(),
            encoded.update_digest.as_slice(),
            observed_at.get(),
        ],
    )?;
    Ok(())
}

fn persist_grants(
    transaction: &Transaction<'_>,
    snapshot: &FederationRemoteAuthoritySnapshot,
    grants: &[EncodedGrant],
    observed_at: UnixMicros,
) -> Result<(), FederationRemoteAuthorityCacheError> {
    let relationship_id = snapshot.relationship.relationship.relationship_id;
    for grant in grants {
        transaction.execute(
            "INSERT INTO local_federation_authority_grants(
                relationship_id, grant_id, record_revision, record_bytes,
                record_digest, observed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(relationship_id, grant_id) DO UPDATE SET
                record_revision = excluded.record_revision,
                record_bytes = excluded.record_bytes,
                record_digest = excluded.record_digest,
                observed_at = excluded.observed_at",
            params![
                relationship_id.as_bytes().as_slice(),
                grant.grant_id.as_bytes().as_slice(),
                to_i64(grant.revision.get())?,
                &grant.bytes,
                grant.digest.as_slice(),
                observed_at.get(),
            ],
        )?;
    }
    Ok(())
}

fn length(value: usize) -> Result<[u8; 8], FederationRemoteAuthorityCacheError> {
    Ok(u64::try_from(value)
        .map_err(|_| FederationRemoteAuthorityCacheError::Invalid)?
        .to_be_bytes())
}

fn positive(value: i64) -> Result<u64, FederationRemoteAuthorityCacheError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(FederationRemoteAuthorityCacheError::Corrupt)
}

fn to_i64(value: u64) -> Result<i64, FederationRemoteAuthorityCacheError> {
    i64::try_from(value).map_err(|_| FederationRemoteAuthorityCacheError::Invalid)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CacheFault {
    AfterRelationship,
    AfterGrants,
}

fn inject(
    selected: Option<CacheFault>,
    current: CacheFault,
) -> Result<(), FederationRemoteAuthorityCacheError> {
    if selected == Some(current) {
        Err(FederationRemoteAuthorityCacheError::InjectedFault)
    } else {
        Ok(())
    }
}

/// Closed cache failures; no variant turns remote observation into authority.
#[derive(Debug, Error)]
pub enum FederationRemoteAuthorityCacheError {
    /// SQLite rejected the local cache operation.
    #[error("remote federation authority cache storage failed")]
    Sqlite(#[from] rusqlite::Error),
    /// The update is structurally or semantically invalid.
    #[error("remote federation authority cache update is invalid")]
    Invalid,
    /// The update does not immediately follow the cached remote revision.
    #[error("remote federation authority cache revision is stale")]
    StaleRevision,
    /// The same resulting revision is bound to different update input.
    #[error("remote federation authority cache update conflicts")]
    Conflict,
    /// Persisted cache bytes contradict their digests, keys or revisions.
    #[error("remote federation authority cache is corrupt")]
    Corrupt,
    /// Deterministic interruption used by the crash-safety proof.
    #[error("injected remote federation authority cache interruption")]
    InjectedFault,
}

#[cfg(test)]
#[path = "federation_remote_authority_tests.rs"]
mod tests;
