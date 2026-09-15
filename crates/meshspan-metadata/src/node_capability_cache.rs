// SPDX-License-Identifier: GPL-2.0-only

//! Bounded local capability preimages; committed node activation digests remain authoritative.

use meshspan_domain::NodeId;
use rusqlite::{OptionalExtension as _, params};

use crate::{LocalDatabase, MetadataStoreError};

const MAXIMUM_PRESENTATIONS: usize = 4096;
const MAXIMUM_NODE_PRESENTATIONS: i64 = 4;
const MAXIMUM_PRESENTATION_BYTES: usize = 64 * 1024 + 4;
const MAXIMUM_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// One locally retained preimage. The transport must revalidate canonical wire bytes and its digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedNodeCapabilityPresentation {
    /// Remote permanent node identity.
    pub node_id: NodeId,
    /// Exact remote process incarnation which presented these capabilities.
    pub incarnation: u64,
    /// Exact authenticated certificate associated with the presentation.
    pub certificate_fingerprint: [u8; 32],
    /// Capability digest to compare against current authoritative activation metadata.
    pub capability_digest: [u8; 32],
    /// Canonical strictly framed `NodeHello`, never executable code or authority by itself.
    pub canonical_hello: Vec<u8>,
}

impl LocalDatabase {
    /// Reads bounded capability preimages without granting authority to any cached claim.
    ///
    /// # Errors
    /// Rejects corrupt identities, allocation bounds or database failures. The transport must
    /// independently decode/hash each presentation before use.
    pub fn node_capability_presentations(
        &self,
    ) -> Result<Vec<CachedNodeCapabilityPresentation>, MetadataStoreError> {
        let (count, bytes): (i64, i64) = self.connection().query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(canonical_hello)), 0) FROM local_node_capability_presentations", [],
            |row| Ok((row.get(0)?, row.get(1)?)))?;
        let count = usize::try_from(count).map_err(|_| MetadataStoreError::IntegrityFailed)?;
        let bytes = usize::try_from(bytes).map_err(|_| MetadataStoreError::IntegrityFailed)?;
        if count > MAXIMUM_PRESENTATIONS || bytes > MAXIMUM_CACHE_BYTES {
            return Err(MetadataStoreError::IntegrityFailed);
        }
        let mut statement = self.connection().prepare(
            "SELECT node_id, incarnation, certificate_fingerprint, capability_digest, length(canonical_hello), canonical_hello
             FROM local_node_capability_presentations ORDER BY recorded_order LIMIT 4097")?;
        let mut rows = statement.query([])?;
        let mut presentations = Vec::with_capacity(count);
        while let Some(row) = rows.next()? {
            let length = usize::try_from(row.get::<_, i64>(4)?)
                .map_err(|_| MetadataStoreError::IntegrityFailed)?;
            if length == 0
                || length > MAXIMUM_PRESENTATION_BYTES
                || presentations.len() >= MAXIMUM_PRESENTATIONS
            {
                return Err(MetadataStoreError::IntegrityFailed);
            }
            let node: Vec<u8> = row.get(0)?;
            let fingerprint: Vec<u8> = row.get(2)?;
            let digest: Vec<u8> = row.get(3)?;
            let presentation = CachedNodeCapabilityPresentation {
                node_id: NodeId::from_bytes(
                    node.try_into()
                        .map_err(|_| MetadataStoreError::IntegrityFailed)?,
                )
                .map_err(|_| MetadataStoreError::IntegrityFailed)?,
                incarnation: u64::try_from(row.get::<_, i64>(1)?)
                    .map_err(|_| MetadataStoreError::IntegrityFailed)?,
                certificate_fingerprint: fingerprint
                    .try_into()
                    .map_err(|_| MetadataStoreError::IntegrityFailed)?,
                capability_digest: digest
                    .try_into()
                    .map_err(|_| MetadataStoreError::IntegrityFailed)?,
                canonical_hello: row.get(5)?,
            };
            validate(&presentation)?;
            presentations.push(presentation);
        }
        Ok(presentations)
    }

    /// Retains an exact local preimage without replacing a prior committed digest's evidence.
    /// Up to four presentations allow the committed value and bounded refreshes in flight.
    ///
    /// # Errors
    /// Rejects invalid/excessive input, stale incarnations and database failures. It cannot activate
    /// a node or change its committed capability digest.
    pub fn cache_node_capability_presentation(
        &mut self,
        value: &CachedNodeCapabilityPresentation,
    ) -> Result<(), MetadataStoreError> {
        validate(value)?;
        let transaction = self.connection_mut().transaction()?;
        let incarnation =
            i64::try_from(value.incarnation).map_err(|_| MetadataStoreError::IntegrityFailed)?;
        let previous: Option<i64> = transaction.query_row(
            "SELECT length(canonical_hello) FROM local_node_capability_presentations WHERE node_id = ?1 AND incarnation = ?2 AND capability_digest = ?3",
            params![value.node_id.as_bytes().as_slice(), incarnation, value.capability_digest.as_slice()], |row| row.get(0)).optional()?;
        let (node_count, highest_incarnation): (i64, i64) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(MAX(incarnation), 0) FROM local_node_capability_presentations WHERE node_id = ?1",
            [value.node_id.as_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?;
        if highest_incarnation > incarnation
            || (previous.is_none() && node_count >= MAXIMUM_NODE_PRESENTATIONS)
        {
            return Err(MetadataStoreError::IntegrityFailed);
        }
        let (count, bytes, order): (i64, i64, i64) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(canonical_hello)), 0), COALESCE(MAX(recorded_order), 0) FROM local_node_capability_presentations", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        let count = usize::try_from(count).map_err(|_| MetadataStoreError::IntegrityFailed)?;
        let bytes = usize::try_from(bytes).map_err(|_| MetadataStoreError::IntegrityFailed)?;
        let previous_length = usize::try_from(previous.unwrap_or(0))
            .map_err(|_| MetadataStoreError::IntegrityFailed)?;
        let order = order
            .checked_add(1)
            .ok_or(MetadataStoreError::IntegrityFailed)?;
        let total = bytes
            .checked_sub(previous_length)
            .and_then(|bytes| bytes.checked_add(value.canonical_hello.len()))
            .ok_or(MetadataStoreError::IntegrityFailed)?;
        if (previous.is_none() && count >= MAXIMUM_PRESENTATIONS) || total > MAXIMUM_CACHE_BYTES {
            return Err(MetadataStoreError::IntegrityFailed);
        }
        transaction.execute(
            "INSERT INTO local_node_capability_presentations(node_id, incarnation, certificate_fingerprint, capability_digest, canonical_hello, recorded_order)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(node_id, incarnation, capability_digest) DO UPDATE SET
             certificate_fingerprint = excluded.certificate_fingerprint, canonical_hello = excluded.canonical_hello,
             recorded_order = excluded.recorded_order",
            params![value.node_id.as_bytes().as_slice(), incarnation, value.certificate_fingerprint.as_slice(),
                value.capability_digest.as_slice(), &value.canonical_hello, order])?;
        transaction.commit()?;
        Ok(())
    }
    /// Drops obsolete local preimages after the current authoritative digest has been resolved.
    ///
    /// # Errors
    /// Rejects malformed bounds or storage failure. Callers retain the committed digest and any
    /// in-flight candidate, each selected by its explicit incarnation and digest. Capability
    /// digests deliberately omit node identity; no cache selector infers that binding.
    pub fn retain_node_capability_presentations(
        &mut self,
        node: NodeId,
        incarnation: u64,
        committed_digest: [u8; 32],
        candidate: (u64, [u8; 32]),
    ) -> Result<(), MetadataStoreError> {
        let incarnation =
            i64::try_from(incarnation).map_err(|_| MetadataStoreError::IntegrityFailed)?;
        let candidate_incarnation =
            i64::try_from(candidate.0).map_err(|_| MetadataStoreError::IntegrityFailed)?;
        if incarnation == 0
            || candidate_incarnation == 0
            || committed_digest == [0; 32]
            || candidate.1 == [0; 32]
        {
            return Err(MetadataStoreError::IntegrityFailed);
        }
        self.connection_mut().execute(
            "DELETE FROM local_node_capability_presentations WHERE node_id = ?1 AND
             ((incarnation != ?2 OR capability_digest != ?3) AND (incarnation != ?4 OR capability_digest != ?5))",
            params![
                node.as_bytes().as_slice(),
                incarnation,
                committed_digest.as_slice(),
                candidate_incarnation,
                candidate.1.as_slice()
            ],
        )?;
        Ok(())
    }
}

fn validate(value: &CachedNodeCapabilityPresentation) -> Result<(), MetadataStoreError> {
    if value.incarnation == 0
        || value.incarnation > i64::MAX as u64
        || value.certificate_fingerprint == [0; 32]
        || value.capability_digest == [0; 32]
        || value.canonical_hello.is_empty()
        || value.canonical_hello.len() > MAXIMUM_PRESENTATION_BYTES
    {
        return Err(MetadataStoreError::IntegrityFailed);
    }
    Ok(())
}
