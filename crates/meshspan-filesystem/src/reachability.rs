// SPDX-License-Identifier: GPL-2.0-only

//! Durable bounded graph proof before an historical version can enter cleanup.

use meshspan_domain::{
    ContentManifestId, FileVersionId, NamespaceCommitId, ObjectRevisionId, OperationId, Revision,
    SnapshotId, UnixMicros, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;

use crate::directory::DirectoryReachabilityReference;
use crate::version_retention::{revalidate_candidate, selection_authority_digest};
use crate::{
    DirectoryNodeDigest, DirectoryNodeRecord, VersionRetentionCandidate, VersionRetentionPressure,
    VersionRetentionSelectionPolicy,
};

const MAXIMUM_ROOT_PAGE_ITEMS: usize = 1_000;
const MAXIMUM_WORK_ITEMS: usize = 1_000;
const STATE_COLLECTING: i64 = 1;
const STATE_SCANNING: i64 = 2;
const STATE_REACHABLE: i64 = 3;
const STATE_UNREACHABLE: i64 = 4;

/// Authoritative reason one immutable namespace root remains retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReachabilityRootSource {
    /// Latest globally converged root for the volume.
    ConvergedHead(VolumeId),
    /// Active or expiring user snapshot root.
    Snapshot(SnapshotId),
}

/// One exact metadata-authoritative root record supplied in stable order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReachabilityRoot {
    /// Record retaining the root.
    pub source: ReachabilityRootSource,
    /// Immutable namespace commit selected by that record.
    pub namespace_commit_id: NamespaceCommitId,
    /// Immutable root object revision selected by the commit.
    pub root_object_revision_id: ObjectRevisionId,
}

/// Complete identity and retention authority for a new durable scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionReachabilityScanRequest {
    /// Stable idempotency identity for the complete scan.
    pub operation_id: OperationId,
    /// Preliminary candidate revalidated before work is admitted.
    pub candidate: VersionRetentionCandidate,
    /// Exact selected retention policy.
    pub policy: VersionRetentionSelectionPolicy,
    /// Capacity pressure used by the selection decision.
    pub pressure: VersionRetentionPressure,
    /// Authoritative selection instant.
    pub selected_at: UnixMicros,
    /// Exact replicated metadata revision shared by every supplied root page.
    pub metadata_revision: Revision,
    /// Complete number of metadata-authoritative roots.
    pub root_count: u64,
    /// Canonical digest of all roots in stable order.
    pub root_digest: [u8; 32],
}

/// One bounded append to the durable authoritative root manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReachabilityRootPage {
    /// Scan receiving these roots.
    pub operation_id: OperationId,
    /// Zero-based ordinal of the first root.
    pub start_ordinal: u64,
    /// Non-empty bounded consecutive roots.
    pub roots: Vec<ReachabilityRoot>,
}

/// Durable scan phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionReachabilityState {
    /// Root pages are still being assembled.
    CollectingRoots,
    /// Immutable graph work remains.
    Scanning,
    /// At least one retained root or live handle reaches the version.
    Reachable,
    /// Every admitted root was exhausted without reaching the version.
    Unreachable,
}

/// Exact proof emitted only after a complete unchanged-root scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionUnreachableProof {
    /// Durable scan identity.
    pub operation_id: OperationId,
    /// Volume whose roots were exhausted.
    pub volume_id: VolumeId,
    /// Historical version proved unreachable.
    pub version_id: FileVersionId,
    /// Content manifest selected by that version.
    pub manifest_id: ContentManifestId,
    /// Immutable manifest root used by physical shard identities.
    pub manifest_root_digest: [u8; 32],
    /// Digest binding the candidate, retention selection and retained-root authority.
    pub scan_request_digest: [u8; 32],
    /// Operation-independent digest shared by honest scans of this exact cleanup subject.
    pub subject_digest: [u8; 32],
    /// Exact retention-policy sequence used to select the version.
    pub retention_policy_sequence: u64,
    /// Replicated metadata revision governing authoritative roots.
    pub metadata_revision: Revision,
    /// Complete number of metadata-authoritative retained roots.
    pub root_count: u64,
    /// Digest of the complete metadata root manifest.
    pub root_digest: [u8; 32],
    /// Digest of local branch and lifecycle roots revalidated at completion.
    pub local_roots_digest: [u8; 32],
    /// Digest binding the final proof result.
    pub result_digest: [u8; 32],
}

/// Current durable scan progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionReachabilityProgress {
    /// Current phase.
    pub state: VersionReachabilityState,
    /// Number of authoritative root records durably received.
    pub roots_received: u64,
    /// Number of graph records already verified.
    pub work_processed: u64,
    /// Number of queued graph records remaining.
    pub work_pending: u64,
    /// Final proof, present only for the unreachable state.
    pub proof: Option<VersionUnreachableProof>,
}

/// Stable reachability-scan failures.
#[derive(Debug, Error)]
pub enum VersionReachabilityError {
    /// Request bounds, ordering or relationships are invalid.
    #[error("version reachability input is invalid")]
    InvalidInput,
    /// Idempotency identity is bound to different input.
    #[error("version reachability identity conflicts with durable state")]
    Conflict,
    /// Candidate or root authority changed during the scan.
    #[error("version reachability authority is stale")]
    Stale,
    /// Persisted graph, roots or proof evidence is corrupt.
    #[error("version reachability evidence is corrupt")]
    Corrupt,
    /// SQLite persistence failed.
    #[error("version reachability database operation failed")]
    Sqlite(#[from] rusqlite::Error),
}

/// Calculates the canonical complete metadata-root manifest digest.
///
/// # Errors
///
/// Rejects an empty, misordered or wrong-volume root set.
pub fn reachability_root_digest(
    volume_id: VolumeId,
    metadata_revision: Revision,
    roots: &[ReachabilityRoot],
) -> Result<[u8; 32], VersionReachabilityError> {
    if metadata_revision == Revision::ZERO || roots.is_empty() {
        return Err(VersionReachabilityError::InvalidInput);
    }
    validate_root_order(volume_id, roots, 0, None)?;
    let mut digest = root_digest_hasher(volume_id, metadata_revision);
    for root in roots {
        digest.update(&root_record_digest(*root));
    }
    Ok(digest.finalize().into())
}

pub(crate) fn begin(
    connection: &mut Connection,
    request: &VersionReachabilityScanRequest,
) -> Result<VersionReachabilityProgress, VersionReachabilityError> {
    validate_scan_request(request)?;
    let subject_digest = reachability_subject_digest(request);
    let digest = scan_request_digest(request.operation_id, subject_digest);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(stored) = load_scan_request(&transaction, request.operation_id)? {
        if stored == digest {
            let progress = progress(&transaction, request.operation_id)?;
            transaction.commit()?;
            return Ok(progress);
        }
        return Err(VersionReachabilityError::Conflict);
    }
    revalidate_candidate(
        &transaction,
        request.candidate,
        request.policy,
        request.pressure,
        request.selected_at,
    )
    .map_err(|_| VersionReachabilityError::Stale)?;
    reject_operation_collision(&transaction, request.operation_id)?;
    transaction.execute(
        "INSERT INTO version_reachability_scans(
            operation_id, request_digest, volume_id, version_id, manifest_id,
            manifest_root_digest,
            metadata_revision, expected_root_count, expected_root_digest,
            retention_policy_sequence, subject_digest,
            roots_received, local_roots_digest, state, started_at, completed_at, result_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, NULL, 1, ?12, NULL, NULL)",
        params![
            request.operation_id.as_bytes().as_slice(),
            digest.as_slice(),
            request.candidate.volume_id.as_bytes().as_slice(),
            request.candidate.version_id.as_bytes().as_slice(),
            request.candidate.manifest_id.as_bytes().as_slice(),
            request.candidate.manifest_root_digest.as_slice(),
            to_i64(request.metadata_revision.get())?,
            to_i64(request.root_count)?,
            request.root_digest.as_slice(),
            to_i64(request.candidate.policy_sequence)?,
            subject_digest.as_slice(),
            request.selected_at.get(),
        ],
    )?;
    let progress = progress(&transaction, request.operation_id)?;
    transaction.commit()?;
    Ok(progress)
}

pub(crate) fn append_roots(
    connection: &mut Connection,
    page: &ReachabilityRootPage,
) -> Result<VersionReachabilityProgress, VersionReachabilityError> {
    if page.roots.is_empty() || page.roots.len() > MAXIMUM_ROOT_PAGE_ITEMS {
        return Err(VersionReachabilityError::InvalidInput);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let scan = load_scan(&transaction, page.operation_id)?;
    if scan.state != STATE_COLLECTING {
        return Err(VersionReachabilityError::Conflict);
    }
    let end = page
        .start_ordinal
        .checked_add(
            u64::try_from(page.roots.len()).map_err(|_| VersionReachabilityError::InvalidInput)?,
        )
        .ok_or(VersionReachabilityError::InvalidInput)?;
    if end > scan.root_count || page.start_ordinal > scan.roots_received {
        return Err(VersionReachabilityError::InvalidInput);
    }
    let previous = previous_root(&transaction, page.operation_id, page.start_ordinal)?;
    validate_root_order(scan.volume_id, &page.roots, page.start_ordinal, previous)?;
    if page.start_ordinal < scan.roots_received {
        verify_root_replay(&transaction, page)?;
    } else {
        insert_roots(&transaction, &scan, page)?;
        transaction.execute(
            "UPDATE version_reachability_scans SET roots_received = ?1
             WHERE operation_id = ?2 AND roots_received = ?3",
            params![
                to_i64(end)?,
                page.operation_id.as_bytes().as_slice(),
                to_i64(page.start_ordinal)?,
            ],
        )?;
    }
    let result = progress(&transaction, page.operation_id)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn seal(
    connection: &mut Connection,
    operation_id: OperationId,
    observed_at: UnixMicros,
) -> Result<VersionReachabilityProgress, VersionReachabilityError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let scan = load_scan(&transaction, operation_id)?;
    if scan.state != STATE_COLLECTING {
        let result = progress(&transaction, operation_id)?;
        transaction.commit()?;
        return Ok(result);
    }
    if scan.roots_received != scan.root_count
        || stored_root_digest(&transaction, &scan)? != scan.root_digest
    {
        return Err(VersionReachabilityError::InvalidInput);
    }
    enqueue_authoritative_roots(&transaction, operation_id)?;
    let local_digest = enqueue_local_roots(&transaction, &scan)?;
    let directly_pinned = candidate_is_directly_pinned(&transaction, &scan)?;
    if directly_pinned {
        complete_scan(
            &transaction,
            &scan,
            local_digest,
            STATE_REACHABLE,
            observed_at,
        )?;
    } else {
        transaction.execute(
            "UPDATE version_reachability_scans
             SET local_roots_digest = ?1, state = 2
             WHERE operation_id = ?2 AND state = 1",
            params![local_digest.as_slice(), operation_id.as_bytes().as_slice()],
        )?;
    }
    let result = progress(&transaction, operation_id)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn advance(
    connection: &mut Connection,
    operation_id: OperationId,
    maximum_work: usize,
    observed_at: UnixMicros,
) -> Result<VersionReachabilityProgress, VersionReachabilityError> {
    if maximum_work == 0 || maximum_work > MAXIMUM_WORK_ITEMS {
        return Err(VersionReachabilityError::InvalidInput);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let scan = load_scan(&transaction, operation_id)?;
    if scan.state != STATE_SCANNING {
        let result = progress(&transaction, operation_id)?;
        transaction.commit()?;
        return Ok(result);
    }
    let local_digest = current_local_roots_digest(&transaction, scan.volume_id)?;
    if Some(local_digest) != scan.local_roots_digest {
        return Err(VersionReachabilityError::Stale);
    }
    let is_reachable = candidate_is_directly_pinned(&transaction, &scan)?
        || process_work(&transaction, &scan, maximum_work)?;
    if is_reachable {
        complete_scan(
            &transaction,
            &scan,
            local_digest,
            STATE_REACHABLE,
            observed_at,
        )?;
    } else if pending_work(&transaction, operation_id)? == 0 {
        complete_scan(
            &transaction,
            &scan,
            local_digest,
            STATE_UNREACHABLE,
            observed_at,
        )?;
    }
    let result = progress(&transaction, operation_id)?;
    transaction.commit()?;
    Ok(result)
}

#[derive(Clone)]
struct StoredScan {
    operation_id: OperationId,
    request_digest: [u8; 32],
    subject_digest: [u8; 32],
    volume_id: VolumeId,
    version_id: FileVersionId,
    manifest_id: ContentManifestId,
    manifest_root_digest: [u8; 32],
    metadata_revision: Revision,
    retention_policy_sequence: u64,
    root_count: u64,
    root_digest: [u8; 32],
    roots_received: u64,
    local_roots_digest: Option<[u8; 32]>,
    state: i64,
    result_digest: Option<[u8; 32]>,
}

fn load_scan(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<StoredScan, VersionReachabilityError> {
    let stored = connection
        .query_row(
            "SELECT request_digest, volume_id, version_id, manifest_id, metadata_revision,
                    expected_root_count, expected_root_digest, roots_received,
                    local_roots_digest, state, result_digest, retention_policy_sequence,
                    subject_digest, manifest_root_digest
             FROM version_reachability_scans WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                    row.get::<_, Option<Vec<u8>>>(12)?,
                    row.get::<_, Option<Vec<u8>>>(13)?,
                ))
            },
        )
        .optional()?
        .ok_or(VersionReachabilityError::InvalidInput)?;
    if !matches!(
        stored.9,
        STATE_COLLECTING | STATE_SCANNING | STATE_REACHABLE | STATE_UNREACHABLE
    ) {
        return Err(VersionReachabilityError::Corrupt);
    }
    Ok(StoredScan {
        operation_id,
        request_digest: array(&stored.0)?,
        subject_digest: stored
            .12
            .as_deref()
            .map(array)
            .transpose()?
            .ok_or(VersionReachabilityError::Corrupt)?,
        volume_id: identifier(&stored.1, VolumeId::from_bytes)?,
        version_id: identifier(&stored.2, FileVersionId::from_bytes)?,
        manifest_id: identifier(&stored.3, ContentManifestId::from_bytes)?,
        manifest_root_digest: stored
            .13
            .as_deref()
            .map(array)
            .transpose()?
            .ok_or(VersionReachabilityError::Corrupt)?,
        metadata_revision: revision(stored.4)?,
        retention_policy_sequence: stored
            .11
            .map(from_i64)
            .transpose()?
            .filter(|value| *value > 0)
            .ok_or(VersionReachabilityError::Corrupt)?,
        root_count: from_i64(stored.5)?,
        root_digest: array(&stored.6)?,
        roots_received: from_i64(stored.7)?,
        local_roots_digest: stored.8.as_deref().map(array).transpose()?,
        state: stored.9,
        result_digest: stored.10.as_deref().map(array).transpose()?,
    })
}

fn load_scan_request(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<[u8; 32]>, VersionReachabilityError> {
    connection
        .query_row(
            "SELECT request_digest FROM version_reachability_scans WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .as_deref()
        .map(array)
        .transpose()
}

fn validate_scan_request(
    request: &VersionReachabilityScanRequest,
) -> Result<(), VersionReachabilityError> {
    if request.metadata_revision == Revision::ZERO
        || request.root_count == 0
        || i64::try_from(request.root_count).is_err()
        || request.root_digest == [0; 32]
    {
        Err(VersionReachabilityError::InvalidInput)
    } else {
        Ok(())
    }
}

/// Calculates the operation-independent identity shared by scans of one exact cleanup subject.
#[must_use]
pub fn reachability_subject_digest(request: &VersionReachabilityScanRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.version-reachability-subject.v1\0");
    digest.update(&request.candidate.version_id.as_bytes());
    digest.update(&request.candidate.superseded_by_version_id.as_bytes());
    digest.update(&request.candidate.branch_id.as_bytes());
    digest.update(&request.candidate.volume_id.as_bytes());
    digest.update(&request.candidate.object_id.as_bytes());
    digest.update(&request.candidate.manifest_id.as_bytes());
    digest.update(&request.candidate.manifest_root_digest);
    digest.update(&request.candidate.logical_length.to_be_bytes());
    digest.update(&request.candidate.superseded_at.get().to_be_bytes());
    digest.update(&request.candidate.policy_sequence.to_be_bytes());
    digest.update(&request.candidate.supersession_policy_sequence.to_be_bytes());
    digest.update(&[candidate_reason_code(request.candidate.reason)]);
    digest.update(&selection_authority_digest(
        request.policy,
        request.pressure,
        request.selected_at,
    ));
    digest.update(&request.metadata_revision.get().to_be_bytes());
    digest.update(&request.root_count.to_be_bytes());
    digest.update(&request.root_digest);
    digest.finalize().into()
}

fn scan_request_digest(operation_id: OperationId, subject_digest: [u8; 32]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.version-reachability-request.v2\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&subject_digest);
    digest.finalize().into()
}

const fn candidate_reason_code(reason: crate::VersionRetentionCandidateReason) -> u8 {
    match reason {
        crate::VersionRetentionCandidateReason::HistoryDisabled => 1,
        crate::VersionRetentionCandidateReason::MaximumAge => 2,
        crate::VersionRetentionCandidateReason::Pressure => 3,
        crate::VersionRetentionCandidateReason::CriticalPressure => 4,
        crate::VersionRetentionCandidateReason::ConflictSafetyElapsed => 5,
        crate::VersionRetentionCandidateReason::MinimumAge => 6,
    }
}

fn validate_root_order(
    volume_id: VolumeId,
    roots: &[ReachabilityRoot],
    start: u64,
    previous: Option<ReachabilityRoot>,
) -> Result<(), VersionReachabilityError> {
    let mut prior = previous.map(root_sort_key);
    for (offset, root) in roots.iter().enumerate() {
        let ordinal = start
            .checked_add(u64::try_from(offset).map_err(|_| VersionReachabilityError::InvalidInput)?)
            .ok_or(VersionReachabilityError::InvalidInput)?;
        if (ordinal == 0 && root.source != ReachabilityRootSource::ConvergedHead(volume_id))
            || (ordinal != 0 && matches!(root.source, ReachabilityRootSource::ConvergedHead(_)))
        {
            return Err(VersionReachabilityError::InvalidInput);
        }
        let key = root_sort_key(*root);
        if prior.is_some_and(|prior| prior >= key) {
            return Err(VersionReachabilityError::InvalidInput);
        }
        prior = Some(key);
    }
    Ok(())
}

fn root_sort_key(root: ReachabilityRoot) -> (u8, [u8; 16]) {
    match root.source {
        ReachabilityRootSource::ConvergedHead(volume) => (1, volume.as_bytes()),
        ReachabilityRootSource::Snapshot(snapshot) => (2, snapshot.as_bytes()),
    }
}

fn root_digest_hasher(volume_id: VolumeId, revision: Revision) -> blake3::Hasher {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.retained-namespace-roots.v1\0");
    digest.update(&volume_id.as_bytes());
    digest.update(&revision.get().to_be_bytes());
    digest
}

fn root_record_digest(root: ReachabilityRoot) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.retained-namespace-root.v1\0");
    let (kind, id) = root_sort_key(root);
    digest.update(&[kind]);
    digest.update(&id);
    digest.update(&root.namespace_commit_id.as_bytes());
    digest.update(&root.root_object_revision_id.as_bytes());
    digest.finalize().into()
}

fn previous_root(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
    start: u64,
) -> Result<Option<ReachabilityRoot>, VersionReachabilityError> {
    let Some(ordinal) = start.checked_sub(1) else {
        return Ok(None);
    };
    load_root(transaction, operation_id, ordinal)
}

fn load_root(
    connection: &Connection,
    operation_id: OperationId,
    ordinal: u64,
) -> Result<Option<ReachabilityRoot>, VersionReachabilityError> {
    connection
        .query_row(
            "SELECT source_kind, source_id, namespace_commit_id, root_object_revision_id
             FROM version_reachability_roots WHERE operation_id = ?1 AND root_ordinal = ?2",
            params![operation_id.as_bytes().as_slice(), to_i64(ordinal)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?
        .map(|stored| decode_root(&stored))
        .transpose()
}

fn decode_root(
    stored: &(i64, Vec<u8>, Vec<u8>, Vec<u8>),
) -> Result<ReachabilityRoot, VersionReachabilityError> {
    let source_id = array(&stored.1)?;
    let source = match stored.0 {
        1 => ReachabilityRootSource::ConvergedHead(
            VolumeId::from_bytes(source_id).map_err(|_| VersionReachabilityError::Corrupt)?,
        ),
        2 => ReachabilityRootSource::Snapshot(
            SnapshotId::from_bytes(source_id).map_err(|_| VersionReachabilityError::Corrupt)?,
        ),
        _ => return Err(VersionReachabilityError::Corrupt),
    };
    Ok(ReachabilityRoot {
        source,
        namespace_commit_id: identifier(&stored.2, NamespaceCommitId::from_bytes)?,
        root_object_revision_id: identifier(&stored.3, ObjectRevisionId::from_bytes)?,
    })
}

fn verify_root_replay(
    transaction: &Transaction<'_>,
    page: &ReachabilityRootPage,
) -> Result<(), VersionReachabilityError> {
    for (offset, expected) in page.roots.iter().enumerate() {
        let ordinal = page.start_ordinal
            + u64::try_from(offset).map_err(|_| VersionReachabilityError::InvalidInput)?;
        if load_root(transaction, page.operation_id, ordinal)? != Some(*expected) {
            return Err(VersionReachabilityError::Conflict);
        }
    }
    Ok(())
}

fn insert_roots(
    transaction: &Transaction<'_>,
    scan: &StoredScan,
    page: &ReachabilityRootPage,
) -> Result<(), VersionReachabilityError> {
    for (offset, root) in page.roots.iter().enumerate() {
        let ordinal = page.start_ordinal
            + u64::try_from(offset).map_err(|_| VersionReachabilityError::InvalidInput)?;
        let (kind, source_id) = root_sort_key(*root);
        let local: Option<(Vec<u8>, Vec<u8>)> = transaction.query_row(
            "SELECT volume_id, root_object_revision_id FROM namespace_commits WHERE namespace_commit_id = ?1",
            [root.namespace_commit_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        let Some((volume, local_root)) = local else {
            return Err(VersionReachabilityError::Stale);
        };
        if volume.as_slice() != scan.volume_id.as_bytes()
            || local_root.as_slice() != root.root_object_revision_id.as_bytes()
        {
            return Err(VersionReachabilityError::Stale);
        }
        transaction.execute(
            "INSERT INTO version_reachability_roots(operation_id, root_ordinal, source_kind,
                source_id, namespace_commit_id, root_object_revision_id, record_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                page.operation_id.as_bytes().as_slice(),
                to_i64(ordinal)?,
                i64::from(kind),
                source_id.as_slice(),
                root.namespace_commit_id.as_bytes().as_slice(),
                root.root_object_revision_id.as_bytes().as_slice(),
                root_record_digest(*root).as_slice()
            ],
        )?;
    }
    Ok(())
}

fn stored_root_digest(
    transaction: &Transaction<'_>,
    scan: &StoredScan,
) -> Result<[u8; 32], VersionReachabilityError> {
    let mut statement = transaction.prepare(
        "SELECT root_ordinal, source_kind, source_id, namespace_commit_id,
                root_object_revision_id, record_digest
         FROM version_reachability_roots
         WHERE operation_id = ?1 ORDER BY root_ordinal",
    )?;
    let rows = statement.query_map([scan.operation_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
        ))
    })?;
    let mut digest = root_digest_hasher(scan.volume_id, scan.metadata_revision);
    let mut count = 0_u64;
    for row in rows {
        let row = row?;
        if from_i64(row.0)? != count {
            return Err(VersionReachabilityError::Corrupt);
        }
        let root = decode_root(&(row.1, row.2, row.3, row.4))?;
        let record_digest = array::<32>(&row.5)?;
        if record_digest != root_record_digest(root) {
            return Err(VersionReachabilityError::Corrupt);
        }
        digest.update(&record_digest);
        count = count
            .checked_add(1)
            .ok_or(VersionReachabilityError::Corrupt)?;
    }
    if count != scan.root_count {
        return Err(VersionReachabilityError::Corrupt);
    }
    Ok(digest.finalize().into())
}

fn enqueue_authoritative_roots(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<(), VersionReachabilityError> {
    transaction.execute(
        "INSERT OR IGNORE INTO version_reachability_work(operation_id, work_kind, identity, processed)
         SELECT operation_id, 1, root_object_revision_id, 0 FROM version_reachability_roots WHERE operation_id = ?1",
        [operation_id.as_bytes().as_slice()],
    )?;
    Ok(())
}

fn enqueue_local_roots(
    transaction: &Transaction<'_>,
    scan: &StoredScan,
) -> Result<[u8; 32], VersionReachabilityError> {
    let digest = current_local_roots_digest(transaction, scan.volume_id)?;
    transaction.execute(
        "INSERT OR IGNORE INTO version_reachability_work(operation_id, work_kind, identity, processed)
         SELECT ?1, 1, commits.root_object_revision_id, 0
         FROM branch_namespace_heads heads JOIN namespace_commits commits USING(namespace_commit_id)
         WHERE heads.volume_id = ?2",
        params![scan.operation_id.as_bytes().as_slice(), scan.volume_id.as_bytes().as_slice()],
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO version_reachability_work(operation_id, work_kind, identity, processed)
         SELECT ?1, 1, restores.root_object_revision_id, 0
         FROM namespace_snapshot_restore_operations restores
         JOIN namespace_commits commits USING(namespace_commit_id)
         WHERE restores.activated_at IS NULL AND commits.volume_id = ?2",
        params![
            scan.operation_id.as_bytes().as_slice(),
            scan.volume_id.as_bytes().as_slice(),
        ],
    )?;
    Ok(digest)
}

fn current_local_roots_digest(
    connection: &Connection,
    volume_id: VolumeId,
) -> Result<[u8; 32], VersionReachabilityError> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.local-lifecycle-roots.v1\0");
    digest.update(&volume_id.as_bytes());
    let mut statement = connection.prepare(
        "SELECT 1, heads.branch_id, heads.namespace_commit_id, commits.root_object_revision_id
         FROM branch_namespace_heads heads JOIN namespace_commits commits USING(namespace_commit_id)
         WHERE heads.volume_id = ?1
         UNION ALL
         SELECT 2, restores.operation_id, restores.namespace_commit_id,
                restores.root_object_revision_id
         FROM namespace_snapshot_restore_operations restores
         JOIN namespace_commits commits USING(namespace_commit_id)
         WHERE restores.activated_at IS NULL AND commits.volume_id = ?1
         ORDER BY 1, 2",
    )?;
    let rows = statement.query_map([volume_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    for row in rows {
        let row = row?;
        if !matches!(row.0, 1 | 2) || row.1.len() != 16 || row.2.len() != 16 || row.3.len() != 16 {
            return Err(VersionReachabilityError::Corrupt);
        }
        digest.update(&[u8::try_from(row.0).map_err(|_| VersionReachabilityError::Corrupt)?]);
        digest.update(&row.1);
        digest.update(&row.2);
        digest.update(&row.3);
    }
    Ok(digest.finalize().into())
}

fn candidate_is_directly_pinned(
    connection: &Connection,
    scan: &StoredScan,
) -> Result<bool, VersionReachabilityError> {
    let pinned: i64 = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM branch_files bf
             JOIN file_versions fv ON fv.version_id = bf.current_version_id
             WHERE bf.current_version_id = ?1 OR fv.manifest_id = ?2
         ) OR EXISTS(
             SELECT 1 FROM open_handles h
             JOIN file_versions fv ON fv.version_id = h.opened_version_id
             WHERE h.state = 1 AND (h.opened_version_id = ?1 OR fv.manifest_id = ?2)
         )",
        params![
            scan.version_id.as_bytes().as_slice(),
            scan.manifest_id.as_bytes().as_slice()
        ],
        |row| row.get(0),
    )?;
    Ok(pinned == 1)
}

fn process_work(
    transaction: &Transaction<'_>,
    scan: &StoredScan,
    limit: usize,
) -> Result<bool, VersionReachabilityError> {
    let mut statement = transaction.prepare(
        "SELECT work_kind, identity FROM version_reachability_work INDEXED BY version_reachability_pending
         WHERE operation_id = ?1 AND processed = 0 ORDER BY work_kind, identity LIMIT ?2")?;
    let rows = statement.query_map(
        params![
            scan.operation_id.as_bytes().as_slice(),
            i64::try_from(limit).map_err(|_| VersionReachabilityError::InvalidInput)?
        ],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    let work = rows.collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for (kind, identity) in work {
        let found = match kind {
            1 => process_object_revision(transaction, scan, &identity)?,
            2 => process_directory_node(transaction, scan, &identity)?,
            _ => return Err(VersionReachabilityError::Corrupt),
        };
        transaction.execute("UPDATE version_reachability_work SET processed = 1 WHERE operation_id = ?1 AND work_kind = ?2 AND identity = ?3 AND processed = 0", params![scan.operation_id.as_bytes().as_slice(), kind, identity])?;
        if found {
            return Ok(true);
        }
    }
    Ok(false)
}

fn process_object_revision(
    transaction: &Transaction<'_>,
    scan: &StoredScan,
    identity: &[u8],
) -> Result<bool, VersionReachabilityError> {
    type StoredObjectRevision = (
        Vec<u8>,
        i64,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    );
    let stored: StoredObjectRevision = transaction
        .query_row(
            "SELECT revisions.volume_id, revisions.object_kind,
                    revisions.directory_root_digest, revisions.file_version_id,
                    versions.manifest_id
             FROM object_revisions revisions
             LEFT JOIN file_versions versions
               ON versions.version_id = revisions.file_version_id
             WHERE revisions.object_revision_id = ?1",
            [identity],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(VersionReachabilityError::Corrupt)?;
    if stored.0.as_slice() != scan.volume_id.as_bytes() {
        return Err(VersionReachabilityError::Corrupt);
    }
    match (stored.1, stored.2, stored.3, stored.4) {
        (1, Some(root), None, None) => {
            enqueue_work(transaction, scan.operation_id, 2, &root)?;
            Ok(false)
        }
        (2, None, Some(version), Some(manifest)) => Ok(version.as_slice()
            == scan.version_id.as_bytes()
            || manifest.as_slice() == scan.manifest_id.as_bytes()),
        _ => Err(VersionReachabilityError::Corrupt),
    }
}

fn process_directory_node(
    transaction: &Transaction<'_>,
    scan: &StoredScan,
    identity: &[u8],
) -> Result<bool, VersionReachabilityError> {
    let encoded: Vec<u8> = transaction
        .query_row(
            "SELECT encoded_node FROM directory_nodes WHERE node_digest = ?1",
            [identity],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(VersionReachabilityError::Corrupt)?;
    let record =
        DirectoryNodeRecord::decode(DirectoryNodeDigest::from_bytes(array(identity)?), &encoded)
            .map_err(|_| VersionReachabilityError::Corrupt)?;
    for reference in record.reachability_references() {
        match reference {
            DirectoryReachabilityReference::Node(node) => {
                enqueue_work(transaction, scan.operation_id, 2, &node.as_bytes())?;
            }
            DirectoryReachabilityReference::ObjectRevision(revision) => {
                enqueue_work(transaction, scan.operation_id, 1, &revision.as_bytes())?;
            }
        }
    }
    Ok(false)
}

fn enqueue_work(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
    kind: i64,
    identity: &[u8],
) -> Result<(), VersionReachabilityError> {
    transaction.execute("INSERT OR IGNORE INTO version_reachability_work(operation_id, work_kind, identity, processed) VALUES (?1, ?2, ?3, 0)", params![operation_id.as_bytes().as_slice(), kind, identity])?;
    Ok(())
}

fn pending_work(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<u64, VersionReachabilityError> {
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM version_reachability_work WHERE operation_id = ?1 AND processed = 0",
        [operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    from_i64(count)
}

fn complete_scan(
    transaction: &Transaction<'_>,
    scan: &StoredScan,
    local_digest: [u8; 32],
    state: i64,
    observed_at: UnixMicros,
) -> Result<(), VersionReachabilityError> {
    let result = result_digest(scan, local_digest, state);
    let updated = transaction.execute(
        "UPDATE version_reachability_scans
         SET local_roots_digest = ?1, state = ?2, completed_at = ?3, result_digest = ?4
         WHERE operation_id = ?5 AND state IN (1, 2)",
        params![
            local_digest.as_slice(),
            state,
            observed_at.get(),
            result.as_slice(),
            scan.operation_id.as_bytes().as_slice(),
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(VersionReachabilityError::Conflict)
    }
}

fn result_digest(scan: &StoredScan, local_digest: [u8; 32], state: i64) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.version-reachability-result.v1\0");
    digest.update(&scan.operation_id.as_bytes());
    digest.update(&scan.request_digest);
    digest.update(&local_digest);
    digest.update(&[u8::try_from(state).unwrap_or(0)]);
    digest.finalize().into()
}

fn progress(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<VersionReachabilityProgress, VersionReachabilityError> {
    let scan = load_scan(connection, operation_id)?;
    let processed: i64 = connection.query_row(
        "SELECT count(*) FROM version_reachability_work WHERE operation_id = ?1 AND processed = 1",
        [operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let pending = pending_work(connection, operation_id)?;
    let state = match scan.state {
        STATE_COLLECTING => VersionReachabilityState::CollectingRoots,
        STATE_SCANNING => VersionReachabilityState::Scanning,
        STATE_REACHABLE => VersionReachabilityState::Reachable,
        STATE_UNREACHABLE => VersionReachabilityState::Unreachable,
        _ => return Err(VersionReachabilityError::Corrupt),
    };
    let proof = if state == VersionReachabilityState::Unreachable {
        Some(VersionUnreachableProof {
            operation_id,
            volume_id: scan.volume_id,
            version_id: scan.version_id,
            manifest_id: scan.manifest_id,
            manifest_root_digest: scan.manifest_root_digest,
            scan_request_digest: scan.request_digest,
            subject_digest: scan.subject_digest,
            retention_policy_sequence: scan.retention_policy_sequence,
            metadata_revision: scan.metadata_revision,
            root_count: scan.root_count,
            root_digest: scan.root_digest,
            local_roots_digest: scan
                .local_roots_digest
                .ok_or(VersionReachabilityError::Corrupt)?,
            result_digest: scan
                .result_digest
                .ok_or(VersionReachabilityError::Corrupt)?,
        })
    } else {
        None
    };
    Ok(VersionReachabilityProgress {
        state,
        roots_received: scan.roots_received,
        work_processed: from_i64(processed)?,
        work_pending: pending,
        proof,
    })
}

fn reject_operation_collision(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<(), VersionReachabilityError> {
    let collision: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM namespace_publication_operations WHERE operation_id = ?1)
          OR EXISTS(SELECT 1 FROM directory_publication_operations WHERE operation_id = ?1)
          OR EXISTS(SELECT 1 FROM namespace_reconciliation_operations WHERE operation_id = ?1)
          OR EXISTS(SELECT 1 FROM namespace_snapshot_restore_operations WHERE operation_id = ?1)
          OR EXISTS(SELECT 1 FROM handle_mutation_operations WHERE operation_id = ?1)
          OR EXISTS(SELECT 1 FROM handle_flush_plans WHERE operation_id = ?1)",
        [operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision == 0 {
        Ok(())
    } else {
        Err(VersionReachabilityError::Conflict)
    }
}

fn to_i64(value: u64) -> Result<i64, VersionReachabilityError> {
    i64::try_from(value).map_err(|_| VersionReachabilityError::InvalidInput)
}
fn from_i64(value: i64) -> Result<u64, VersionReachabilityError> {
    u64::try_from(value).map_err(|_| VersionReachabilityError::Corrupt)
}
fn revision(value: i64) -> Result<Revision, VersionReachabilityError> {
    let value = from_i64(value)?;
    if value == 0 {
        Err(VersionReachabilityError::Corrupt)
    } else {
        Ok(Revision::new(value))
    }
}
fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], VersionReachabilityError> {
    bytes
        .try_into()
        .map_err(|_| VersionReachabilityError::Corrupt)
}
fn identifier<T>(
    bytes: &[u8],
    constructor: fn([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, VersionReachabilityError> {
    constructor(array(bytes)?).map_err(|_| VersionReachabilityError::Corrupt)
}
