// SPDX-License-Identifier: GPL-2.0-only

//! Safe local release of a temporary cleanup fence after replicated cancellation.

use meshspan_domain::{
    ContentManifestId, FileVersionId, OperationId, Revision, UnixMicros, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

/// Exact replicated cancellation authority applied by one gateway.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupCancellationAuthority {
    /// Idempotency identity of this gateway-local application.
    pub release_operation_id: OperationId,
    /// Replicated cleanup proposal identity.
    pub cleanup_operation_id: OperationId,
    /// This gateway's temporary local scan fence to release.
    pub source_scan_operation_id: OperationId,
    /// Exact operation-independent cleanup subject shared by the proposal and local fence.
    pub reachability_subject_digest: [u8; 32],
    /// Replicated operation that cancelled the cleanup proposal.
    pub cancellation_operation_id: OperationId,
    /// Replicated cancellation revision.
    pub cancellation_revision: Revision,
    /// Replicated cancellation instant.
    pub cancelled_at: UnixMicros,
    /// Gateway-known time at which this authority is applied.
    pub released_at: UnixMicros,
}

/// Immutable local proof that one cancelled cleanup fence was safely released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupCancellationReceipt {
    /// Idempotency identity of this gateway-local application.
    pub release_operation_id: OperationId,
    /// Replicated cleanup proposal identity.
    pub cleanup_operation_id: OperationId,
    /// Local scan whose temporary fence was released.
    pub source_scan_operation_id: OperationId,
    /// Volume containing the historical version.
    pub volume_id: VolumeId,
    /// Historical version selected by the scan.
    pub version_id: FileVersionId,
    /// Immutable content-manifest identity.
    pub manifest_id: ContentManifestId,
    /// Immutable manifest root no longer temporarily fenced.
    pub manifest_root_digest: [u8; 32],
    /// Replicated cancellation revision.
    pub cancellation_revision: Revision,
    /// Digest binding the exact durable local release and replicated authority.
    pub release_digest: [u8; 32],
}

/// Stable failures while applying replicated cleanup cancellation locally.
#[derive(Debug, Error)]
pub enum VersionCleanupCancellationError {
    /// Required identity, revision, digest or time ordering is invalid.
    #[error("cleanup cancellation input is invalid")]
    InvalidInput,
    /// An idempotency or cleanup identity belongs to different authority.
    #[error("cleanup cancellation authority conflicts with durable state")]
    Conflict,
    /// The local scan fence is absent, released, retired or describes another subject.
    #[error("cleanup cancellation authority is stale")]
    Stale,
    /// Persisted cancellation release or fence state violates its exact contract.
    #[error("cleanup cancellation state is corrupt")]
    Corrupt,
    /// Deterministic test-only interruption before the release transaction commits.
    #[error("cleanup cancellation transaction fault injected")]
    InjectedFault,
    /// SQLite persistence failed.
    #[error("cleanup cancellation database operation failed")]
    Sqlite(#[from] rusqlite::Error),
}

pub(crate) fn release(
    connection: &mut Connection,
    authority: VersionCleanupCancellationAuthority,
) -> Result<VersionCleanupCancellationReceipt, VersionCleanupCancellationError> {
    release_inner(connection, authority, false)
}

#[cfg(test)]
pub(crate) fn release_with_fault(
    connection: &mut Connection,
    authority: VersionCleanupCancellationAuthority,
) -> Result<VersionCleanupCancellationReceipt, VersionCleanupCancellationError> {
    release_inner(connection, authority, true)
}

fn release_inner(
    connection: &mut Connection,
    authority: VersionCleanupCancellationAuthority,
    inject_before_commit: bool,
) -> Result<VersionCleanupCancellationReceipt, VersionCleanupCancellationError> {
    validate_authority(authority)?;
    let request_digest = cancellation_request_digest(authority);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(stored) = load_release(&transaction, authority.release_operation_id)? {
        if stored.request_digest != request_digest || stored.authority != authority {
            return Err(VersionCleanupCancellationError::Conflict);
        }
        validate_stored_release(&transaction, &stored)?;
        transaction.commit()?;
        return Ok(stored.receipt);
    }
    crate::reachability::reject_operation_collision(&transaction, authority.release_operation_id)
        .map_err(map_reachability)?;
    reject_identity_collision(&transaction, authority)?;
    let fence = crate::cleanup_fence::load(&transaction, authority.source_scan_operation_id)
        .map_err(map_reachability)?
        .ok_or(VersionCleanupCancellationError::Stale)?;
    if !fence.is_active() || fence.subject_digest != authority.reachability_subject_digest {
        return Err(VersionCleanupCancellationError::Stale);
    }
    let release_digest = cancellation_release_digest(authority, fence);
    transaction.execute(
        "INSERT INTO cancelled_cleanup_releases(
            release_operation_id, request_digest, cleanup_operation_id,
            source_scan_operation_id, volume_id, version_id, manifest_id,
            manifest_root_digest, reachability_subject_digest,
            cancellation_operation_id, cancellation_revision, cancelled_at,
            released_at, release_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            authority.release_operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            authority.cleanup_operation_id.as_bytes().as_slice(),
            authority.source_scan_operation_id.as_bytes().as_slice(),
            fence.volume_id.as_bytes().as_slice(),
            fence.version_id.as_bytes().as_slice(),
            fence.manifest_id.as_bytes().as_slice(),
            fence.manifest_root_digest.as_slice(),
            authority.reachability_subject_digest.as_slice(),
            authority.cancellation_operation_id.as_bytes().as_slice(),
            to_i64(authority.cancellation_revision.get())?,
            authority.cancelled_at.get(),
            authority.released_at.get(),
            release_digest.as_slice(),
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE version_cleanup_reference_fences
         SET state = 2, released_at = ?1
         WHERE operation_id = ?2 AND state = 1 AND released_at IS NULL",
        params![
            authority.released_at.get(),
            authority.source_scan_operation_id.as_bytes().as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(VersionCleanupCancellationError::Stale);
    }
    let receipt = cancellation_receipt(authority, fence, release_digest);
    if inject_before_commit {
        return Err(VersionCleanupCancellationError::InjectedFault);
    }
    transaction.commit()?;
    Ok(receipt)
}

fn reject_identity_collision(
    connection: &Connection,
    authority: VersionCleanupCancellationAuthority,
) -> Result<(), VersionCleanupCancellationError> {
    let collision: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM retired_manifest_roots
            WHERE cleanup_operation_id = ?1
               OR source_scan_operation_id = ?2
               OR completion_operation_id = ?3
         ) OR EXISTS(
            SELECT 1 FROM cancelled_cleanup_releases
            WHERE cleanup_operation_id = ?1
               OR source_scan_operation_id = ?2
               OR cancellation_operation_id = ?3
         )",
        params![
            authority.cleanup_operation_id.as_bytes().as_slice(),
            authority.source_scan_operation_id.as_bytes().as_slice(),
            authority.cancellation_operation_id.as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    if collision == 0 {
        Ok(())
    } else {
        Err(VersionCleanupCancellationError::Conflict)
    }
}

#[derive(Clone, Copy)]
struct StoredCancellationRelease {
    request_digest: [u8; 32],
    authority: VersionCleanupCancellationAuthority,
    receipt: VersionCleanupCancellationReceipt,
}

fn load_release(
    connection: &Connection,
    release_operation_id: OperationId,
) -> Result<Option<StoredCancellationRelease>, VersionCleanupCancellationError> {
    connection
        .query_row(
            "SELECT request_digest, cleanup_operation_id, source_scan_operation_id,
                    volume_id, version_id, manifest_id, manifest_root_digest,
                    reachability_subject_digest, cancellation_operation_id,
                    cancellation_revision, cancelled_at, released_at, release_digest
             FROM cancelled_cleanup_releases WHERE release_operation_id = ?1",
            [release_operation_id.as_bytes().as_slice()],
            |row| {
                let cleanup_operation_id = operation(&row.get::<_, Vec<u8>>(1)?)?;
                let source_scan_operation_id = operation(&row.get::<_, Vec<u8>>(2)?)?;
                let cancellation_revision = revision(row.get(9)?)?;
                let authority = VersionCleanupCancellationAuthority {
                    release_operation_id,
                    cleanup_operation_id,
                    source_scan_operation_id,
                    reachability_subject_digest: sql_array(&row.get::<_, Vec<u8>>(7)?)?,
                    cancellation_operation_id: operation(&row.get::<_, Vec<u8>>(8)?)?,
                    cancellation_revision,
                    cancelled_at: UnixMicros::new(row.get(10)?),
                    released_at: UnixMicros::new(row.get(11)?),
                };
                Ok(StoredCancellationRelease {
                    request_digest: sql_array(&row.get::<_, Vec<u8>>(0)?)?,
                    authority,
                    receipt: VersionCleanupCancellationReceipt {
                        release_operation_id,
                        cleanup_operation_id,
                        source_scan_operation_id,
                        volume_id: VolumeId::from_bytes(sql_array(&row.get::<_, Vec<u8>>(3)?)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        version_id: FileVersionId::from_bytes(sql_array(
                            &row.get::<_, Vec<u8>>(4)?,
                        )?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        manifest_id: ContentManifestId::from_bytes(sql_array(
                            &row.get::<_, Vec<u8>>(5)?,
                        )?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        manifest_root_digest: sql_array(&row.get::<_, Vec<u8>>(6)?)?,
                        cancellation_revision,
                        release_digest: sql_array(&row.get::<_, Vec<u8>>(12)?)?,
                    },
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

pub(crate) fn require_released_scan(
    connection: &Connection,
    identity: crate::cleanup_fence::ReferenceFenceIdentity,
) -> Result<(), crate::VersionReachabilityError> {
    let release_operation_id: Option<Vec<u8>> = connection
        .query_row(
            "SELECT release_operation_id FROM cancelled_cleanup_releases
             WHERE source_scan_operation_id = ?1",
            [identity.operation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(release_operation_id) = release_operation_id else {
        return Err(crate::VersionReachabilityError::Stale);
    };
    let release_operation_id = OperationId::from_bytes(
        release_operation_id
            .try_into()
            .map_err(|_| crate::VersionReachabilityError::Corrupt)?,
    )
    .map_err(|_| crate::VersionReachabilityError::Corrupt)?;
    let stored = load_release(connection, release_operation_id)
        .map_err(map_cancellation_to_reachability)?
        .ok_or(crate::VersionReachabilityError::Corrupt)?;
    validate_stored_release(connection, &stored).map_err(map_cancellation_to_reachability)?;
    if stored.authority.source_scan_operation_id == identity.operation_id
        && stored.authority.reachability_subject_digest == identity.subject_digest
        && stored.receipt.volume_id == identity.volume_id
        && stored.receipt.version_id == identity.version_id
        && stored.receipt.manifest_id == identity.manifest_id
        && stored.receipt.manifest_root_digest == identity.manifest_root_digest
    {
        Ok(())
    } else {
        Err(crate::VersionReachabilityError::Corrupt)
    }
}

fn validate_stored_release(
    connection: &Connection,
    stored: &StoredCancellationRelease,
) -> Result<(), VersionCleanupCancellationError> {
    validate_authority(stored.authority).map_err(|_| VersionCleanupCancellationError::Corrupt)?;
    let fence = crate::cleanup_fence::load(connection, stored.authority.source_scan_operation_id)
        .map_err(map_reachability)?
        .ok_or(VersionCleanupCancellationError::Corrupt)?;
    let expected_receipt = cancellation_receipt(
        stored.authority,
        fence,
        cancellation_release_digest(stored.authority, fence),
    );
    if !fence.is_released_at(stored.authority.released_at)
        || fence.subject_digest != stored.authority.reachability_subject_digest
        || stored.request_digest != cancellation_request_digest(stored.authority)
        || stored.receipt != expected_receipt
    {
        Err(VersionCleanupCancellationError::Corrupt)
    } else {
        Ok(())
    }
}

fn validate_authority(
    authority: VersionCleanupCancellationAuthority,
) -> Result<(), VersionCleanupCancellationError> {
    if authority.release_operation_id == authority.cleanup_operation_id
        || authority.release_operation_id == authority.source_scan_operation_id
        || authority.release_operation_id == authority.cancellation_operation_id
        || authority.cleanup_operation_id == authority.source_scan_operation_id
        || authority.cleanup_operation_id == authority.cancellation_operation_id
        || authority.source_scan_operation_id == authority.cancellation_operation_id
        || authority.reachability_subject_digest == [0; 32]
        || authority.cancellation_revision == Revision::ZERO
        || authority.released_at < authority.cancelled_at
    {
        Err(VersionCleanupCancellationError::InvalidInput)
    } else {
        Ok(())
    }
}

fn cancellation_request_digest(authority: VersionCleanupCancellationAuthority) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.cleanup-cancellation-request.v1\0");
    digest.update(&authority.release_operation_id.as_bytes());
    digest.update(&authority.cleanup_operation_id.as_bytes());
    digest.update(&authority.source_scan_operation_id.as_bytes());
    digest.update(&authority.reachability_subject_digest);
    digest.update(&authority.cancellation_operation_id.as_bytes());
    digest.update(&authority.cancellation_revision.get().to_be_bytes());
    digest.update(&authority.cancelled_at.get().to_be_bytes());
    digest.update(&authority.released_at.get().to_be_bytes());
    digest.finalize().into()
}

fn cancellation_release_digest(
    authority: VersionCleanupCancellationAuthority,
    fence: crate::cleanup_fence::ReferenceFenceIdentity,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.cleanup-cancellation.v1\0");
    digest.update(&cancellation_request_digest(authority));
    digest.update(&fence.volume_id.as_bytes());
    digest.update(&fence.version_id.as_bytes());
    digest.update(&fence.manifest_id.as_bytes());
    digest.update(&fence.manifest_root_digest);
    digest.finalize().into()
}

const fn cancellation_receipt(
    authority: VersionCleanupCancellationAuthority,
    fence: crate::cleanup_fence::ReferenceFenceIdentity,
    release_digest: [u8; 32],
) -> VersionCleanupCancellationReceipt {
    VersionCleanupCancellationReceipt {
        release_operation_id: authority.release_operation_id,
        cleanup_operation_id: authority.cleanup_operation_id,
        source_scan_operation_id: authority.source_scan_operation_id,
        volume_id: fence.volume_id,
        version_id: fence.version_id,
        manifest_id: fence.manifest_id,
        manifest_root_digest: fence.manifest_root_digest,
        cancellation_revision: authority.cancellation_revision,
        release_digest,
    }
}

fn map_reachability(error: crate::VersionReachabilityError) -> VersionCleanupCancellationError {
    match error {
        crate::VersionReachabilityError::Sqlite(error) => {
            VersionCleanupCancellationError::Sqlite(error)
        }
        crate::VersionReachabilityError::Corrupt => VersionCleanupCancellationError::Corrupt,
        crate::VersionReachabilityError::InvalidInput
        | crate::VersionReachabilityError::Conflict
        | crate::VersionReachabilityError::Stale => VersionCleanupCancellationError::Conflict,
    }
}

fn map_cancellation_to_reachability(
    error: VersionCleanupCancellationError,
) -> crate::VersionReachabilityError {
    match error {
        VersionCleanupCancellationError::Sqlite(error) => {
            crate::VersionReachabilityError::Sqlite(error)
        }
        VersionCleanupCancellationError::InvalidInput
        | VersionCleanupCancellationError::Conflict
        | VersionCleanupCancellationError::Stale => crate::VersionReachabilityError::Stale,
        VersionCleanupCancellationError::Corrupt
        | VersionCleanupCancellationError::InjectedFault => {
            crate::VersionReachabilityError::Corrupt
        }
    }
}

fn to_i64(value: u64) -> Result<i64, VersionCleanupCancellationError> {
    i64::try_from(value).map_err(|_| VersionCleanupCancellationError::InvalidInput)
}

fn positive(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn revision(value: i64) -> Result<Revision, rusqlite::Error> {
    positive(value).map(Revision::new)
}

fn sql_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], rusqlite::Error> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn operation(bytes: &[u8]) -> Result<OperationId, rusqlite::Error> {
    OperationId::from_bytes(sql_array(bytes)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
