// SPDX-License-Identifier: GPL-2.0-only

//! Durable node-local exclusion of new references while physical cleanup is proved.

use meshspan_domain::{ContentManifestId, FileVersionId, OperationId, UnixMicros, VolumeId};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{
    ManifestPublication, PublicationError, VersionCleanupRetirementAuthority,
    VersionCleanupRetirementError, VersionCleanupRetirementReceipt, VersionReachabilityError,
    VersionReachabilityScanRequest,
};

const FENCE_ACTIVE: i64 = 1;
const FENCE_RELEASED: i64 = 2;
type StoredReferenceFence = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Option<i64>,
);

pub(crate) fn install(
    transaction: &Transaction<'_>,
    request: &VersionReachabilityScanRequest,
    subject_digest: [u8; 32],
) -> Result<(), VersionReachabilityError> {
    reject_active_collision(transaction, request.candidate.manifest_root_digest)?;
    transaction.execute(
        "INSERT INTO version_cleanup_reference_fences(
            operation_id, volume_id, version_id, manifest_id, manifest_root_digest,
            subject_digest, state, installed_at, released_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, NULL)",
        params![
            request.operation_id.as_bytes().as_slice(),
            request.candidate.volume_id.as_bytes().as_slice(),
            request.candidate.version_id.as_bytes().as_slice(),
            request.candidate.manifest_id.as_bytes().as_slice(),
            request.candidate.manifest_root_digest.as_slice(),
            subject_digest.as_slice(),
            request.selected_at.get(),
        ],
    )?;
    Ok(())
}

pub(crate) fn require_active(
    connection: &Connection,
    identity: ReferenceFenceIdentity,
) -> Result<(), VersionReachabilityError> {
    let stored = load(connection, identity.operation_id)?.ok_or(VersionReachabilityError::Stale)?;
    if stored == identity && stored.state == FENCE_ACTIVE && stored.released_at.is_none() {
        Ok(())
    } else {
        Err(VersionReachabilityError::Stale)
    }
}

pub(crate) fn require_released(
    connection: &Connection,
    identity: ReferenceFenceIdentity,
) -> Result<(), VersionReachabilityError> {
    let stored = load(connection, identity.operation_id)?.ok_or(VersionReachabilityError::Stale)?;
    let expected = ReferenceFenceIdentity {
        state: FENCE_RELEASED,
        released_at: stored.released_at,
        ..identity
    };
    if stored == expected && stored.released_at.is_some() {
        Ok(())
    } else {
        Err(VersionReachabilityError::Stale)
    }
}

pub(crate) fn release_reachable(
    transaction: &Transaction<'_>,
    identity: ReferenceFenceIdentity,
    released_at: UnixMicros,
) -> Result<(), VersionReachabilityError> {
    require_active(transaction, identity)?;
    let retired: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM retired_manifest_roots WHERE source_scan_operation_id = ?1
         )",
        [identity.operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if retired != 0 {
        return Err(VersionReachabilityError::Stale);
    }
    let changed = transaction.execute(
        "UPDATE version_cleanup_reference_fences
         SET state = ?1, released_at = ?2
         WHERE operation_id = ?3 AND state = ?4 AND released_at IS NULL",
        params![
            FENCE_RELEASED,
            released_at.get(),
            identity.operation_id.as_bytes().as_slice(),
            FENCE_ACTIVE,
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(VersionReachabilityError::Stale)
    }
}

pub(crate) fn reject_manifest_reference(
    connection: &Connection,
    manifest: ManifestPublication,
) -> Result<(), PublicationError> {
    reject_manifest_identity(connection, manifest.manifest_id, manifest.root_digest)
}

pub(crate) fn reject_volume_restore(
    connection: &Connection,
    volume_id: VolumeId,
) -> Result<(), PublicationError> {
    let fenced: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM version_cleanup_reference_fences
            WHERE volume_id = ?1 AND state = 1
            UNION ALL
            SELECT 1 FROM retired_manifest_roots WHERE volume_id = ?1
         )",
        [volume_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if fenced == 0 {
        Ok(())
    } else {
        Err(PublicationError::CleanupFenced)
    }
}

fn reject_manifest_identity(
    connection: &Connection,
    manifest_id: ContentManifestId,
    manifest_root_digest: [u8; 32],
) -> Result<(), PublicationError> {
    let mut statement = connection.prepare(
        "SELECT manifest_id, manifest_root_digest FROM (
            SELECT manifest_id, manifest_root_digest
            FROM version_cleanup_reference_fences
            WHERE state = 1 AND (manifest_id = ?1 OR manifest_root_digest = ?2)
            UNION
            SELECT manifest_id, manifest_root_digest
            FROM retired_manifest_roots
            WHERE manifest_id = ?1 OR manifest_root_digest = ?2
         ) LIMIT 2",
    )?;
    let stored = statement
        .query_map(
            params![
                manifest_id.as_bytes().as_slice(),
                manifest_root_digest.as_slice(),
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    match stored.as_slice() {
        [] => Ok(()),
        [(_, root_digest)] if root_digest.as_slice() == manifest_root_digest => {
            Err(PublicationError::CleanupFenced)
        }
        _ => Err(PublicationError::Corrupt),
    }
}

pub(crate) fn reject_version_reference(
    connection: &Connection,
    version_id: FileVersionId,
) -> Result<(), PublicationError> {
    let stored: (i64, Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT manifests.state, versions.manifest_id, manifests.root_digest
         FROM file_versions versions
         JOIN content_manifests manifests USING(manifest_id)
         WHERE versions.version_id = ?1",
        [version_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if stored.0 != 1 || stored.1.len() != 16 || stored.2.len() != 32 {
        return Err(PublicationError::Corrupt);
    }
    reject_manifest_identity(
        connection,
        ContentManifestId::from_bytes(stored.1.try_into().map_err(|_| PublicationError::Corrupt)?)
            .map_err(|_| PublicationError::Corrupt)?,
        stored.2.try_into().map_err(|_| PublicationError::Corrupt)?,
    )
}

fn reject_active_collision(
    connection: &Connection,
    manifest_root_digest: [u8; 32],
) -> Result<(), VersionReachabilityError> {
    let active: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM version_cleanup_reference_fences
            WHERE manifest_root_digest = ?1 AND state = 1
            UNION ALL
            SELECT 1 FROM retired_manifest_roots WHERE manifest_root_digest = ?1
         )",
        [manifest_root_digest.as_slice()],
        |row| row.get(0),
    )?;
    if active == 0 {
        Ok(())
    } else {
        Err(VersionReachabilityError::Conflict)
    }
}

pub(crate) fn retire_completed(
    connection: &mut Connection,
    authority: VersionCleanupRetirementAuthority,
) -> Result<VersionCleanupRetirementReceipt, VersionCleanupRetirementError> {
    retire_completed_inner(connection, authority, false)
}

#[cfg(test)]
pub(crate) fn retire_completed_with_fault(
    connection: &mut Connection,
    authority: VersionCleanupRetirementAuthority,
) -> Result<VersionCleanupRetirementReceipt, VersionCleanupRetirementError> {
    retire_completed_inner(connection, authority, true)
}

fn retire_completed_inner(
    connection: &mut Connection,
    authority: VersionCleanupRetirementAuthority,
    inject_before_commit: bool,
) -> Result<VersionCleanupRetirementReceipt, VersionCleanupRetirementError> {
    validate_retirement_authority(authority)?;
    let request_digest = retirement_request_digest(authority);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(stored) = load_retirement(&transaction, authority.retirement_operation_id)? {
        if stored.request_digest != request_digest || stored.authority != authority {
            return Err(VersionCleanupRetirementError::Conflict);
        }
        validate_stored_retirement(&stored)?;
        transaction.commit()?;
        return Ok(stored.receipt);
    }
    crate::reachability::reject_operation_collision(
        &transaction,
        authority.retirement_operation_id,
    )
    .map_err(map_reachability)?;
    let identity_collision: i64 = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM retired_manifest_roots
            WHERE cleanup_operation_id = ?1
               OR source_scan_operation_id = ?2
               OR completion_operation_id = ?3
         )",
        params![
            authority.cleanup_operation_id.as_bytes().as_slice(),
            authority.source_scan_operation_id.as_bytes().as_slice(),
            authority.completion_operation_id.as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    if identity_collision != 0 {
        return Err(VersionCleanupRetirementError::Conflict);
    }
    let fence = load(&transaction, authority.source_scan_operation_id)
        .map_err(map_reachability)?
        .ok_or(VersionCleanupRetirementError::Stale)?;
    if fence.state != FENCE_ACTIVE
        || fence.released_at.is_some()
        || fence.subject_digest != authority.reachability_subject_digest
    {
        return Err(VersionCleanupRetirementError::Stale);
    }
    let retirement_digest = retirement_digest(authority, fence);
    transaction.execute(
        "INSERT INTO retired_manifest_roots(
            retirement_operation_id, request_digest, cleanup_operation_id,
            source_scan_operation_id, volume_id, version_id, manifest_id,
            manifest_root_digest, reachability_subject_digest, completed_item_count,
            completion_digest, completion_operation_id, completion_revision,
            completed_at, retired_at, retirement_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                   ?14, ?15, ?16)",
        params![
            authority.retirement_operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            authority.cleanup_operation_id.as_bytes().as_slice(),
            authority.source_scan_operation_id.as_bytes().as_slice(),
            fence.volume_id.as_bytes().as_slice(),
            fence.version_id.as_bytes().as_slice(),
            fence.manifest_id.as_bytes().as_slice(),
            fence.manifest_root_digest.as_slice(),
            authority.reachability_subject_digest.as_slice(),
            to_i64(authority.completed_item_count)?,
            authority.completion_digest.as_slice(),
            authority.completion_operation_id.as_bytes().as_slice(),
            to_i64(authority.completion_revision.get())?,
            authority.completed_at.get(),
            authority.retired_at.get(),
            retirement_digest.as_slice(),
        ],
    )?;
    let receipt = retirement_receipt(authority, fence, retirement_digest);
    if inject_before_commit {
        return Err(VersionCleanupRetirementError::InjectedFault);
    }
    transaction.commit()?;
    Ok(receipt)
}

#[derive(Clone, Copy)]
struct StoredRetirement {
    request_digest: [u8; 32],
    authority: VersionCleanupRetirementAuthority,
    receipt: VersionCleanupRetirementReceipt,
}

fn load_retirement(
    connection: &Connection,
    retirement_operation_id: meshspan_domain::OperationId,
) -> Result<Option<StoredRetirement>, VersionCleanupRetirementError> {
    connection
        .query_row(
            "SELECT request_digest, cleanup_operation_id, source_scan_operation_id,
                    volume_id, version_id, manifest_id, manifest_root_digest,
                    reachability_subject_digest, completed_item_count, completion_digest,
                    completion_operation_id, completion_revision, completed_at, retired_at,
                    retirement_digest
             FROM retired_manifest_roots WHERE retirement_operation_id = ?1",
            [retirement_operation_id.as_bytes().as_slice()],
            |row| {
                let cleanup_operation_id = operation(&row.get::<_, Vec<u8>>(1)?)?;
                let source_scan_operation_id = operation(&row.get::<_, Vec<u8>>(2)?)?;
                let completion_revision = revision(row.get(11)?)?;
                let authority = VersionCleanupRetirementAuthority {
                    retirement_operation_id,
                    cleanup_operation_id,
                    source_scan_operation_id,
                    reachability_subject_digest: sql_array(&row.get::<_, Vec<u8>>(7)?)?,
                    completed_item_count: positive(row.get(8)?)?,
                    completion_digest: sql_array(&row.get::<_, Vec<u8>>(9)?)?,
                    completion_operation_id: operation(&row.get::<_, Vec<u8>>(10)?)?,
                    completion_revision,
                    completed_at: UnixMicros::new(row.get(12)?),
                    retired_at: UnixMicros::new(row.get(13)?),
                };
                Ok(StoredRetirement {
                    request_digest: sql_array(&row.get::<_, Vec<u8>>(0)?)?,
                    authority,
                    receipt: VersionCleanupRetirementReceipt {
                        retirement_operation_id,
                        cleanup_operation_id,
                        source_scan_operation_id,
                        volume_id: VolumeId::from_bytes(sql_array(&row.get::<_, Vec<u8>>(3)?)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        version_id: meshspan_domain::FileVersionId::from_bytes(sql_array(
                            &row.get::<_, Vec<u8>>(4)?,
                        )?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        manifest_id: ContentManifestId::from_bytes(sql_array(
                            &row.get::<_, Vec<u8>>(5)?,
                        )?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        manifest_root_digest: sql_array(&row.get::<_, Vec<u8>>(6)?)?,
                        completion_revision,
                        retirement_digest: sql_array(&row.get::<_, Vec<u8>>(14)?)?,
                    },
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn validate_retirement_authority(
    authority: VersionCleanupRetirementAuthority,
) -> Result<(), VersionCleanupRetirementError> {
    if authority.retirement_operation_id == authority.cleanup_operation_id
        || authority.retirement_operation_id == authority.source_scan_operation_id
        || authority.retirement_operation_id == authority.completion_operation_id
        || authority.cleanup_operation_id == authority.source_scan_operation_id
        || authority.cleanup_operation_id == authority.completion_operation_id
        || authority.source_scan_operation_id == authority.completion_operation_id
        || authority.reachability_subject_digest == [0; 32]
        || authority.completed_item_count == 0
        || i64::try_from(authority.completed_item_count).is_err()
        || authority.completion_digest == [0; 32]
        || authority.completion_revision == meshspan_domain::Revision::ZERO
        || authority.retired_at < authority.completed_at
    {
        Err(VersionCleanupRetirementError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_stored_retirement(
    stored: &StoredRetirement,
) -> Result<(), VersionCleanupRetirementError> {
    validate_retirement_authority(stored.authority)
        .map_err(|_| VersionCleanupRetirementError::Corrupt)?;
    let expected = retirement_digest_from_receipt(stored.authority, stored.receipt);
    if stored.request_digest == retirement_request_digest(stored.authority)
        && stored.receipt.retirement_digest == expected
    {
        Ok(())
    } else {
        Err(VersionCleanupRetirementError::Corrupt)
    }
}

fn retirement_request_digest(authority: VersionCleanupRetirementAuthority) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.cleanup-retirement-request.v1\0");
    digest.update(&authority.retirement_operation_id.as_bytes());
    digest.update(&authority.cleanup_operation_id.as_bytes());
    digest.update(&authority.source_scan_operation_id.as_bytes());
    digest.update(&authority.reachability_subject_digest);
    digest.update(&authority.completed_item_count.to_be_bytes());
    digest.update(&authority.completion_digest);
    digest.update(&authority.completion_operation_id.as_bytes());
    digest.update(&authority.completion_revision.get().to_be_bytes());
    digest.update(&authority.completed_at.get().to_be_bytes());
    digest.update(&authority.retired_at.get().to_be_bytes());
    digest.finalize().into()
}

fn retirement_digest(
    authority: VersionCleanupRetirementAuthority,
    fence: ReferenceFenceIdentity,
) -> [u8; 32] {
    retirement_digest_fields(
        authority,
        fence.volume_id,
        fence.version_id,
        fence.manifest_id,
        fence.manifest_root_digest,
    )
}

fn retirement_digest_from_receipt(
    authority: VersionCleanupRetirementAuthority,
    receipt: VersionCleanupRetirementReceipt,
) -> [u8; 32] {
    retirement_digest_fields(
        authority,
        receipt.volume_id,
        receipt.version_id,
        receipt.manifest_id,
        receipt.manifest_root_digest,
    )
}

fn retirement_digest_fields(
    authority: VersionCleanupRetirementAuthority,
    volume_id: VolumeId,
    version_id: meshspan_domain::FileVersionId,
    manifest_id: ContentManifestId,
    manifest_root_digest: [u8; 32],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.cleanup-retirement.v1\0");
    digest.update(&retirement_request_digest(authority));
    digest.update(&volume_id.as_bytes());
    digest.update(&version_id.as_bytes());
    digest.update(&manifest_id.as_bytes());
    digest.update(&manifest_root_digest);
    digest.finalize().into()
}

const fn retirement_receipt(
    authority: VersionCleanupRetirementAuthority,
    fence: ReferenceFenceIdentity,
    retirement_digest: [u8; 32],
) -> VersionCleanupRetirementReceipt {
    VersionCleanupRetirementReceipt {
        retirement_operation_id: authority.retirement_operation_id,
        cleanup_operation_id: authority.cleanup_operation_id,
        source_scan_operation_id: authority.source_scan_operation_id,
        volume_id: fence.volume_id,
        version_id: fence.version_id,
        manifest_id: fence.manifest_id,
        manifest_root_digest: fence.manifest_root_digest,
        completion_revision: authority.completion_revision,
        retirement_digest,
    }
}

fn map_reachability(error: VersionReachabilityError) -> VersionCleanupRetirementError {
    match error {
        VersionReachabilityError::Sqlite(error) => VersionCleanupRetirementError::Sqlite(error),
        VersionReachabilityError::Corrupt => VersionCleanupRetirementError::Corrupt,
        VersionReachabilityError::InvalidInput
        | VersionReachabilityError::Conflict
        | VersionReachabilityError::Stale => VersionCleanupRetirementError::Conflict,
    }
}

fn to_i64(value: u64) -> Result<i64, VersionCleanupRetirementError> {
    i64::try_from(value).map_err(|_| VersionCleanupRetirementError::InvalidInput)
}

fn positive(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn revision(value: i64) -> Result<meshspan_domain::Revision, rusqlite::Error> {
    positive(value).map(meshspan_domain::Revision::new)
}

fn sql_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], rusqlite::Error> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn operation(bytes: &[u8]) -> Result<meshspan_domain::OperationId, rusqlite::Error> {
    meshspan_domain::OperationId::from_bytes(sql_array(bytes)?)
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReferenceFenceIdentity {
    pub operation_id: OperationId,
    pub volume_id: VolumeId,
    pub version_id: FileVersionId,
    pub manifest_id: ContentManifestId,
    pub manifest_root_digest: [u8; 32],
    pub subject_digest: [u8; 32],
    state: i64,
    released_at: Option<i64>,
}

impl ReferenceFenceIdentity {
    pub(crate) const fn active(
        operation_id: OperationId,
        volume_id: VolumeId,
        version_id: FileVersionId,
        manifest_id: ContentManifestId,
        manifest_root_digest: [u8; 32],
        subject_digest: [u8; 32],
    ) -> Self {
        Self {
            operation_id,
            volume_id,
            version_id,
            manifest_id,
            manifest_root_digest,
            subject_digest,
            state: FENCE_ACTIVE,
            released_at: None,
        }
    }

    pub(crate) const fn is_active(self) -> bool {
        self.state == FENCE_ACTIVE && self.released_at.is_none()
    }

    pub(crate) fn is_released_at(self, released_at: UnixMicros) -> bool {
        self.state == FENCE_RELEASED && self.released_at == Some(released_at.get())
    }
}

pub(crate) fn load(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<ReferenceFenceIdentity>, VersionReachabilityError> {
    connection
        .query_row(
            "SELECT volume_id, version_id, manifest_id, manifest_root_digest,
                    subject_digest, state, released_at
             FROM version_cleanup_reference_fences WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?
        .map(|stored: StoredReferenceFence| decode(operation_id, &stored))
        .transpose()
}

fn decode(
    operation_id: OperationId,
    stored: &StoredReferenceFence,
) -> Result<ReferenceFenceIdentity, VersionReachabilityError> {
    let state = stored.5;
    if !matches!(state, FENCE_ACTIVE | FENCE_RELEASED)
        || (state == FENCE_ACTIVE) != stored.6.is_none()
    {
        return Err(VersionReachabilityError::Corrupt);
    }
    Ok(ReferenceFenceIdentity {
        operation_id,
        volume_id: VolumeId::from_bytes(array(&stored.0)?)
            .map_err(|_| VersionReachabilityError::Corrupt)?,
        version_id: FileVersionId::from_bytes(array(&stored.1)?)
            .map_err(|_| VersionReachabilityError::Corrupt)?,
        manifest_id: ContentManifestId::from_bytes(array(&stored.2)?)
            .map_err(|_| VersionReachabilityError::Corrupt)?,
        manifest_root_digest: array(&stored.3)?,
        subject_digest: array(&stored.4)?,
        state,
        released_at: stored.6,
    })
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], VersionReachabilityError> {
    bytes
        .try_into()
        .map_err(|_| VersionReachabilityError::Corrupt)
}
