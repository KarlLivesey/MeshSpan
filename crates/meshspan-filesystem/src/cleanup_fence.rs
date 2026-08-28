// SPDX-License-Identifier: GPL-2.0-only

//! Durable node-local exclusion of new references while physical cleanup is proved.

use meshspan_domain::{ContentManifestId, FileVersionId, OperationId, UnixMicros, VolumeId};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::{
    ManifestPublication, PublicationError, VersionReachabilityError, VersionReachabilityScanRequest,
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
    let stored: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT manifest_id, manifest_root_digest
             FROM version_cleanup_reference_fences
             WHERE state = 1 AND (manifest_id = ?1 OR manifest_root_digest = ?2)
             LIMIT 1",
            params![
                manifest_id.as_bytes().as_slice(),
                manifest_root_digest.as_slice(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match stored {
        None => Ok(()),
        Some((_, root_digest)) if root_digest.as_slice() == manifest_root_digest => {
            Err(PublicationError::CleanupFenced)
        }
        Some(_) => Err(PublicationError::Corrupt),
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
}

fn load(
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
