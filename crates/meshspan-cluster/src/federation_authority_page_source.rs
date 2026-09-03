// SPDX-License-Identifier: GPL-2.0-only

//! Stable, bounded composition of relationship and grant authority records.

mod cursor;

use meshspan_domain::{FederationRelationshipId, Revision};
use meshspan_metadata::{AuthoritativeRepository, PageLimit, RepositoryError};
use meshspan_protocol::v1::VersionedPayload;
use thiserror::Error;

use self::cursor::FederationAuthorityCursor;

/// Stable-revision query passed only after the requesting peer and message are authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationAuthorityPageQuery {
    /// Exact admitted relationship.
    pub relationship_id: FederationRelationshipId,
    /// Peer revision floor; zero requests its initial authority snapshot.
    pub after_revision: u64,
    /// Opaque continuation previously emitted in a signed page.
    pub cursor: Vec<u8>,
    /// Positive peer-requested bound already checked against negotiated wire limits.
    pub limit: u32,
    /// Exact local committed revision under which the page must remain stable.
    pub authority_revision: Revision,
}

/// Canonical records and optional continuation returned by an authority source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationAuthorityPageRecords {
    /// Exact stable source revision represented by this page.
    pub authority_revision: Revision,
    /// Independently versioned canonical authority records.
    pub records: Vec<VersionedPayload>,
    /// Opaque continuation, empty only when this stable page is terminal.
    pub next_cursor: Vec<u8>,
}

/// Narrow read boundary for relationship, identity, delegation and restriction history.
pub trait FederationAuthorityPageSource {
    /// Produces one stable page for an already authenticated request.
    ///
    /// # Errors
    ///
    /// Fails closed for stale/forged cursors, unavailable revisions or corrupt authority records.
    fn authority_page(
        &self,
        query: FederationAuthorityPageQuery,
    ) -> Result<FederationAuthorityPageRecords, FederationAuthorityPageSourceError>;
}

/// Deliberately non-diagnostic authority source failures safe to expose across composition layers.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FederationAuthorityPageSourceError {
    /// Cursor, revision or page bounds did not identify one valid stable query.
    #[error("federation authority page query is invalid")]
    InvalidQuery,
    /// The requested stable revision is not currently available.
    #[error("federation authority page revision is unavailable")]
    Unavailable,
    /// Persisted or generated authority evidence failed validation.
    #[error("federation authority page evidence is corrupt")]
    Corrupt,
}

impl FederationAuthorityPageSource for AuthoritativeRepository {
    fn authority_page(
        &self,
        query: FederationAuthorityPageQuery,
    ) -> Result<FederationAuthorityPageRecords, FederationAuthorityPageSourceError> {
        let limit = query_limit(query.limit)?;
        let authority = self
            .federation_transport_authority(query.relationship_id)
            .map_err(|_| FederationAuthorityPageSourceError::Corrupt)?
            .ok_or(FederationAuthorityPageSourceError::Unavailable)?;
        validate_revision_window(&query, authority.authority_revision)?;
        if query.after_revision == authority.authority_revision.get() {
            return terminal_page(authority.authority_revision, &query.cursor);
        }
        let continuation = decode_cursor(&query)?;
        let mut records = Vec::with_capacity(limit);
        if continuation.is_none() {
            records.push(versioned(
                authority
                    .canonical_bytes()
                    .map_err(|_| FederationAuthorityPageSourceError::Corrupt)?,
            ));
        }
        append_grants(self, &query, continuation, limit, records)
    }
}

fn append_grants(
    repository: &AuthoritativeRepository,
    query: &FederationAuthorityPageQuery,
    continuation: Option<FederationAuthorityCursor>,
    limit: usize,
    mut records: Vec<VersionedPayload>,
) -> Result<FederationAuthorityPageRecords, FederationAuthorityPageSourceError> {
    let grant_cursor = continuation.and_then(FederationAuthorityCursor::grant_cursor);
    let available = limit.saturating_sub(records.len());
    let query_limit = PageLimit::new(available.max(1))
        .map_err(|_| FederationAuthorityPageSourceError::InvalidQuery)?;
    let page = repository
        .federation_grants_page(
            query.relationship_id,
            Revision::new(query.after_revision),
            query.authority_revision,
            grant_cursor,
            query_limit,
        )
        .map_err(|error| map_repository_error(&error))?;
    if available == 0 {
        let next_cursor = if page.items.is_empty() {
            Vec::new()
        } else {
            page_cursor(query, None)?
                .canonical_bytes()
                .map_err(|_| FederationAuthorityPageSourceError::Corrupt)?
        };
        return Ok(page_records(query.authority_revision, records, next_cursor));
    }
    for grant in page.items {
        records.push(versioned(
            grant
                .canonical_bytes()
                .map_err(|_| FederationAuthorityPageSourceError::Corrupt)?,
        ));
    }
    let next_cursor = page
        .next
        .map(|grant_cursor| {
            page_cursor(query, Some(grant_cursor))?
                .canonical_bytes()
                .map_err(|_| FederationAuthorityPageSourceError::Corrupt)
        })
        .transpose()?
        .unwrap_or_default();
    Ok(page_records(query.authority_revision, records, next_cursor))
}

fn validate_revision_window(
    query: &FederationAuthorityPageQuery,
    current_revision: Revision,
) -> Result<(), FederationAuthorityPageSourceError> {
    if query.authority_revision != current_revision {
        return Err(FederationAuthorityPageSourceError::Unavailable);
    }
    if query.after_revision > current_revision.get() {
        Err(FederationAuthorityPageSourceError::InvalidQuery)
    } else {
        Ok(())
    }
}

fn decode_cursor(
    query: &FederationAuthorityPageQuery,
) -> Result<Option<FederationAuthorityCursor>, FederationAuthorityPageSourceError> {
    if query.cursor.is_empty() {
        return Ok(None);
    }
    let cursor = FederationAuthorityCursor::from_canonical_bytes(&query.cursor)
        .map_err(|_| FederationAuthorityPageSourceError::InvalidQuery)?;
    if cursor.relationship_id() != query.relationship_id
        || cursor.after_revision() != Revision::new(query.after_revision)
        || cursor.snapshot_revision() != query.authority_revision
    {
        Err(FederationAuthorityPageSourceError::InvalidQuery)
    } else {
        Ok(Some(cursor))
    }
}

fn terminal_page(
    authority_revision: Revision,
    cursor: &[u8],
) -> Result<FederationAuthorityPageRecords, FederationAuthorityPageSourceError> {
    if cursor.is_empty() {
        Ok(page_records(authority_revision, Vec::new(), Vec::new()))
    } else {
        Err(FederationAuthorityPageSourceError::InvalidQuery)
    }
}

fn page_cursor(
    query: &FederationAuthorityPageQuery,
    grant_cursor: Option<meshspan_metadata::FederationGrantCursor>,
) -> Result<FederationAuthorityCursor, FederationAuthorityPageSourceError> {
    FederationAuthorityCursor::new(
        query.relationship_id,
        Revision::new(query.after_revision),
        query.authority_revision,
        grant_cursor,
    )
    .map_err(|_| FederationAuthorityPageSourceError::Corrupt)
}

fn query_limit(value: u32) -> Result<usize, FederationAuthorityPageSourceError> {
    let limit =
        usize::try_from(value).map_err(|_| FederationAuthorityPageSourceError::InvalidQuery)?;
    PageLimit::new(limit).map_err(|_| FederationAuthorityPageSourceError::InvalidQuery)?;
    Ok(limit)
}

fn map_repository_error(error: &RepositoryError) -> FederationAuthorityPageSourceError {
    match error {
        RepositoryError::StaleRevision => FederationAuthorityPageSourceError::Unavailable,
        RepositoryError::Store(_)
        | RepositoryError::Sqlite(_)
        | RepositoryError::OperationConflict
        | RepositoryError::InvalidLogPosition
        | RepositoryError::StaleVolumeHead
        | RepositoryError::StaleRetentionPolicy
        | RepositoryError::StaleAuthenticationPolicy
        | RepositoryError::StaleSnapshot
        | RepositoryError::StaleSnapshotSchedule
        | RepositoryError::StaleMetadataBackupSchedule
        | RepositoryError::InvalidCommand
        | RepositoryError::CapacityExceeded
        | RepositoryError::CorruptState
        | RepositoryError::InvalidPageLimit
        | RepositoryError::Io(_)
        | RepositoryError::BackupDestinationExists
        | RepositoryError::BackupMismatch
        | RepositoryError::EncryptedBackup(_)
        | RepositoryError::SnapshotMismatch
        | RepositoryError::InjectedFault => FederationAuthorityPageSourceError::Corrupt,
    }
}

fn versioned(canonical_bytes: Vec<u8>) -> VersionedPayload {
    VersionedPayload {
        format_version: 1,
        canonical_bytes,
    }
}

fn page_records(
    authority_revision: Revision,
    records: Vec<VersionedPayload>,
    next_cursor: Vec<u8>,
) -> FederationAuthorityPageRecords {
    FederationAuthorityPageRecords {
        authority_revision,
        records,
        next_cursor,
    }
}
