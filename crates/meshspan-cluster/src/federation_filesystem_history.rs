// SPDX-License-Identifier: GPL-2.0-only

//! Filesystem-backed federated history paging on a designated blocking worker.

use std::path::{Path, PathBuf};

use meshspan_domain::{DurationMicros, FederationResourceScope, UnixMicros, VolumeId};
use meshspan_filesystem::{NamespaceHistoryPageRequest, PublicationError, VersionPublicationStore};
use meshspan_protocol::v1::VersionedPayload;
use sha2::{Digest, Sha256};

use crate::federation_branch_page_source::grant_allows_history_read;
use crate::federation_resource_wire::version_federation_resource_scope;
use crate::{
    EffectiveFederationGrantAuthority, FederationBranchPageFuture, FederationBranchPageQuery,
    FederationBranchPageRecords, FederationBranchPageSource, FederationBranchPageSourceError,
};

const HISTORY_RECORD_FORMAT_VERSION: u32 = 1;
const EXPORT_SESSION_LIFETIME: DurationMicros = DurationMicros::new(60 * 60 * 1_000_000);
const AUTHORITY_BINDING_DOMAIN: &[u8] = b"meshspan.federation.history-authority.v1\0";

/// Opens the local branch database per request and exports only already-authorised history.
#[derive(Clone, Debug)]
pub struct FilesystemFederationHistorySource {
    state_directory: PathBuf,
}

impl FilesystemFederationHistorySource {
    /// Selects the daemon-owned filesystem state directory.
    #[must_use]
    pub fn new(state_directory: impl Into<PathBuf>) -> Self {
        Self {
            state_directory: state_directory.into(),
        }
    }

    /// Returns the selected daemon-owned state directory.
    #[must_use]
    pub fn state_directory(&self) -> &Path {
        &self.state_directory
    }
}

impl FederationBranchPageSource for FilesystemFederationHistorySource {
    fn branch_page(&self, query: FederationBranchPageQuery) -> FederationBranchPageFuture<'_> {
        let state_directory = self.state_directory.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || load_page(&state_directory, query))
                .await
                .map_err(|_| FederationBranchPageSourceError::Unavailable)?
        })
    }
}

fn load_page(
    state_directory: &Path,
    query: FederationBranchPageQuery,
) -> Result<FederationBranchPageRecords, FederationBranchPageSourceError> {
    validate_authority(query.authority, query.resource, query.now)?;
    let volume_id = volume_scope(query.resource)?;
    let expires_at = export_expiry(query.authority, query.now)?;
    let mut store = VersionPublicationStore::open(state_directory, query.now)
        .map_err(|error| map_publication_error(&error))?;
    let page = store
        .namespace_history_page(NamespaceHistoryPageRequest {
            scope_binding: authority_binding(query.authority, query.resource),
            volume_id,
            requested_heads: query.requested_heads,
            known_commits: query.known_commits,
            cursor: query.cursor,
            limit: usize::try_from(query.limit)
                .map_err(|_| FederationBranchPageSourceError::InvalidQuery)?,
            now: query.now,
            expires_at,
        })
        .map_err(|error| map_publication_error(&error))?;
    Ok(FederationBranchPageRecords {
        branch_commits: page
            .commits
            .into_iter()
            .map(|record| VersionedPayload {
                format_version: HISTORY_RECORD_FORMAT_VERSION,
                canonical_bytes: record.canonical_bytes().to_vec(),
            })
            .collect(),
        immutable_object_digests: page.immutable_object_digests,
        next_cursor: page.next_cursor,
    })
}

fn validate_authority(
    authority: EffectiveFederationGrantAuthority,
    resource: FederationResourceScope,
    now: UnixMicros,
) -> Result<(), FederationBranchPageSourceError> {
    let grant = authority.grant;
    if grant.resource() != resource
        || !grant_allows_history_read(authority)
        || now < grant.valid_from()
        || grant.valid_until().is_some_and(|expiry| now >= expiry)
    {
        Err(FederationBranchPageSourceError::InvalidQuery)
    } else {
        Ok(())
    }
}

fn volume_scope(
    resource: FederationResourceScope,
) -> Result<VolumeId, FederationBranchPageSourceError> {
    match resource {
        FederationResourceScope::Volume { volume_id, .. } => Ok(volume_id),
        FederationResourceScope::Subtree { .. }
        | FederationResourceScope::File { .. }
        | FederationResourceScope::StorageCapacity { .. } => {
            Err(FederationBranchPageSourceError::Unavailable)
        }
    }
}

fn export_expiry(
    authority: EffectiveFederationGrantAuthority,
    now: UnixMicros,
) -> Result<UnixMicros, FederationBranchPageSourceError> {
    let session_expiry = now
        .checked_add(EXPORT_SESSION_LIFETIME)
        .ok_or(FederationBranchPageSourceError::InvalidQuery)?;
    let expiry = authority
        .grant
        .valid_until()
        .map_or(session_expiry, |grant_expiry| {
            grant_expiry.min(session_expiry)
        });
    if expiry <= now {
        Err(FederationBranchPageSourceError::InvalidQuery)
    } else {
        Ok(expiry)
    }
}

fn authority_binding(
    authority: EffectiveFederationGrantAuthority,
    resource: FederationResourceScope,
) -> [u8; 32] {
    let grant = authority.grant;
    let subject = grant.subject();
    let scope = version_federation_resource_scope(resource);
    let mut digest = Sha256::new();
    digest.update(AUTHORITY_BINDING_DOMAIN);
    digest.update(grant.grant_id().as_bytes());
    digest.update(grant.relationship_id().as_bytes());
    digest.update(subject.home_mesh_id().as_bytes());
    digest.update(subject.principal_id().as_bytes());
    digest.update(grant.authority_epoch().to_be_bytes());
    digest.update(grant.valid_from().get().to_be_bytes());
    update_optional_time(&mut digest, grant.valid_until());
    digest.update(authority.local_authority_revision.get().to_be_bytes());
    digest.update(authority.local_grant_revision.get().to_be_bytes());
    digest.update(authority.remote_authority_revision.get().to_be_bytes());
    digest.update(authority.remote_grant_revision.get().to_be_bytes());
    digest.update(scope.format_version.to_be_bytes());
    digest.update(scope.canonical_bytes);
    digest.finalize().into()
}

fn update_optional_time(digest: &mut Sha256, value: Option<UnixMicros>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.get().to_be_bytes());
        }
        None => digest.update([0]),
    }
}

const fn map_publication_error(error: &PublicationError) -> FederationBranchPageSourceError {
    match error {
        PublicationError::InvalidInput => FederationBranchPageSourceError::InvalidQuery,
        PublicationError::Io(_) | PublicationError::Sqlite(_) | PublicationError::InjectedFault => {
            FederationBranchPageSourceError::Unavailable
        }
        PublicationError::StaleHead
        | PublicationError::OperationConflict
        | PublicationError::CleanupFenced
        | PublicationError::Corrupt
        | PublicationError::Directory(_) => FederationBranchPageSourceError::Corrupt,
    }
}

#[cfg(test)]
#[path = "federation_filesystem_history_tests.rs"]
mod tests;
