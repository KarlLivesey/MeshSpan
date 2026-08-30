// SPDX-License-Identifier: GPL-2.0-only

//! Filesystem-backed federated content-layout paging on a designated blocking worker.

use std::path::{Path, PathBuf};

use meshspan_filesystem::{
    ContentCatalogError, DurableContentCatalog, NamespaceHistoryImmutableKind,
    NamespaceHistoryObjectRequest, PublicationError, VersionPublicationStore,
};

use crate::federation_branch_page_source::grant_allows_history_read;
use crate::federation_filesystem_history::authority_binding;
use crate::{
    FederationContentLayoutFuture, FederationContentLayoutQuery, FederationContentLayoutRecords,
    FederationContentLayoutSource, FederationContentLayoutSourceError,
};

/// Opens daemon-owned namespace and content catalogues per request after external admission.
#[derive(Clone, Debug)]
pub struct FilesystemFederationContentSource {
    state_directory: PathBuf,
}

impl FilesystemFederationContentSource {
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

impl FederationContentLayoutSource for FilesystemFederationContentSource {
    fn content_layout(
        &self,
        query: FederationContentLayoutQuery,
    ) -> FederationContentLayoutFuture<'_> {
        let state_directory = self.state_directory.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || load_layout(&state_directory, &query))
                .await
                .map_err(|_| FederationContentLayoutSourceError::Unavailable)?
        })
    }
}

fn load_layout(
    state_directory: &Path,
    query: &FederationContentLayoutQuery,
) -> Result<FederationContentLayoutRecords, FederationContentLayoutSourceError> {
    validate_query(query)?;
    let namespace = VersionPublicationStore::open(state_directory, query.now)
        .map_err(|error| map_publication_error(&error))?;
    let advertised = namespace
        .namespace_history_object(NamespaceHistoryObjectRequest {
            scope_binding: authority_binding(query.authority, query.resource),
            export_token: query.export_token,
            object_digest: query.manifest_object_digest,
            now: query.now,
        })
        .map_err(|error| map_publication_error(&error))?;
    if advertised.kind() != NamespaceHistoryImmutableKind::Manifest {
        return Err(FederationContentLayoutSourceError::InvalidQuery);
    }
    let advertised_manifest = advertised
        .as_manifest()
        .map_err(|_| FederationContentLayoutSourceError::Corrupt)?
        .ok_or(FederationContentLayoutSourceError::Corrupt)?;
    if advertised_manifest.manifest_id != query.manifest_id {
        return Err(FederationContentLayoutSourceError::InvalidQuery);
    }

    let catalog = DurableContentCatalog::open(state_directory, query.now)
        .map_err(|error| map_catalog_error(&error))?;
    let content = catalog
        .committed_content_by_manifest(query.manifest_id)
        .map_err(|error| map_catalog_error(&error))?
        .ok_or(FederationContentLayoutSourceError::Unavailable)?;
    if content.manifest != advertised_manifest {
        return Err(FederationContentLayoutSourceError::Corrupt);
    }
    let transfer = catalog
        .committed_layout_transfer(content)
        .map_err(|error| map_catalog_error(&error))?;
    let header = transfer.header();
    let page = if header.chunk_count == 0 {
        if query.after_index.is_some() {
            return Err(FederationContentLayoutSourceError::InvalidQuery);
        }
        None
    } else {
        Some(
            transfer
                .page(query.after_index, query.limit)
                .map_err(|error| map_catalog_error(&error))?,
        )
    };
    Ok(FederationContentLayoutRecords { header, page })
}

fn validate_query(
    query: &FederationContentLayoutQuery,
) -> Result<(), FederationContentLayoutSourceError> {
    let grant = query.authority.grant;
    if grant.resource() != query.resource
        || !grant_allows_history_read(query.authority)
        || query.now < grant.valid_from()
        || grant
            .valid_until()
            .is_some_and(|expiry| query.now >= expiry)
        || query.limit == 0
    {
        Err(FederationContentLayoutSourceError::InvalidQuery)
    } else {
        Ok(())
    }
}

const fn map_publication_error(error: &PublicationError) -> FederationContentLayoutSourceError {
    match error {
        PublicationError::InvalidInput => FederationContentLayoutSourceError::InvalidQuery,
        PublicationError::Io(_) | PublicationError::Sqlite(_) | PublicationError::InjectedFault => {
            FederationContentLayoutSourceError::Unavailable
        }
        PublicationError::StaleHead
        | PublicationError::OperationConflict
        | PublicationError::CleanupFenced
        | PublicationError::Corrupt
        | PublicationError::Directory(_) => FederationContentLayoutSourceError::Corrupt,
    }
}

const fn map_catalog_error(error: &ContentCatalogError) -> FederationContentLayoutSourceError {
    match error {
        ContentCatalogError::InvalidInput | ContentCatalogError::Conflict => {
            FederationContentLayoutSourceError::InvalidQuery
        }
        ContentCatalogError::Incomplete
        | ContentCatalogError::Io(_)
        | ContentCatalogError::Sqlite(_) => FederationContentLayoutSourceError::Unavailable,
        ContentCatalogError::Corrupt => FederationContentLayoutSourceError::Corrupt,
    }
}
