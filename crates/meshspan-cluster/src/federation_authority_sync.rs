// SPDX-License-Identifier: GPL-2.0-only

//! Complete bounded remote-authority synchronisation over authenticated Quinn pages.

use meshspan_domain::{FederationRelationshipId, Revision, UnixMicros};
use meshspan_metadata::{
    FederationRemoteAuthorityCacheDisposition, FederationRemoteAuthorityCacheError, LocalDatabase,
};
use meshspan_transport::{FederationExchangeContext, FederationReplayGuard};
use thiserror::Error;

use crate::federation_session::load_authority;
use crate::{
    FederationAuthorityFetchRequest, FederationAuthorityImportError,
    FederationAuthorityImportLimits, FederationAuthoritySource, FederationAuthorityUpdate,
    FederationRemoteAuthoritySnapshotReceiver, FederationSessionError, FederationSessionRuntime,
};

const MAXIMUM_SYNC_CONTEXTS: usize = 4_096;

/// Complete pre-generated request material and bounds for one authority synchronisation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationAuthoritySyncRequest {
    relationship_id: FederationRelationshipId,
    page_contexts: Vec<FederationExchangeContext>,
    page_limit: u32,
    import_limits: FederationAuthorityImportLimits,
    now: UnixMicros,
}

impl FederationAuthoritySyncRequest {
    /// Constructs one bounded sync request with fresh signed context for every permitted page.
    ///
    /// # Errors
    ///
    /// Rejects empty or excessive context sets and a zero page size.
    pub fn new(
        relationship_id: FederationRelationshipId,
        page_contexts: Vec<FederationExchangeContext>,
        page_limit: u32,
        import_limits: FederationAuthorityImportLimits,
        now: UnixMicros,
    ) -> Result<Self, FederationAuthoritySyncError> {
        if page_contexts.is_empty()
            || page_contexts.len() > MAXIMUM_SYNC_CONTEXTS
            || page_contexts.len() > import_limits.maximum_pages()
            || page_limit == 0
        {
            return Err(FederationAuthoritySyncError::InvalidRequest);
        }
        Ok(Self {
            relationship_id,
            page_contexts,
            page_limit,
            import_limits,
            now,
        })
    }
}

/// Durable result of one complete remote-authority synchronisation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationAuthoritySyncOutcome {
    /// The authenticated peer confirmed that the durable cache was already current.
    Unchanged {
        /// Confirmed peer authority revision.
        authority_revision: Revision,
        /// Authenticated pages consumed by this proof.
        pages: usize,
    },
    /// One complete authenticated update was installed atomically.
    Updated {
        /// Newly durable peer authority revision.
        authority_revision: Revision,
        /// Whether installation applied state or resolved an exact lost response.
        disposition: FederationRemoteAuthorityCacheDisposition,
        /// Authenticated pages consumed by this update.
        pages: usize,
        /// Complete canonical relationship/grant records received.
        records: usize,
    },
}

impl FederationSessionRuntime<'_> {
    /// Fetches every bounded page and atomically installs only the completed authenticated update.
    ///
    /// No database transaction is opened until the terminal page has arrived and the complete
    /// sequence has passed receiver validation.
    ///
    /// # Errors
    ///
    /// Rejects stale local authority, hostile/replayed pages, exhausted bounds, cache corruption or
    /// an incomplete context budget without exposing or persisting partial records.
    pub async fn sync_remote_authority(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        cache: &mut LocalDatabase,
        request: FederationAuthoritySyncRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<FederationAuthoritySyncOutcome, FederationAuthoritySyncError> {
        let after_revision = cache.remote_federation_authority_revision(request.relationship_id)?;
        let local = load_authority(authority, request.relationship_id, request.now)?;
        let mut receiver = FederationRemoteAuthoritySnapshotReceiver::new(
            local,
            after_revision,
            request.import_limits,
        );
        let mut cursor = Vec::new();
        let mut pages = 0_usize;
        let mut records = 0_usize;
        for context in request.page_contexts {
            let requested_cursor = cursor;
            let page = self
                .fetch_authority_page(
                    connection,
                    authority,
                    FederationAuthorityFetchRequest {
                        relationship_id: request.relationship_id,
                        context,
                        after_revision: after_revision.get(),
                        cursor: requested_cursor.clone(),
                        limit: request.page_limit,
                        now: request.now,
                    },
                    replay,
                )
                .await?;
            pages = pages
                .checked_add(1)
                .ok_or(FederationAuthoritySyncError::InvalidRequest)?;
            records = records
                .checked_add(page.records().len())
                .ok_or(FederationAuthoritySyncError::InvalidRequest)?;
            receiver.accept_page(&requested_cursor, &page)?;
            let Some(next_cursor) = receiver.next_cursor() else {
                return finish_sync(cache, receiver.finish()?, request.now, pages, records);
            };
            cursor = next_cursor.to_vec();
        }
        Err(FederationAuthoritySyncError::Incomplete)
    }
}

fn finish_sync(
    cache: &mut LocalDatabase,
    update: FederationAuthorityUpdate,
    observed_at: UnixMicros,
    pages: usize,
    records: usize,
) -> Result<FederationAuthoritySyncOutcome, FederationAuthoritySyncError> {
    match update {
        FederationAuthorityUpdate::Unchanged { authority_revision } => {
            Ok(FederationAuthoritySyncOutcome::Unchanged {
                authority_revision,
                pages,
            })
        }
        FederationAuthorityUpdate::Snapshot(snapshot) => {
            let authority_revision = snapshot.authority_revision;
            let disposition = cache.install_remote_federation_authority(&snapshot, observed_at)?;
            Ok(FederationAuthoritySyncOutcome::Updated {
                authority_revision,
                disposition,
                pages,
                records,
            })
        }
    }
}

/// Closed failures for one complete remote-authority synchronisation.
#[derive(Debug, Error)]
pub enum FederationAuthoritySyncError {
    /// Request bounds or pre-generated context material are unusable.
    #[error("federation authority sync request is invalid")]
    InvalidRequest,
    /// The supplied page-context budget ended before a terminal page.
    #[error("federation authority sync ended before a terminal page")]
    Incomplete,
    /// One signed page exchange failed.
    #[error("federation authority sync transport failed")]
    Session(#[from] FederationSessionError),
    /// The complete page sequence was malformed or exceeded its bounds.
    #[error("federation authority sync import failed")]
    Import(#[from] FederationAuthorityImportError),
    /// The local remote-observation cache was corrupt or rejected the transition.
    #[error("federation authority sync cache update failed")]
    Cache(#[from] FederationRemoteAuthorityCacheError),
}
