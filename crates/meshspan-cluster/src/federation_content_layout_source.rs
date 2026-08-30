// SPDX-License-Identifier: GPL-2.0-only

//! Narrow source boundary for already-authorised portable encrypted-content layouts.

use std::future::Future;
use std::pin::Pin;

use meshspan_domain::{ContentManifestId, FederationResourceScope, UnixMicros};
use meshspan_filesystem::{ContentLayoutTransferHeader, ContentLayoutTransferPage};
use thiserror::Error;

use crate::EffectiveFederationGrantAuthority;

/// Exact authority and export evidence admitted before content-catalogue lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationContentLayoutQuery {
    /// Current bilateral namespace authority.
    pub authority: EffectiveFederationGrantAuthority,
    /// Exact namespace resource which advertised the manifest.
    pub resource: FederationResourceScope,
    /// Immutable manifest identity selected by the requester.
    pub manifest_id: ContentManifestId,
    /// Live source export which advertised the manifest object.
    pub export_token: [u8; 32],
    /// Exact advertised immutable manifest-object digest.
    pub manifest_object_digest: [u8; 32],
    /// Last chunk index returned by the same immutable layout, or no cursor initially.
    pub after_index: Option<u64>,
    /// Positive maximum chunk identities requested.
    pub limit: usize,
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Source-verified portable layout page before connection-bound key wrapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationContentLayoutRecords {
    /// Immutable layout geometry with the source-local wrapped content key.
    pub header: ContentLayoutTransferHeader,
    /// Bounded provider-neutral identities, absent only for a valid empty file.
    pub page: Option<ContentLayoutTransferPage>,
}

/// Source which cannot be reached before mTLS, signature and bilateral grant admission.
pub trait FederationContentLayoutSource: Send + Sync {
    /// Proves the manifest belongs to the live authorised export and loads a stable page.
    fn content_layout(
        &self,
        query: FederationContentLayoutQuery,
    ) -> FederationContentLayoutFuture<'_>;
}

/// Asynchronous source lookup which may dispatch blocking SQLite work.
pub type FederationContentLayoutFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<FederationContentLayoutRecords, FederationContentLayoutSourceError>,
            > + Send
            + 'a,
    >,
>;

/// Deliberately non-diagnostic source failures safe across the federation boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FederationContentLayoutSourceError {
    /// Authority, export proof, cursor or page bound was invalid.
    #[error("federation content layout query is invalid")]
    InvalidQuery,
    /// The namespace export or committed content catalogue is temporarily unavailable.
    #[error("federation content layout is unavailable")]
    Unavailable,
    /// Advertised namespace and committed content evidence disagree or are corrupt.
    #[error("federation content layout evidence is corrupt")]
    Corrupt,
}
