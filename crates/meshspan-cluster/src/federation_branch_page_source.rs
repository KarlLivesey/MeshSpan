// SPDX-License-Identifier: GPL-2.0-only

//! Narrow, bounded source boundary for already-authorised federated history pages.

use std::future::Future;
use std::pin::Pin;

use meshspan_domain::{FederationResourceScope, NamespaceCommitId, Rights, UnixMicros};
use meshspan_protocol::v1::VersionedPayload;
use thiserror::Error;

use crate::EffectiveFederationGrantAuthority;

/// Typed query passed to storage only after transport and bilateral authority admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationBranchPageQuery {
    /// Exact current authority, including independent local and remote revision receipts.
    pub authority: EffectiveFederationGrantAuthority,
    /// Exact typed resource selected by both the request and grant.
    pub resource: FederationResourceScope,
    /// Exact source heads whose missing causal history is requested.
    pub requested_heads: Vec<NamespaceCommitId>,
    /// Bounded commit identities the requester already holds.
    pub known_commits: Vec<NamespaceCommitId>,
    /// Opaque continuation previously returned by this source.
    pub cursor: Vec<u8>,
    /// Positive maximum combined commit/object records requested for this page.
    pub limit: u32,
    /// Current authoritative mesh time used for the durable export lifetime.
    pub now: UnixMicros,
}

/// Canonical branch commit records and referenced immutable object identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationBranchPageRecords {
    /// Stable source-side export identity used to fetch advertised immutable bodies.
    pub export_token: [u8; 32],
    /// Independently versioned immutable history records.
    pub branch_commits: Vec<VersionedPayload>,
    /// Content identities whose bytes travel separately over bounded data streams.
    pub immutable_object_digests: Vec<[u8; 32]>,
    /// Opaque continuation, empty only when the history page is terminal.
    pub next_cursor: Vec<u8>,
}

/// Read boundary which cannot be reached with an unauthenticated or unauthorised request.
pub trait FederationBranchPageSource: Send + Sync {
    /// Produces one stable bounded page for an already-authorised exact resource.
    ///
    /// # Errors
    ///
    /// Fails closed for forged cursors, unavailable history or corrupt immutable records.
    fn branch_page(&self, query: FederationBranchPageQuery) -> FederationBranchPageFuture<'_>;
}

/// Asynchronous page lookup which may use a designated blocking persistence worker.
pub type FederationBranchPageFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<FederationBranchPageRecords, FederationBranchPageSourceError>>
            + Send
            + 'a,
    >,
>;

/// Deliberately non-diagnostic source failures safe across the service boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FederationBranchPageSourceError {
    /// Cursor or page bounds did not identify one valid stable query.
    #[error("federation branch page query is invalid")]
    InvalidQuery,
    /// Requested immutable history is not currently available.
    #[error("federation branch history is unavailable")]
    Unavailable,
    /// Persisted or generated history failed integrity validation.
    #[error("federation branch history is corrupt")]
    Corrupt,
}

pub(crate) fn grant_allows_history_read(authority: &EffectiveFederationGrantAuthority) -> bool {
    match authority.grant.policy() {
        meshspan_domain::FederationPolicy::Namespace(policy) => {
            policy.access().rights().contains(Rights::READ_DATA)
        }
        meshspan_domain::FederationPolicy::Storage(_) => false,
    }
}
