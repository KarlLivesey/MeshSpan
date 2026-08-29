// SPDX-License-Identifier: GPL-2.0-only

//! Narrow, bounded source boundary for already-authorised federated history pages.

use meshspan_domain::{FederationResourceScope, Rights};
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
    /// Bounded content identities the requester already holds.
    pub causal_frontier: Vec<[u8; 32]>,
    /// Opaque continuation previously returned by this source.
    pub cursor: Vec<u8>,
    /// Positive maximum combined commit/object records requested for this page.
    pub limit: u32,
}

/// Canonical branch commit records and referenced immutable object identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationBranchPageRecords {
    /// Independently versioned immutable history records.
    pub branch_commits: Vec<VersionedPayload>,
    /// Content identities whose bytes travel separately over bounded data streams.
    pub immutable_object_digests: Vec<[u8; 32]>,
    /// Opaque continuation, empty only when the history page is terminal.
    pub next_cursor: Vec<u8>,
}

/// Read boundary which cannot be reached with an unauthenticated or unauthorised request.
pub trait FederationBranchPageSource {
    /// Produces one stable bounded page for an already-authorised exact resource.
    ///
    /// # Errors
    ///
    /// Fails closed for forged cursors, unavailable history or corrupt immutable records.
    fn branch_page(
        &self,
        query: FederationBranchPageQuery,
    ) -> Result<FederationBranchPageRecords, FederationBranchPageSourceError>;
}

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

pub(crate) fn grant_allows_history_read(authority: EffectiveFederationGrantAuthority) -> bool {
    match authority.grant.policy() {
        meshspan_domain::FederationPolicy::Namespace(policy) => {
            policy.access().rights().contains(Rights::READ_DATA)
        }
        meshspan_domain::FederationPolicy::Storage(_) => false,
    }
}
