// SPDX-License-Identifier: GPL-2.0-only

//! Narrow source boundary for one already-authorised advertised immutable history body.

use std::future::Future;
use std::pin::Pin;

use meshspan_domain::{FederationResourceScope, UnixMicros};
use thiserror::Error;

use crate::EffectiveFederationGrantAuthority;

/// Exact authority and signed export identity admitted before local body lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationHistoryObjectQuery {
    /// Current bilateral grant authority.
    pub authority: EffectiveFederationGrantAuthority,
    /// Exact typed resource selected by request and grant.
    pub resource: FederationResourceScope,
    /// Signed source-side export identity.
    pub export_token: [u8; 32],
    /// Exact immutable digest advertised by the export.
    pub object_digest: [u8; 32],
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Canonical immutable body whose digest was revalidated by its source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationHistoryObject {
    /// Exact domain-separated canonical bytes.
    pub canonical_bytes: Vec<u8>,
}

/// Source which cannot be reached before transport and bilateral authority admission.
pub trait FederationHistoryObjectSource: Send + Sync {
    /// Loads one exact advertised body without blocking an async executor worker.
    fn history_object(
        &self,
        query: FederationHistoryObjectQuery,
    ) -> FederationHistoryObjectFuture<'_>;
}

/// Asynchronous immutable-body lookup.
pub type FederationHistoryObjectFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<FederationHistoryObject, FederationHistoryObjectSourceError>>
            + Send
            + 'a,
    >,
>;

/// Deliberately non-diagnostic source failures safe across the service boundary.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FederationHistoryObjectSourceError {
    /// Authority, token or digest did not select one valid advertised body.
    #[error("federation history object query is invalid")]
    InvalidQuery,
    /// The selected history database is temporarily unavailable.
    #[error("federation history object is unavailable")]
    Unavailable,
    /// The persisted or regenerated body failed integrity validation.
    #[error("federation history object is corrupt")]
    Corrupt,
}
