// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable verified immutable-content read boundary used by file reads and `CoW` overlays.

use std::io::Write;

use meshspan_domain::{OperationId, Revision, UnixMicros};
use thiserror::Error;

use crate::ManifestPublication;

/// Immutable branch-to-content-catalogue reference for one published file version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedContentReference {
    /// Original content-publication operation that owns the durable catalogue layout.
    pub publication_operation_id: OperationId,
    /// Independently revalidated immutable manifest.
    pub manifest: ManifestPublication,
}

/// Exact bounded range request against one immutable published content reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentReadRequest {
    /// Stable identity for this read attempt and its provider permits.
    pub operation_id: OperationId,
    /// Immutable content being read.
    pub content: PublishedContentReference,
    /// First logical byte requested.
    pub offset: u64,
    /// Exact number of bytes requested.
    pub length: u64,
    /// Current authority revision admitting the read.
    pub authorization_revision: Revision,
    /// Exclusive provider-work deadline.
    pub deadline: UnixMicros,
    /// Authoritative attempt instant.
    pub observed_at: UnixMicros,
}

/// Replaceable boundary that streams an independently verified immutable byte range.
pub trait DurableContentReader {
    /// Writes exactly the requested bytes to `destination` or returns an explicit failure.
    ///
    /// # Errors
    ///
    /// Rejects malformed ranges, stale authority, unavailable/corrupt shards, manifest mismatch
    /// and destination IO failure. Success is allowed only after all returned bytes verify.
    fn stream_range(
        &mut self,
        request: ContentReadRequest,
        destination: &mut dyn Write,
    ) -> Result<(), ContentReadError>;
}

/// Stable immutable-content read failures.
#[derive(Debug, Error)]
pub enum ContentReadError {
    /// Range, time, revision or identity input is malformed.
    #[error("content read input is invalid")]
    InvalidInput,
    /// A durable operation or immutable identity conflicts with the request.
    #[error("content read identity conflicts with durable state")]
    Conflict,
    /// Manifest, layout, shard or plaintext evidence is corrupt.
    #[error("content read evidence is corrupt")]
    Corrupt,
    /// Required authority or verified storage is temporarily unavailable.
    #[error("content read is unavailable")]
    Unavailable,
    /// Destination or private content IO failed.
    #[error("content read IO failed")]
    Io(#[from] std::io::Error),
}
