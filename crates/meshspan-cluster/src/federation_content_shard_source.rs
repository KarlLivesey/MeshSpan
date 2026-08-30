// SPDX-License-Identifier: GPL-2.0-only

//! Source boundary for one already-authorised immutable encrypted content shard.

use std::future::Future;
use std::pin::Pin;

use meshspan_contracts::{BoundedBytes, ShardIdentity};
use meshspan_domain::{
    ContentManifestId, FederationResourceScope, NodeId, OperationId, TargetId, UnixMicros,
};
use thiserror::Error;

use crate::EffectiveFederationGrantAuthority;

/// Exact authority, namespace evidence and provider receipt selected before shard IO.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationContentShardQuery {
    /// Current bilateral namespace-read authority.
    pub authority: EffectiveFederationGrantAuthority,
    /// Exact shared namespace resource which advertised the manifest.
    pub resource: FederationResourceScope,
    /// Immutable manifest selected by the authorised history record.
    pub manifest_id: ContentManifestId,
    /// Live source export which advertised the manifest record.
    pub export_token: [u8; 32],
    /// Exact immutable manifest-record digest in that export.
    pub manifest_object_digest: [u8; 32],
    /// Exact source node advertised for this target incarnation.
    pub provider_node_id: NodeId,
    /// Exact provider target selected by the committed source receipt.
    pub target_id: TargetId,
    /// Exact provider target incarnation fence.
    pub target_generation: u64,
    /// Exact immutable encrypted shard generation.
    pub shard: ShardIdentity,
    /// Exact journal-confirmed encrypted byte length.
    pub expected_length: u64,
    /// Exact journal-confirmed encrypted byte digest.
    pub expected_digest: [u8; 32],
    /// Idempotent remote read operation identity.
    pub operation_id: OperationId,
    /// Exclusive signed request deadline.
    pub deadline: UnixMicros,
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Provider-verified encrypted bytes returned only after all namespace and receipt evidence agrees.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationContentShard {
    /// Exact bounded encrypted bytes; no volume or content key crosses this boundary.
    pub bytes: BoundedBytes,
}

/// Source which is unreachable until mTLS, signature, replay and bilateral grant admission pass.
pub trait FederationContentShardSource: Send + Sync {
    /// Proves one shard belongs to the advertised committed manifest and reads its exact bytes.
    fn content_shard(&self, query: FederationContentShardQuery)
    -> FederationContentShardFuture<'_>;
}

/// Asynchronous source lookup which may dispatch blocking SQLite and provider work.
pub type FederationContentShardFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<FederationContentShard, FederationContentShardSourceError>>
            + Send
            + 'a,
    >,
>;

/// Deliberately non-diagnostic failures safe across an autonomous-swarm boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FederationContentShardSourceError {
    /// Authority, export, manifest, route, receipt or byte bound was not exact.
    #[error("federation content shard query is invalid")]
    InvalidQuery,
    /// Required namespace, catalogue or provider state is temporarily unavailable.
    #[error("federation content shard is unavailable")]
    Unavailable,
    /// Advertised, committed or physical byte evidence disagrees.
    #[error("federation content shard evidence is corrupt")]
    Corrupt,
}
