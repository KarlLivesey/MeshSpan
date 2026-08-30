// SPDX-License-Identifier: GPL-2.0-only

//! Destination-side composition of authenticated federation reads into durable local healing.

use meshspan_contracts::StorageProvider;
use meshspan_domain::{RandomSource, UnixMicros};
use meshspan_filesystem::{
    ContentPublicationError, ContentPublicationRequest, UnprotectedContentPublisher,
};
use meshspan_transport::FederationReplayGuard;
use thiserror::Error;

use crate::{
    FederationContentShardFetchRequest, FederationContentShardFetchServices,
    FederationSessionError, FederationSessionRuntime,
};

/// Exact remote fetch and receiver-local recovery journal operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationContentHealingRequest {
    /// Export-bound source shard request.
    pub remote: FederationContentShardFetchRequest,
    /// Receiver-local durable recovery operation.
    pub local: ContentPublicationRequest,
}

/// Success only after exact encrypted bytes have a destination-local provider receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HealedFederationContentShard {
    /// Logical chunk index durably installed at the destination.
    pub chunk_index: u64,
    /// Exact encrypted byte count verified on both source and destination.
    pub byte_count: usize,
    /// Source provider's signed service instant.
    pub source_served_at: UnixMicros,
}

/// Fail-closed federation transport or receiver-local recovery failure.
#[derive(Debug, Error)]
pub enum FederationContentHealingError {
    /// Remote and local operations did not name the same immutable manifest.
    #[error("federated content healing request is inconsistent")]
    InvalidRequest,
    /// Relationship, grant, transport, framing or source evidence failed.
    #[error("federated content shard fetch failed")]
    Federation(#[from] FederationSessionError),
    /// Destination key, layout, provider or durable receipt validation failed.
    #[error("federated content shard could not be installed locally")]
    Filesystem(#[from] ContentPublicationError),
}

/// Fetches one encrypted shard and returns only after destination-local durable installation.
///
/// # Errors
///
/// Rejects manifest mismatch, remote authority/data failure and every local recovery contradiction.
pub async fn heal_federated_content_shard<P, R>(
    runtime: &FederationSessionRuntime<'_>,
    connection: &quinn::Connection,
    services: FederationContentShardFetchServices<'_>,
    replay: &mut FederationReplayGuard,
    receiver: &mut UnprotectedContentPublisher<P, R>,
    request: FederationContentHealingRequest,
) -> Result<HealedFederationContentShard, FederationContentHealingError>
where
    P: StorageProvider,
    R: RandomSource,
{
    if request.remote.manifest_id != request.local.manifest_id {
        return Err(FederationContentHealingError::InvalidRequest);
    }
    let chunk_index = request.remote.shard.stripe_index;
    let fetched_shard = runtime
        .fetch_content_shard(connection, services, request.remote, replay)
        .await?;
    let byte_count = fetched_shard.bytes.len();
    receiver.store_recovered_content_chunk(request.local, chunk_index, fetched_shard.bytes)?;
    Ok(HealedFederationContentShard {
        chunk_index,
        byte_count,
        source_served_at: fetched_shard.served_at,
    })
}
