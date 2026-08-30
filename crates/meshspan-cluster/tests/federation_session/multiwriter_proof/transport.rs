// SPDX-License-Identifier: GPL-2.0-only

//! Bounded signed Quinn/Protobuf history transfer for the composed two-swarm proof.

use std::error::Error;
use std::path::Path;

use meshspan_cluster::{
    AdmittingFederationHistoryReceiver, ConsensusFederationMutationAdmissionCommitter,
    FederationBranchPageServeRequest, FederationBranchPageServices,
    FederationHistoryObjectServeRequest, FederationHistoryObjectServices,
    FederationHistorySyncError, FederationHistorySyncOutcome, FederationHistorySyncRequest,
    FilesystemFederationHistorySource, MetadataFederationBranchAuthority,
    MetadataFederationHistoryAdmissionSource,
};
use meshspan_domain::{DurationMicros, NamespaceCommitId, PartitionId, UnixMicros};
use meshspan_filesystem::{NamespaceHistoryLimits, VersionPublicationStore};
use meshspan_protocol::v1::ProtocolVersion;
use meshspan_transport::{FederationExchangeContext, FederationReplayGuard, TransportError};

use super::super::SessionProof;
use super::SYNC_NOW;
use super::metadata::{DatabaseCommitSubmitter, FederationFixture};

const OWNER_PARTITION_SEED: u8 = 20;

pub(super) async fn sync_history(
    proof: &SessionProof<'_>,
    federation: &FederationFixture,
    source_directory: &Path,
    owner_directory: &Path,
    requested_head: NamespaceCommitId,
    known_commits: Vec<NamespaceCommitId>,
    seed: u8,
) -> Result<(), Box<dyn Error>> {
    let source_store = VersionPublicationStore::open(source_directory, SYNC_NOW)?;
    let bundle = source_store.export_namespace_history(
        federation.volume,
        &[requested_head],
        &known_commits,
        NamespaceHistoryLimits::DEFAULT,
    )?;
    let immutable_count = bundle.immutable_record_count();
    drop(source_store);

    let source = FilesystemFederationHistorySource::new(source_directory);
    let partition_id = PartitionId::from_bytes([OWNER_PARTITION_SEED; 16])?;
    let submitter = DatabaseCommitSubmitter::new(&federation.owner_database_path, partition_id);
    let receiver = AdmittingFederationHistoryReceiver::new(
        FilesystemFederationHistorySource::new(owner_directory),
        MetadataFederationHistoryAdmissionSource::new(
            &federation.owner_database_path,
            partition_id,
        ),
        ConsensusFederationMutationAdmissionCommitter::new(
            submitter,
            federation.owner_administrator,
        ),
    );
    let owner_grants =
        MetadataFederationBranchAuthority::new(proof.client_authority, &federation.client_cache);
    let exchange_count = history_exchange_count(immutable_count)?;
    let mut owner_replay = history_replay_guard()?;
    let mut source_replay = history_replay_guard()?;
    let sync = proof.client_runtime.sync_federated_history(
        proof.client_connection,
        proof.client_authority,
        &owner_grants,
        &receiver,
        FederationHistorySyncRequest {
            session_id: [seed; 32],
            relationship_id: federation.relationship,
            grant_id: federation.grant,
            resource: federation.resource(),
            requested_heads: vec![requested_head],
            known_commits,
            limits: NamespaceHistoryLimits::DEFAULT,
            page_limit: 1,
            exchange_contexts: (0..exchange_count)
                .map(|index| exchange_context(seed, index))
                .collect::<Result<Vec<_>, _>>()?,
            now: SYNC_NOW,
            expires_at: UnixMicros::new(2_000_000),
        },
        &mut owner_replay,
    );
    let serve = serve_history(
        proof,
        federation,
        &source,
        immutable_count,
        seed,
        &mut source_replay,
    );
    let labelled_sync = async {
        sync.await
            .map_err(|error| format!("history receiver: {error:?}"))
    };
    let labelled_serve = async {
        serve
            .await
            .map_err(|error| format!("history source: {error:?}"))
    };
    let (outcome, ()) = tokio::try_join!(labelled_sync, labelled_serve)?;
    assert!(matches!(
        outcome,
        FederationHistorySyncOutcome::Completed { objects, .. } if objects == immutable_count
    ));
    drop(receiver);
    VersionPublicationStore::open(owner_directory, UnixMicros::new(1_500_001))?;
    Ok(())
}

async fn serve_history(
    proof: &SessionProof<'_>,
    federation: &FederationFixture,
    source: &FilesystemFederationHistorySource,
    immutable_count: usize,
    seed: u8,
    replay: &mut FederationReplayGuard,
) -> Result<(), FederationHistorySyncError> {
    let source_grants =
        MetadataFederationBranchAuthority::new(proof.server_authority, &federation.server_cache);
    proof
        .server_runtime
        .serve_branch_page(
            proof.server_connection,
            FederationBranchPageServices::new(proof.server_authority, &source_grants, source),
            FederationBranchPageServeRequest {
                response_replay_nonce: exchange_nonce(seed, 0, 5),
                now: SYNC_NOW,
            },
            replay,
        )
        .await
        .map_err(FederationHistorySyncError::from)?;
    for index in 0..immutable_count {
        serve_history_object(proof, &source_grants, source, seed, index, replay).await?;
    }
    Ok(())
}

async fn serve_history_object(
    proof: &SessionProof<'_>,
    source_grants: &MetadataFederationBranchAuthority<'_>,
    source: &FilesystemFederationHistorySource,
    seed: u8,
    index: usize,
    replay: &mut FederationReplayGuard,
) -> Result<(), FederationHistorySyncError> {
    proof
        .server_runtime
        .serve_branch_page(
            proof.server_connection,
            FederationBranchPageServices::new(proof.server_authority, source_grants, source),
            FederationBranchPageServeRequest {
                response_replay_nonce: exchange_nonce(seed, index, 6),
                now: SYNC_NOW,
            },
            replay,
        )
        .await
        .map_err(FederationHistorySyncError::from)?;
    proof
        .server_runtime
        .serve_history_object(
            proof.server_connection,
            FederationHistoryObjectServices::new(proof.server_authority, source_grants, source),
            FederationHistoryObjectServeRequest {
                response_replay_nonce: exchange_nonce(seed, index, 7),
                now: SYNC_NOW,
            },
            replay,
        )
        .await
        .map_err(FederationHistorySyncError::from)?;
    Ok(())
}

fn history_exchange_count(immutable_count: usize) -> Result<usize, Box<dyn Error>> {
    immutable_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| "history exchange count overflow".into())
}

fn exchange_context(seed: u8, index: usize) -> Result<FederationExchangeContext, TransportError> {
    FederationExchangeContext::new(
        ProtocolVersion { major: 1, minor: 1 },
        exchange_id(seed, index, 1),
        exchange_id(seed, index, 2),
        exchange_id(seed, index, 3),
        UnixMicros::new(2_000_000),
        exchange_nonce(seed, index, 4),
    )
}

fn exchange_id(seed: u8, index: usize, kind: u8) -> [u8; 16] {
    let mut value = [0; 16];
    value[0] = seed;
    value[1] = kind;
    value[8..].copy_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_be_bytes());
    value
}

fn exchange_nonce(seed: u8, index: usize, kind: u8) -> [u8; 32] {
    let mut value = [0; 32];
    value[0] = seed;
    value[1] = kind;
    value[24..].copy_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_be_bytes());
    value
}

fn history_replay_guard() -> Result<FederationReplayGuard, TransportError> {
    FederationReplayGuard::new(4_096, DurationMicros::new(1_000_000))
}
