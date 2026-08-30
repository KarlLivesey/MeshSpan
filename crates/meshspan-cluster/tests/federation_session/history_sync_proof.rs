// SPDX-License-Identifier: GPL-2.0-only

//! Real-Quinn proof for restart-resumable durable filesystem history convergence.

use std::error::Error;

use meshspan_cluster::{
    AdmittingFederationHistoryReceiver, FederationBranchPageServeRequest,
    FederationBranchPageServices, FederationHistoryAdmissionBatch, FederationHistoryAdmissionError,
    FederationHistoryAdmissionFuture, FederationHistoryAdmissionSource,
    FederationHistoryObjectServeRequest, FederationHistoryObjectServices,
    FederationHistorySyncError, FederationHistorySyncOutcome, FederationHistorySyncRequest,
    FederationQuarantineCommitError, FederationQuarantineCommitFuture,
    FederationQuarantineCommitter, FederationQuarantineRetention,
    FilesystemFederationHistorySource,
};
use meshspan_domain::{
    DurationMicros, FederatedMutationAcknowledgement, FederatedMutationAdmission,
    FederatedMutationEvidence, FederatedPrincipal, MeshId, Rights, UnixMicros,
};
use meshspan_filesystem::{
    NamespaceHistoryCommitRecord, NamespaceHistoryLimits, NamespaceHistoryMutationDecision,
    RootFilePublication, VersionPublicationStore,
};
use meshspan_protocol::v1::ProtocolVersion;
use meshspan_transport::{FederationExchangeContext, FederationReplayGuard, TransportError};
use tempfile::tempdir;

use super::branch_page_proof::{BranchFixture, StaticBranchAuthority, publication};
use super::{NOW, SessionProof};

struct SyncEnvironment<'a> {
    proof: &'a SessionProof<'a>,
    fixture: &'a BranchFixture,
    publication: &'a RootFilePublication,
    source: &'a FilesystemFederationHistorySource,
    receiver: &'a ProofReceiver,
    client_grants: &'a StaticBranchAuthority,
    server_grants: &'a StaticBranchAuthority,
}

type ProofReceiver = AdmittingFederationHistoryReceiver<AdmitEverySignedMutation, NoQuarantine>;

pub(super) async fn prove_restart_resumable_filesystem_sync(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
) -> Result<(), Box<dyn Error>> {
    let source_directory = tempdir()?;
    let receiver_directory = tempdir()?;
    let publication = publication()?;
    let mut source_store =
        VersionPublicationStore::open(source_directory.path(), UnixMicros::new(1))?;
    let acknowledgement = acknowledgement(proof, fixture, &publication)?;
    source_store.publish_federated_root_file(&publication, &acknowledgement)?;
    let bundle = source_store.export_namespace_history(
        publication.file.volume_id,
        &[publication.namespace_commit_id],
        &[],
        NamespaceHistoryLimits::DEFAULT,
    )?;
    assert_eq!(bundle.commit_count(), 1);
    let immutable_count = bundle.immutable_record_count();
    drop(source_store);

    let source = FilesystemFederationHistorySource::new(source_directory.path());
    let receiver = AdmittingFederationHistoryReceiver::new(
        FilesystemFederationHistorySource::new(receiver_directory.path()),
        AdmitEverySignedMutation,
        NoQuarantine,
    );
    let client_grants = StaticBranchAuthority::admit(fixture.authority);
    let server_grants = StaticBranchAuthority::admit(fixture.authority);
    let environment = SyncEnvironment {
        proof,
        fixture,
        publication: &publication,
        source: &source,
        receiver: &receiver,
        client_grants: &client_grants,
        server_grants: &server_grants,
    };
    let mut client_replay = history_replay_guard()?;
    let mut server_replay = history_replay_guard()?;
    prove_first_page_checkpoint(&environment, &mut client_replay, &mut server_replay).await?;
    prove_resumed_completion(
        &environment,
        immutable_count,
        &mut client_replay,
        &mut server_replay,
    )
    .await?;
    let receiver_store =
        VersionPublicationStore::open(receiver_directory.path(), UnixMicros::new(2))?;
    assert_eq!(
        receiver_store
            .export_namespace_history(
                publication.file.volume_id,
                &[publication.namespace_commit_id],
                &[],
                NamespaceHistoryLimits::DEFAULT,
            )?
            .commit_count(),
        1
    );
    Ok(())
}

fn acknowledgement(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
    publication: &RootFilePublication,
) -> Result<FederatedMutationAcknowledgement, Box<dyn Error>> {
    Ok(FederatedMutationAcknowledgement {
        source_operation_id: publication.file.operation_id,
        evidence: FederatedMutationEvidence::new(
            fixture.grant_id,
            proof.relationship_id,
            FederatedPrincipal::new(MeshId::from_bytes([211; 16])?, publication.file.created_by),
            fixture.resource,
            1,
            publication.file.created_at,
            Rights::TRAVERSE
                .union(Rights::CREATE_CHILD)
                .union(Rights::WRITE_DATA),
            0,
        ),
        payload_digest: VersionPublicationStore::root_file_federated_mutation_digest(publication)?,
        signer_generation: 1,
        signature: [212; 64],
    })
}

struct AdmitEverySignedMutation;

impl FederationHistoryAdmissionSource for AdmitEverySignedMutation {
    fn classify(
        &self,
        _session_id: [u8; 32],
        records: Vec<NamespaceHistoryCommitRecord>,
        now: UnixMicros,
    ) -> FederationHistoryAdmissionFuture<'_> {
        Box::pin(async move {
            let mut decisions = Vec::with_capacity(records.len());
            for record in records {
                if record.federated_acknowledgement()?.is_none() {
                    return Err(FederationHistoryAdmissionError::MissingAcknowledgement);
                }
                decisions.push(NamespaceHistoryMutationDecision::new(
                    record.mutation_authority()?.commit_id(),
                    FederatedMutationAdmission::Admitted,
                    now,
                ));
            }
            Ok(FederationHistoryAdmissionBatch::new(decisions, Vec::new()))
        })
    }
}

struct NoQuarantine;

impl FederationQuarantineCommitter for NoQuarantine {
    fn retain(
        &self,
        _retention: FederationQuarantineRetention,
    ) -> FederationQuarantineCommitFuture<'_> {
        Box::pin(async { Err(FederationQuarantineCommitError::Rejected) })
    }
}

async fn prove_first_page_checkpoint(
    environment: &SyncEnvironment<'_>,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<(), Box<dyn Error>> {
    let proof = environment.proof;
    let sync = proof.client_runtime.sync_federated_history(
        proof.client_connection,
        proof.client_authority,
        environment.client_grants,
        environment.receiver,
        history_sync_request(environment, 160, 1)?,
        client_replay,
    );
    let serve = async {
        proof
            .server_runtime
            .serve_branch_page(
                proof.server_connection,
                FederationBranchPageServices::new(
                    proof.server_authority,
                    environment.server_grants,
                    environment.source,
                ),
                FederationBranchPageServeRequest {
                    response_replay_nonce: [170; 32],
                    now: NOW,
                },
                server_replay,
            )
            .await
            .map_err(FederationHistorySyncError::from)
    };
    let (outcome, _) = tokio::try_join!(sync, serve)?;
    assert!(matches!(
        outcome,
        FederationHistorySyncOutcome::Progress {
            pages: 1,
            objects: 0,
            ..
        }
    ));
    Ok(())
}

async fn prove_resumed_completion(
    environment: &SyncEnvironment<'_>,
    immutable_count: usize,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<(), Box<dyn Error>> {
    let exchanges = immutable_count
        .checked_mul(2)
        .ok_or("exchange count overflow")?;
    let proof = environment.proof;
    let sync = proof.client_runtime.sync_federated_history(
        proof.client_connection,
        proof.client_authority,
        environment.client_grants,
        environment.receiver,
        history_sync_request(environment, 180, exchanges)?,
        client_replay,
    );
    let serve = serve_history_sync_tail(environment, immutable_count, server_replay);
    let (outcome, ()) = tokio::try_join!(sync, serve)?;
    assert!(matches!(
        outcome,
        FederationHistorySyncOutcome::Completed { objects, .. } if objects == immutable_count
    ));
    Ok(())
}

async fn serve_history_sync_tail(
    environment: &SyncEnvironment<'_>,
    immutable_count: usize,
    replay: &mut FederationReplayGuard,
) -> Result<(), FederationHistorySyncError> {
    let proof = environment.proof;
    for index in 0..immutable_count {
        proof
            .server_runtime
            .serve_branch_page(
                proof.server_connection,
                FederationBranchPageServices::new(
                    proof.server_authority,
                    environment.server_grants,
                    environment.source,
                ),
                FederationBranchPageServeRequest {
                    response_replay_nonce: exchange_nonce(200, index, 1),
                    now: NOW,
                },
                replay,
            )
            .await?;
        proof
            .server_runtime
            .serve_history_object(
                proof.server_connection,
                FederationHistoryObjectServices::new(
                    proof.server_authority,
                    environment.server_grants,
                    environment.source,
                ),
                FederationHistoryObjectServeRequest {
                    response_replay_nonce: exchange_nonce(200, index, 2),
                    now: NOW,
                },
                replay,
            )
            .await?;
    }
    Ok(())
}

fn history_sync_request(
    environment: &SyncEnvironment<'_>,
    seed: u8,
    exchange_count: usize,
) -> Result<FederationHistorySyncRequest, Box<dyn Error>> {
    Ok(FederationHistorySyncRequest {
        session_id: [159; 32],
        relationship_id: environment.proof.relationship_id,
        grant_id: environment.fixture.grant_id,
        resource: environment.fixture.resource,
        requested_heads: vec![environment.publication.namespace_commit_id],
        known_commits: Vec::new(),
        limits: NamespaceHistoryLimits::DEFAULT,
        page_limit: 1,
        exchange_contexts: (0..exchange_count)
            .map(|index| exchange_context(seed, index))
            .collect::<Result<Vec<_>, _>>()?,
        now: NOW,
        expires_at: UnixMicros::new(2_000_000),
    })
}

fn exchange_context(seed: u8, index: usize) -> Result<FederationExchangeContext, Box<dyn Error>> {
    Ok(FederationExchangeContext::new(
        ProtocolVersion { major: 1, minor: 1 },
        exchange_id(seed, index, 1),
        exchange_id(seed, index, 2),
        exchange_id(seed, index, 3),
        UnixMicros::new(2_000_000),
        exchange_nonce(seed, index, 4),
    )?)
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
