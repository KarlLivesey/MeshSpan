// SPDX-License-Identifier: GPL-2.0-only

//! Real Quinn proof for signed federated storage issuance and lost-response replay.

use std::error::Error;
use std::fs;

use meshspan_cluster::{
    FederationShardServeRequest, FederationStorageCapabilityProvider,
    FederationStorageCapabilityRequest, FederationStorageCapabilityServeRequest,
    FederationStorageReceiptReceiveRequest, ServedFederationStorageCapability,
};
use meshspan_contracts::{
    BoundedBytes, FederatedShardPermit, FederatedStoragePermitMacKey, ReclamationReceipt,
    ScrubObservation, ScrubOutcome, ShardReceipt, StoragePermitMacKey, TombstoneReceipt,
    federated_provider_shard_identity, verify_federated_shard_permit_mac,
};
use meshspan_data_plane::{
    DataPlaneError, RemoteShardService, decode_federated_shard_permit, get_federated_shard,
    put_federated_shard, reclaim_federated_shard, retire_federated_shard, scrub_federated_shard,
};
use meshspan_domain::{
    EntropyError, FederationStorageAction, FederationStorageAllocation, NodeId, OperationId,
    PartitionId, RandomSource, Revision, UnixMicros,
};
use meshspan_metadata::{FederationStorageQuotaDisposition, FederationStorageUsage, LocalDatabase};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::{
    ProtocolVersion, RemoteShardAction, RequestFederatedStorageCapability, RequestHeader,
    ShardIdentity,
};
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder, StoragePermitVerifier,
    UsageLimit,
};
use meshspan_transport::{
    AuthenticatedFederationStorageCapability, FederationExchangeContext, FederationReplayGuard,
};

use super::{NOW, SessionProof, replay_guard};

const PROVIDER_PERMIT_KEY: [u8; 32] = [209; 32];
const PAYLOAD: &[u8] = b"federated shard";

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(17);
        Ok(())
    }
}

pub(super) async fn prove_storage_capability_exchange(
    proof: &SessionProof<'_>,
    allocation: FederationStorageAllocation,
    provider_node_id: NodeId,
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let local_path = directory.path().join("provider-local.sqlite3");
    let mut local = LocalDatabase::open(&local_path, provider_node_id, NOW)?;
    let permit_key = FederatedStoragePermitMacKey::from_bytes([210; 32])?;
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let issued = issue_write_capability(
        proof,
        &mut local,
        &permit_key,
        allocation,
        provider_node_id,
        &mut client_replay,
        &mut server_replay,
    )
    .await?;
    assert_eq!(usage(&local, allocation)?.reserved_bytes, 20);

    let payload = BoundedBytes::copy_from(PAYLOAD, 20)?;
    let mut service = shard_service(directory.path(), proof, allocation, provider_node_id)?;
    reject_deadline_beyond_permit(proof, &issued.presented, &payload).await?;
    let receipt = put_cycle(
        proof,
        &mut local,
        &mut service,
        &permit_key,
        &issued.presented,
        &payload,
        NOW,
    )
    .await?;
    assert_eq!(receipt.shard_receipt.length, PAYLOAD.len() as u64);
    assert_usage(&local, allocation, PAYLOAD.len() as u64, 0)?;

    drop(local);
    let retry_now = UnixMicros::new(NOW.get() + 1);
    let mut local = LocalDatabase::open(&local_path, provider_node_id, retry_now)?;
    let (retry, replayed) = exchange(
        proof,
        &mut local,
        &permit_key,
        request(allocation, FederationStorageAction::Put),
        exchange_values(221, 212, retry_now, UnixMicros::new(1_850_000))?,
        &mut client_replay,
        &mut server_replay,
    )
    .await?;
    let retry_presented = replayed_write_permit(retry, replayed, &issued)?;
    let retried = put_cycle(
        proof,
        &mut local,
        &mut service,
        &permit_key,
        &retry_presented,
        &payload,
        retry_now,
    )
    .await?;
    assert_eq!(retried.shard_receipt, receipt.shard_receipt);
    assert_eq!(retried.result_digest, receipt.result_digest);
    assert_eq!(retried.completed_at, receipt.completed_at);
    assert_usage(&local, allocation, PAYLOAD.len() as u64, 0)?;

    prove_federated_lifecycle(
        proof,
        &mut local,
        &mut service,
        &permit_key,
        allocation,
        &issued,
        &payload,
        &mut client_replay,
        &mut server_replay,
    )
    .await?;
    let inventory = service.into_provider().inventory(None, 2)?;
    assert!(inventory.entries.is_empty());
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the lifecycle proof keeps independently authenticated runtime inputs explicit"
)]
async fn prove_federated_lifecycle(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    service: &mut RemoteShardService<FolderShardStore>,
    permit_key: &FederatedStoragePermitMacKey,
    allocation: FederationStorageAllocation,
    issued: &IssuedWriteCapability,
    payload: &BoundedBytes,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<(), Box<dyn Error>> {
    prove_federated_read(
        proof,
        local,
        service,
        permit_key,
        allocation,
        client_replay,
        server_replay,
    )
    .await?;
    prove_federated_repair(
        proof,
        local,
        service,
        permit_key,
        allocation,
        payload,
        client_replay,
        server_replay,
    )
    .await?;
    prove_federated_scrub(
        proof,
        local,
        service,
        permit_key,
        allocation,
        client_replay,
        server_replay,
    )
    .await?;
    Box::pin(prove_federated_retire_and_reclaim(
        proof,
        local,
        service,
        permit_key,
        allocation,
        &issued.presented.permit,
        client_replay,
        server_replay,
    ))
    .await?;
    Ok(())
}

fn replayed_write_permit(
    capability: AuthenticatedFederationStorageCapability,
    served: ServedFederationStorageCapability,
    original: &IssuedWriteCapability,
) -> Result<PresentedPermit, Box<dyn Error>> {
    assert_eq!(
        served.quota_disposition,
        Some(FederationStorageQuotaDisposition::Replayed)
    );
    assert_eq!(
        capability.capability().canonical_capability,
        original.canonical_capability
    );
    let permit = decode_federated_shard_permit(&capability.capability().canonical_capability)?;
    Ok(PresentedPermit { permit, capability })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the integration boundary keeps every independently authenticated runtime input explicit"
)]
async fn prove_federated_repair(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    service: &mut RemoteShardService<FolderShardStore>,
    permit_key: &FederatedStoragePermitMacKey,
    allocation: FederationStorageAllocation,
    payload: &BoundedBytes,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<(), Box<dyn Error>> {
    let repair_now = UnixMicros::new(NOW.get() + 3);
    let (repair_capability, repair_served) = exchange(
        proof,
        local,
        permit_key,
        request(allocation, FederationStorageAction::Repair),
        exchange_values(241, 214, repair_now, UnixMicros::new(1_850_000))?,
        client_replay,
        server_replay,
    )
    .await?;
    assert_eq!(repair_served.action, FederationStorageAction::Repair);
    assert_eq!(
        repair_served.quota_disposition,
        Some(FederationStorageQuotaDisposition::Applied)
    );
    assert_usage(local, allocation, PAYLOAD.len() as u64, 20)?;
    let repair_permit =
        decode_federated_shard_permit(&repair_capability.capability().canonical_capability)?;
    let repair_presented = PresentedPermit {
        permit: repair_permit,
        capability: repair_capability,
    };
    let repaired = put_cycle(
        proof,
        local,
        service,
        permit_key,
        &repair_presented,
        payload,
        repair_now,
    )
    .await?;
    assert_eq!(repaired.shard_receipt.length, PAYLOAD.len() as u64);
    assert_ne!(repaired.result_digest, [0; 32]);
    assert_usage(local, allocation, PAYLOAD.len() as u64, 0)?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the integration boundary keeps every independently authenticated runtime input explicit"
)]
async fn prove_federated_retire_and_reclaim(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    service: &mut RemoteShardService<FolderShardStore>,
    permit_key: &FederatedStoragePermitMacKey,
    allocation: FederationStorageAllocation,
    written_permit: &FederatedShardPermit,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<(), Box<dyn Error>> {
    let retired = Box::pin(prove_federated_retirement(
        proof,
        local,
        service,
        permit_key,
        allocation,
        written_permit,
        client_replay,
        server_replay,
    ))
    .await?;
    Box::pin(prove_federated_reclamation(
        proof,
        local,
        service,
        permit_key,
        allocation,
        retired.tombstone,
        client_replay,
        server_replay,
    ))
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "the integration boundary keeps every independently authenticated runtime input explicit"
)]
async fn prove_federated_retirement(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    service: &mut RemoteShardService<FolderShardStore>,
    permit_key: &FederatedStoragePermitMacKey,
    allocation: FederationStorageAllocation,
    written_permit: &FederatedShardPermit,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<SignedRetirement, Box<dyn Error>> {
    let retire_now = UnixMicros::new(NOW.get() + 6);
    let retire_capability = presented_capability(
        proof,
        local,
        permit_key,
        allocation,
        FederationStorageAction::Retire,
        exchange_values(181, 215, retire_now, UnixMicros::new(1_850_000))?,
        client_replay,
        server_replay,
    )
    .await?;
    let retired = retire_cycle(
        proof,
        local,
        service,
        permit_key,
        &retire_capability,
        retire_now,
    )
    .await
    .map_err(|error| format!("initial retirement cycle: {error:?}"))?;
    assert_usage(local, allocation, PAYLOAD.len() as u64, 0)?;
    let lifecycle = local
        .federated_storage_lifecycle(
            retire_capability.permit.remote_mesh_id,
            retire_capability.permit.scope_digest,
            retire_capability.permit.target_id,
            retire_capability.permit.target_generation,
            retire_capability.permit.shard,
        )?
        .ok_or("provider retirement lifecycle was not persisted")?;
    assert_eq!(lifecycle.logical_tombstone, retired.tombstone);
    assert_eq!(
        lifecycle.provider_tombstone.shard,
        federated_provider_shard_identity(
            written_permit.remote_mesh_id,
            written_permit.scope_digest,
            written_permit.shard,
        )
    );

    let retire_retry_now = UnixMicros::new(NOW.get() + 7);
    let retry_capability = presented_capability(
        proof,
        local,
        permit_key,
        allocation,
        FederationStorageAction::Retire,
        exchange_values(186, 215, retire_retry_now, UnixMicros::new(1_860_000))?,
        client_replay,
        server_replay,
    )
    .await?;
    assert_eq!(retry_capability.permit, retire_capability.permit);
    let replayed_retirement = retire_cycle(
        proof,
        local,
        service,
        permit_key,
        &retry_capability,
        retire_retry_now,
    )
    .await
    .map_err(|error| format!("replayed retirement cycle: {error:?}"))?;
    assert_eq!(replayed_retirement, retired);
    Ok(retired)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the integration boundary keeps every independently authenticated runtime input explicit"
)]
async fn prove_federated_reclamation(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    service: &mut RemoteShardService<FolderShardStore>,
    permit_key: &FederatedStoragePermitMacKey,
    allocation: FederationStorageAllocation,
    logical_tombstone: TombstoneReceipt,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<(), Box<dyn Error>> {
    let reclaim_now = UnixMicros::new(NOW.get() + 8);
    let reclaim_capability = presented_capability(
        proof,
        local,
        permit_key,
        allocation,
        FederationStorageAction::Reclaim,
        exchange_values(191, 216, reclaim_now, UnixMicros::new(1_850_000))?,
        client_replay,
        server_replay,
    )
    .await?;
    let reclaimed = reclaim_cycle(
        proof,
        local,
        service,
        permit_key,
        &reclaim_capability,
        logical_tombstone,
        reclaim_now,
    )
    .await
    .map_err(|error| format!("initial reclamation cycle: {error:?}"))?;
    assert_eq!(reclaimed.receipt.reclaimed_bytes, PAYLOAD.len() as u64);
    assert_usage(local, allocation, 0, 0)?;

    let reclaim_retry_now = UnixMicros::new(NOW.get() + 9);
    let retry_capability = presented_capability(
        proof,
        local,
        permit_key,
        allocation,
        FederationStorageAction::Reclaim,
        exchange_values(196, 216, reclaim_retry_now, UnixMicros::new(1_860_000))?,
        client_replay,
        server_replay,
    )
    .await?;
    assert_eq!(retry_capability.permit, reclaim_capability.permit);
    let replayed_reclamation = reclaim_cycle(
        proof,
        local,
        service,
        permit_key,
        &retry_capability,
        logical_tombstone,
        reclaim_retry_now,
    )
    .await
    .map_err(|error| format!("replayed reclamation cycle: {error:?}"))?;
    assert_eq!(replayed_reclamation, reclaimed);
    assert_usage(local, allocation, 0, 0)?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "capability exchange requires explicit independent client and provider replay guards"
)]
async fn presented_capability(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    permit_key: &FederatedStoragePermitMacKey,
    allocation: FederationStorageAllocation,
    action: FederationStorageAction,
    values: ExchangeValues,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<PresentedPermit, Box<dyn Error>> {
    let (capability, served) = exchange(
        proof,
        local,
        permit_key,
        request(allocation, action),
        values,
        client_replay,
        server_replay,
    )
    .await
    .map_err(|error| format!("{action:?} capability exchange: {error:?}"))?;
    assert_eq!(served.action, action);
    assert_eq!(served.quota_disposition, None);
    let permit = decode_federated_shard_permit(&capability.capability().canonical_capability)?;
    Ok(PresentedPermit { permit, capability })
}

async fn prove_federated_read(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    service: &mut RemoteShardService<FolderShardStore>,
    permit_key: &FederatedStoragePermitMacKey,
    allocation: FederationStorageAllocation,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<(), Box<dyn Error>> {
    let read_now = UnixMicros::new(NOW.get() + 2);
    let (read_capability, read_served) = exchange(
        proof,
        local,
        permit_key,
        request(allocation, FederationStorageAction::Get),
        exchange_values(231, 213, read_now, UnixMicros::new(1_850_000))?,
        client_replay,
        server_replay,
    )
    .await?;
    assert_eq!(read_served.action, FederationStorageAction::Get);
    assert_eq!(read_served.quota_disposition, None);
    let read_permit =
        decode_federated_shard_permit(&read_capability.capability().canonical_capability)?;
    let read_presented = PresentedPermit {
        permit: read_permit,
        capability: read_capability,
    };
    let downloaded =
        get_cycle(proof, local, service, permit_key, &read_presented, read_now).await?;
    assert_eq!(downloaded.as_slice(), PAYLOAD);
    assert_usage(local, allocation, PAYLOAD.len() as u64, 0)?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the integration boundary keeps every independently authenticated runtime input explicit"
)]
async fn prove_federated_scrub(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    service: &mut RemoteShardService<FolderShardStore>,
    permit_key: &FederatedStoragePermitMacKey,
    allocation: FederationStorageAllocation,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<(), Box<dyn Error>> {
    let scrub_now = UnixMicros::new(NOW.get() + 4);
    let capability = presented_capability(
        proof,
        local,
        permit_key,
        allocation,
        FederationStorageAction::Scrub,
        exchange_values(171, 217, scrub_now, UnixMicros::new(1_850_000))?,
        client_replay,
        server_replay,
    )
    .await?;
    let scrubbed = scrub_cycle(proof, local, service, permit_key, &capability, scrub_now).await?;
    assert_eq!(scrubbed.observation.outcome, ScrubOutcome::Healthy);
    assert_eq!(
        scrubbed.observation.observed_digest,
        Some(blake3::hash(PAYLOAD).into())
    );

    let retry_now = UnixMicros::new(NOW.get() + 5);
    let retry = presented_capability(
        proof,
        local,
        permit_key,
        allocation,
        FederationStorageAction::Scrub,
        exchange_values(176, 217, retry_now, UnixMicros::new(1_860_000))?,
        client_replay,
        server_replay,
    )
    .await?;
    assert_eq!(retry.permit, capability.permit);
    let replayed = scrub_cycle(proof, local, service, permit_key, &retry, retry_now).await?;
    assert_eq!(replayed, scrubbed);
    Ok(())
}

async fn reject_deadline_beyond_permit(
    proof: &SessionProof<'_>,
    presented: &PresentedPermit,
    payload: &BoundedBytes,
) -> Result<(), Box<dyn Error>> {
    let permit = &presented.permit;
    let mut header = request_header(proof.client_mesh, permit.operation_id, permit.expires_at)?;
    header.deadline_unix_micros = permit.expires_at.get() + 1;
    assert!(matches!(
        put_federated_shard(
            proof.client_connection,
            header,
            *permit,
            presented.capability.capability_digest(),
            payload,
            wire_limits()?
        )
        .await,
        Err(DataPlaneError::InvalidMessage)
    ));
    Ok(())
}

struct IssuedWriteCapability {
    canonical_capability: Vec<u8>,
    presented: PresentedPermit,
}

struct PresentedPermit {
    permit: FederatedShardPermit,
    capability: AuthenticatedFederationStorageCapability,
}

async fn issue_write_capability(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    permit_key: &FederatedStoragePermitMacKey,
    allocation: FederationStorageAllocation,
    provider_node_id: NodeId,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<IssuedWriteCapability, Box<dyn Error>> {
    let (capability, served) = exchange(
        proof,
        local,
        permit_key,
        request(allocation, FederationStorageAction::Put),
        exchange_values(211, 212, NOW, UnixMicros::new(1_800_000))?,
        client_replay,
        server_replay,
    )
    .await?;
    assert_eq!(served.relationship_id, proof.relationship_id);
    assert_eq!(served.action, FederationStorageAction::Put);
    assert_eq!(served.maximum_bytes, 20);
    assert_eq!(
        served.quota_disposition,
        Some(FederationStorageQuotaDisposition::Applied)
    );
    let canonical_capability = capability.capability().canonical_capability.clone();
    let permit = decode_federated_shard_permit(&canonical_capability)?;
    assert!(verify_federated_shard_permit_mac(permit_key, &permit));
    assert_eq!(permit.operation_id, served.operation_id);
    assert_eq!(permit.provider_node_id, provider_node_id);
    Ok(IssuedWriteCapability {
        canonical_capability,
        presented: PresentedPermit { permit, capability },
    })
}

fn shard_service(
    root: &std::path::Path,
    proof: &SessionProof<'_>,
    allocation: FederationStorageAllocation,
    provider_node_id: NodeId,
) -> Result<RemoteShardService<FolderShardStore>, Box<dyn Error>> {
    let storage_path = root.join("provider-storage");
    let state_path = root.join("provider-state");
    fs::create_dir(&storage_path)?;
    let mut random = FixedRandom;
    let folder = RegisteredFolder::register_new(
        &storage_path,
        FolderRegistration {
            mesh_id: proof.server_mesh,
            target_id: allocation.target_id(),
            generation: allocation.target_generation(),
            usage_limit: UsageLimit::bytes(4_096)?,
        },
        &mut random,
    )?;
    let provider = FolderShardStore::open(
        folder,
        &state_path,
        CapacityPolicy {
            usage_limit: UsageLimit::bytes(4_096)?,
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(
            proof.server_mesh,
            9,
            Revision::new(3),
            StoragePermitMacKey::from_bytes(PROVIDER_PERMIT_KEY)?,
        )?,
        NOW,
        &mut random,
    )?;
    Ok(RemoteShardService::new(
        provider,
        StoragePermitMacKey::from_bytes(PROVIDER_PERMIT_KEY)?,
        proof.server_mesh,
        provider_node_id,
        allocation.target_id(),
        allocation.target_generation(),
        1_024,
    )?)
}

async fn put_cycle(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    service: &mut RemoteShardService<FolderShardStore>,
    permit_key: &FederatedStoragePermitMacKey,
    presented: &PresentedPermit,
    payload: &BoundedBytes,
    now: UnixMicros,
) -> Result<SignedPutResult, Box<dyn Error>> {
    let limits = wire_limits()?;
    let permit = &presented.permit;
    let put = put_federated_shard(
        proof.client_connection,
        request_header(proof.client_mesh, permit.operation_id, permit.expires_at)?,
        *permit,
        presented.capability.capability_digest(),
        payload,
        limits,
    );
    let serve = proof.server_runtime.serve_federated_shard_stream(
        proof.server_connection,
        proof.server_authority,
        local,
        service,
        permit_key,
        FederationShardServeRequest {
            relationship_id: proof.relationship_id,
            now,
            receipt_replay_nonce: receipt_nonce(now),
        },
    );
    let (put_result, serve_result) = tokio::join!(put, serve);
    let served = serve_result?.ok_or("provider did not produce a durable federation result")?;
    assert_eq!(served.action, permit.action);
    assert_eq!(served.affected_bytes, PAYLOAD.len() as u64);
    let mut receipt_replay = replay_guard()?;
    let signed = proof
        .client_runtime
        .receive_storage_receipt(
            proof.client_connection,
            proof.client_authority,
            FederationStorageReceiptReceiveRequest {
                relationship_id: proof.relationship_id,
                capability: &presented.capability,
                now,
            },
            &mut receipt_replay,
        )
        .await?;
    let receipt = signed.receipt();
    assert_eq!(receipt.affected_bytes, served.affected_bytes);
    assert_eq!(receipt.capability_digest, served.capability_digest);
    let result_digest: [u8; 32] = receipt.result_digest.as_slice().try_into()?;
    Ok(SignedPutResult {
        shard_receipt: put_result?,
        result_digest,
        completed_at: UnixMicros::new(receipt.completed_at_unix_micros),
    })
}

async fn get_cycle(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    service: &mut RemoteShardService<FolderShardStore>,
    permit_key: &FederatedStoragePermitMacKey,
    presented: &PresentedPermit,
    now: UnixMicros,
) -> Result<BoundedBytes, Box<dyn Error>> {
    let limits = wire_limits()?;
    let permit = &presented.permit;
    let get = get_federated_shard(
        proof.client_connection,
        request_header(proof.client_mesh, permit.operation_id, permit.expires_at)?,
        *permit,
        presented.capability.capability_digest(),
        1_024,
        limits,
    );
    let serve = proof.server_runtime.serve_federated_shard_stream(
        proof.server_connection,
        proof.server_authority,
        local,
        service,
        permit_key,
        FederationShardServeRequest {
            relationship_id: proof.relationship_id,
            now,
            receipt_replay_nonce: receipt_nonce(now),
        },
    );
    let (get_result, serve_result) = tokio::join!(get, serve);
    let served = serve_result?.ok_or("provider did not produce a verified federation result")?;
    let mut receipt_replay = replay_guard()?;
    let signed = proof
        .client_runtime
        .receive_storage_receipt(
            proof.client_connection,
            proof.client_authority,
            FederationStorageReceiptReceiveRequest {
                relationship_id: proof.relationship_id,
                capability: &presented.capability,
                now,
            },
            &mut receipt_replay,
        )
        .await?;
    assert_eq!(signed.receipt().affected_bytes, served.affected_bytes);
    assert_eq!(signed.receipt().capability_digest, served.capability_digest);
    Ok(get_result?)
}

async fn scrub_cycle(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    service: &mut RemoteShardService<FolderShardStore>,
    permit_key: &FederatedStoragePermitMacKey,
    presented: &PresentedPermit,
    now: UnixMicros,
) -> Result<SignedScrub, Box<dyn Error>> {
    let limits = wire_limits()?;
    let permit = &presented.permit;
    let scrub = scrub_federated_shard(
        proof.client_connection,
        request_header(proof.client_mesh, permit.operation_id, permit.expires_at)?,
        *permit,
        presented.capability.capability_digest(),
        limits,
    );
    let serve = proof.server_runtime.serve_federated_shard_stream(
        proof.server_connection,
        proof.server_authority,
        local,
        service,
        permit_key,
        FederationShardServeRequest {
            relationship_id: proof.relationship_id,
            now,
            receipt_replay_nonce: receipt_nonce(now),
        },
    );
    let (scrub_result, serve_result) = tokio::join!(scrub, serve);
    let served = serve_result?.ok_or("provider did not produce a durable scrub result")?;
    let mut receipt_replay = replay_guard()?;
    let signed = proof
        .client_runtime
        .receive_storage_receipt(
            proof.client_connection,
            proof.client_authority,
            FederationStorageReceiptReceiveRequest {
                relationship_id: proof.relationship_id,
                capability: &presented.capability,
                now,
            },
            &mut receipt_replay,
        )
        .await?;
    let receipt = signed.receipt();
    assert_eq!(served.action, FederationStorageAction::Scrub);
    assert_eq!(receipt.affected_bytes, served.affected_bytes);
    assert_eq!(receipt.capability_digest, served.capability_digest);
    Ok(SignedScrub {
        observation: scrub_result?,
        result_digest: receipt.result_digest.as_slice().try_into()?,
        completed_at: UnixMicros::new(receipt.completed_at_unix_micros),
    })
}

async fn retire_cycle(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    service: &mut RemoteShardService<FolderShardStore>,
    permit_key: &FederatedStoragePermitMacKey,
    presented: &PresentedPermit,
    now: UnixMicros,
) -> Result<SignedRetirement, Box<dyn Error>> {
    let limits = wire_limits()?;
    let permit = &presented.permit;
    let retire = retire_federated_shard(
        proof.client_connection,
        request_header(proof.client_mesh, permit.operation_id, permit.expires_at)?,
        *permit,
        presented.capability.capability_digest(),
        limits,
    );
    let serve = proof.server_runtime.serve_federated_shard_stream(
        proof.server_connection,
        proof.server_authority,
        local,
        service,
        permit_key,
        FederationShardServeRequest {
            relationship_id: proof.relationship_id,
            now,
            receipt_replay_nonce: receipt_nonce(now),
        },
    );
    let (retire_result, serve_result) = tokio::join!(retire, serve);
    let served = serve_result?.ok_or_else(|| {
        format!(
            "provider rejected retirement at {}; client observed {retire_result:?}",
            now.get()
        )
    })?;
    let mut receipt_replay = replay_guard()?;
    let signed = proof
        .client_runtime
        .receive_storage_receipt(
            proof.client_connection,
            proof.client_authority,
            FederationStorageReceiptReceiveRequest {
                relationship_id: proof.relationship_id,
                capability: &presented.capability,
                now,
            },
            &mut receipt_replay,
        )
        .await?;
    let receipt = signed.receipt();
    assert_eq!(served.action, FederationStorageAction::Retire);
    assert_eq!(receipt.affected_bytes, served.affected_bytes);
    assert_eq!(receipt.capability_digest, served.capability_digest);
    Ok(SignedRetirement {
        tombstone: retire_result?,
        result_digest: receipt.result_digest.as_slice().try_into()?,
        completed_at: UnixMicros::new(receipt.completed_at_unix_micros),
    })
}

async fn reclaim_cycle(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    service: &mut RemoteShardService<FolderShardStore>,
    permit_key: &FederatedStoragePermitMacKey,
    presented: &PresentedPermit,
    logical_tombstone: TombstoneReceipt,
    now: UnixMicros,
) -> Result<SignedReclamation, Box<dyn Error>> {
    let limits = wire_limits()?;
    let permit = &presented.permit;
    let reclaim = reclaim_federated_shard(
        proof.client_connection,
        request_header(proof.client_mesh, permit.operation_id, permit.expires_at)?,
        *permit,
        presented.capability.capability_digest(),
        logical_tombstone,
        limits,
    );
    let serve = proof.server_runtime.serve_federated_shard_stream(
        proof.server_connection,
        proof.server_authority,
        local,
        service,
        permit_key,
        FederationShardServeRequest {
            relationship_id: proof.relationship_id,
            now,
            receipt_replay_nonce: receipt_nonce(now),
        },
    );
    let (reclaim_result, serve_result) = tokio::join!(reclaim, serve);
    let served = serve_result?.ok_or_else(|| {
        format!("provider rejected reclamation; client observed {reclaim_result:?}")
    })?;
    let mut receipt_replay = replay_guard()?;
    let signed = proof
        .client_runtime
        .receive_storage_receipt(
            proof.client_connection,
            proof.client_authority,
            FederationStorageReceiptReceiveRequest {
                relationship_id: proof.relationship_id,
                capability: &presented.capability,
                now,
            },
            &mut receipt_replay,
        )
        .await?;
    let receipt = signed.receipt();
    assert_eq!(served.action, FederationStorageAction::Reclaim);
    assert_eq!(receipt.affected_bytes, served.affected_bytes);
    assert_eq!(receipt.capability_digest, served.capability_digest);
    Ok(SignedReclamation {
        receipt: reclaim_result?,
        result_digest: receipt.result_digest.as_slice().try_into()?,
        completed_at: UnixMicros::new(receipt.completed_at_unix_micros),
    })
}

struct SignedPutResult {
    shard_receipt: ShardReceipt,
    result_digest: [u8; 32],
    completed_at: UnixMicros,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SignedScrub {
    observation: ScrubObservation,
    result_digest: [u8; 32],
    completed_at: UnixMicros,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SignedRetirement {
    tombstone: TombstoneReceipt,
    result_digest: [u8; 32],
    completed_at: UnixMicros,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SignedReclamation {
    receipt: ReclamationReceipt,
    result_digest: [u8; 32],
    completed_at: UnixMicros,
}

fn receipt_nonce(now: UnixMicros) -> [u8; 32] {
    let mut nonce = [244; 32];
    nonce[..8].copy_from_slice(&now.get().to_be_bytes());
    nonce
}

async fn exchange(
    proof: &SessionProof<'_>,
    local: &mut LocalDatabase,
    permit_key: &FederatedStoragePermitMacKey,
    capability: RequestFederatedStorageCapability,
    values: ExchangeValues,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<
    (
        meshspan_transport::AuthenticatedFederationStorageCapability,
        meshspan_cluster::ServedFederationStorageCapability,
    ),
    meshspan_cluster::FederationSessionError,
> {
    let request = proof.client_runtime.request_storage_capability(
        proof.client_connection,
        proof.client_authority,
        FederationStorageCapabilityRequest {
            relationship_id: proof.relationship_id,
            capability,
            context: values.context,
            now: values.now,
        },
        client_replay,
    );
    let serve = proof.server_runtime.serve_storage_capability(
        proof.server_connection,
        FederationStorageCapabilityProvider::new(proof.server_authority, local, permit_key),
        FederationStorageCapabilityServeRequest {
            response_replay_nonce: values.response_replay_nonce,
            capability_nonce: values.capability_nonce,
            valid_until: values.valid_until,
            now: values.now,
        },
        server_replay,
    );
    tokio::try_join!(request, serve)
}

#[derive(Clone, Copy)]
struct ExchangeValues {
    context: FederationExchangeContext,
    response_replay_nonce: [u8; 32],
    capability_nonce: [u8; 32],
    valid_until: UnixMicros,
    now: UnixMicros,
}

fn exchange_values(
    seed: u8,
    operation_seed: u8,
    now: UnixMicros,
    requested_valid_until: UnixMicros,
) -> Result<ExchangeValues, meshspan_transport::TransportError> {
    Ok(ExchangeValues {
        context: FederationExchangeContext::new(
            ProtocolVersion { major: 1, minor: 1 },
            [seed; 16],
            [operation_seed; 16],
            [seed.saturating_add(1); 16],
            UnixMicros::new(1_900_000),
            [seed.saturating_add(2); 32],
        )?,
        response_replay_nonce: [seed.saturating_add(3); 32],
        capability_nonce: [seed.saturating_add(4); 32],
        valid_until: requested_valid_until,
        now,
    })
}

fn request(
    allocation: FederationStorageAllocation,
    action: FederationStorageAction,
) -> RequestFederatedStorageCapability {
    RequestFederatedStorageCapability {
        grant_id: allocation.grant_id().as_bytes().to_vec(),
        allocation_id: allocation.allocation_id().as_bytes().to_vec(),
        target_id: allocation.target_id().as_bytes().to_vec(),
        target_generation: allocation.target_generation(),
        shard: Some(ShardIdentity {
            manifest_digest: vec![230; 32],
            stripe_index: 3,
            shard_index: 4,
            generation: 1,
        }),
        action: wire_action(action).into(),
        maximum_bytes: 20,
        scope_digest: vec![231; 32],
        signature: Vec::new(),
    }
}

fn wire_action(action: FederationStorageAction) -> RemoteShardAction {
    match action {
        FederationStorageAction::Put => RemoteShardAction::Put,
        FederationStorageAction::Get => RemoteShardAction::Get,
        FederationStorageAction::Scrub => RemoteShardAction::Scrub,
        FederationStorageAction::Repair => RemoteShardAction::Repair,
        FederationStorageAction::Retire => RemoteShardAction::Retire,
        FederationStorageAction::Reclaim => RemoteShardAction::Reclaim,
    }
}

fn request_header(
    mesh_id: meshspan_domain::MeshId,
    operation: OperationId,
    deadline: UnixMicros,
) -> Result<RequestHeader, Box<dyn Error>> {
    Ok(RequestHeader {
        version: Some(ProtocolVersion { major: 1, minor: 0 }),
        mesh_id: mesh_id.as_bytes().to_vec(),
        partition_id: PartitionId::from_bytes([240; 16])?.as_bytes().to_vec(),
        routing_epoch: 1,
        sender_node_id: NodeId::from_bytes([241; 16])?.as_bytes().to_vec(),
        sender_incarnation: 1,
        request_id: operation.as_bytes().to_vec(),
        operation_id: operation.as_bytes().to_vec(),
        deadline_unix_micros: deadline.get(),
        trace_id: operation.as_bytes().to_vec(),
    })
}

fn wire_limits() -> Result<WireLimits, Box<dyn Error>> {
    Ok(WireLimits::new(64 * 1_024, 64 * 1_024, 256, 4_096)?)
}

fn usage(
    local: &LocalDatabase,
    allocation: FederationStorageAllocation,
) -> Result<FederationStorageUsage, Box<dyn Error>> {
    local
        .federated_storage_usage(allocation.allocation_id())?
        .ok_or_else(|| "federated storage usage was not persisted".into())
}

fn assert_usage(
    local: &LocalDatabase,
    allocation: FederationStorageAllocation,
    committed_bytes: u64,
    reserved_bytes: u64,
) -> Result<(), Box<dyn Error>> {
    let usage = usage(local, allocation)?;
    assert_eq!(usage.committed_bytes, committed_bytes);
    assert_eq!(usage.reserved_bytes, reserved_bytes);
    Ok(())
}
