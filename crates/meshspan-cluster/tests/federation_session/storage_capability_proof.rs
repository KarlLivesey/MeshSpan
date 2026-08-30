// SPDX-License-Identifier: GPL-2.0-only

//! Real Quinn proof for signed federated storage issuance and lost-response replay.

use std::error::Error;

use meshspan_cluster::{
    FederationStorageCapabilityProvider, FederationStorageCapabilityRequest,
    FederationStorageCapabilityServeRequest,
};
use meshspan_contracts::{FederatedStoragePermitMacKey, verify_federated_shard_permit_mac};
use meshspan_data_plane::decode_federated_shard_permit;
use meshspan_domain::{FederationStorageAction, FederationStorageAllocation, NodeId, UnixMicros};
use meshspan_metadata::{FederationStorageQuotaDisposition, LocalDatabase};
use meshspan_protocol::v1::{
    ProtocolVersion, RemoteShardAction, RequestFederatedStorageCapability, ShardIdentity,
};
use meshspan_transport::{FederationExchangeContext, FederationReplayGuard};

use super::{NOW, SessionProof, replay_guard};

pub(super) async fn prove_storage_capability_exchange(
    proof: &SessionProof<'_>,
    allocation: FederationStorageAllocation,
    provider_node_id: NodeId,
) -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let local_path = directory.path().join("provider-local.sqlite3");
    let mut local = LocalDatabase::open(&local_path, provider_node_id, NOW)?;
    let permit_key = FederatedStoragePermitMacKey::from_bytes([210; 32])?;
    let capability_request = request(allocation);
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;

    let (capability, served) = exchange(
        proof,
        &mut local,
        &permit_key,
        capability_request.clone(),
        exchange_values(211, NOW, UnixMicros::new(1_800_000))?,
        &mut client_replay,
        &mut server_replay,
    )
    .await?;
    assert_eq!(served.relationship_id, proof.relationship_id);
    assert_eq!(served.action, FederationStorageAction::Put);
    assert_eq!(served.maximum_bytes, 20);
    assert_eq!(
        served.quota_disposition,
        Some(FederationStorageQuotaDisposition::Applied)
    );
    let permit = decode_federated_shard_permit(&capability.capability().canonical_capability)?;
    assert!(verify_federated_shard_permit_mac(&permit_key, &permit));
    assert_eq!(permit.operation_id, served.operation_id);
    assert_eq!(permit.provider_node_id, provider_node_id);
    assert_eq!(reserved_bytes(&local, allocation)?, 20);

    drop(local);
    let retry_now = UnixMicros::new(NOW.get() + 1);
    let mut local = LocalDatabase::open(&local_path, provider_node_id, retry_now)?;
    let (retry, replayed) = exchange(
        proof,
        &mut local,
        &permit_key,
        capability_request,
        exchange_values(221, retry_now, UnixMicros::new(1_850_000))?,
        &mut client_replay,
        &mut server_replay,
    )
    .await?;
    assert_eq!(
        replayed.quota_disposition,
        Some(FederationStorageQuotaDisposition::Replayed)
    );
    assert_eq!(
        retry.capability().canonical_capability,
        capability.capability().canonical_capability
    );
    assert_eq!(reserved_bytes(&local, allocation)?, 20);
    Ok(())
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
    now: UnixMicros,
    requested_valid_until: UnixMicros,
) -> Result<ExchangeValues, meshspan_transport::TransportError> {
    Ok(ExchangeValues {
        context: FederationExchangeContext::new(
            ProtocolVersion { major: 1, minor: 1 },
            [seed; 16],
            [212; 16],
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

fn request(allocation: FederationStorageAllocation) -> RequestFederatedStorageCapability {
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
        action: RemoteShardAction::Put.into(),
        maximum_bytes: 20,
        scope_digest: vec![231; 32],
        signature: Vec::new(),
    }
}

fn reserved_bytes(
    local: &LocalDatabase,
    allocation: FederationStorageAllocation,
) -> Result<u64, Box<dyn Error>> {
    Ok(local
        .federated_storage_usage(allocation.allocation_id())?
        .ok_or("federated storage usage was not persisted")?
        .reserved_bytes)
}
