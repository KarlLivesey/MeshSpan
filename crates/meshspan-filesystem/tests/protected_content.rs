// SPDX-License-Identifier: GPL-2.0-only

//! Real-folder proof for placement, erasure coding, eventual durability and degraded reads.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::sync::{Arc, Mutex};

use meshspan_coding::ReedSolomonCoding;
use meshspan_contracts::{
    BoundedBytes, ContractError, PlacementCandidate, PutShardRequest, RequestContext,
    ReserveStorageRequest, ShardAcknowledgement, ShardReadPermit, ShardReceipt,
    StoragePermitMacKey, StorageProvider, StorageReservation,
};
use meshspan_domain::{
    ContentManifestId, EntropyError, FailureScenario, FailureTerm, FaultGroupClassId, FaultGroupId,
    FaultGroupMember, HostId, MeshId, OperationId, RandomSource, Revision, TargetId, Topology,
    UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    CompletedStage, ContentChunkLimits, ContentPublicationRequest, ContentReadError,
    ContentReadRequest, ContentShardRouter, DurableContentPublisher, DurableContentReader,
    ProtectedContentAccess, ProtectedContentPublisher, ProtectionConfiguration,
    PublishedContentReference, VolumeContentKeyring, VolumeKeyEncryptionKey,
};
use meshspan_placement::FaultAwarePlacement;
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder, StoragePermitVerifier,
    UsageLimit,
};
use tempfile::tempdir;

const PERMIT_KEY: [u8; 32] = [42; 32];

#[test]
fn real_folders_commit_without_eventual_target_and_read_after_two_target_losses()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let mesh_id = MeshId::from_bytes([1; 16])?;
    let mut topology = Topology::default();
    let mut candidates = Vec::new();
    let mut providers = BTreeMap::new();
    let device_class = FaultGroupClassId::from_bytes([2; 16])?;
    let mut eventual_target = None;
    let mut required_targets = Vec::new();

    for index in 0_u8..4 {
        let host_id = HostId::from_bytes([10 + index; 16])?;
        let target_id = TargetId::from_bytes([20 + index; 16])?;
        topology.register_host(host_id)?;
        topology.register_target(target_id, host_id)?;
        let group_id = FaultGroupId::from_bytes([30 + index; 16])?;
        topology.register_fault_group(group_id, device_class)?;
        topology.add_fault_group_member(group_id, FaultGroupMember::Target(target_id))?;
        let acknowledgement = if index == 3 {
            eventual_target = Some(target_id);
            ShardAcknowledgement::Eventual
        } else {
            required_targets.push(target_id);
            ShardAcknowledgement::Required
        };
        candidates.push(PlacementCandidate {
            target_id,
            target_generation: 1,
            writable_bytes: 2 * 1_024 * 1_024,
            performance_weight: 100,
            acknowledgement,
        });
        providers.insert(
            target_id,
            open_provider(root.path(), mesh_id, target_id, index)?,
        );
    }

    let router = TestRouter::new(providers);
    let control = router.clone();
    control.set_offline(eventual_target.ok_or("missing eventual target")?)?;
    let protection = ProtectionConfiguration::from_untrusted(
        topology,
        Revision::new(1),
        Revision::new(1),
        vec![FailureScenario::new(vec![FailureTerm {
            class_id: device_class,
            failure_count: 2,
        }])?],
        candidates,
    )?;
    let state = root.path().join("filesystem-state");
    let volume_id = VolumeId::from_bytes([3; 16])?;
    let request = publication_request(volume_id)?;
    let bytes = fixture_bytes();
    let mut publisher = ProtectedContentPublisher::open(
        &state,
        UnixMicros::new(1),
        router,
        ReedSolomonCoding::new(),
        FaultAwarePlacement::new(),
        protection,
        FixedRandom,
        VolumeContentKeyring::new(volume_id, VolumeKeyEncryptionKey::from_bytes(1, [4; 32])?),
        ContentChunkLimits::new(350_000)?,
        ProtectedContentAccess::new(mesh_id, StoragePermitMacKey::from_bytes(PERMIT_KEY)?),
    )?;

    let mut sink = publisher.begin(request)?;
    sink.write_all(&bytes)?;
    let manifest = publisher.finish(
        request,
        sink,
        CompletedStage {
            logical_length: u64::try_from(bytes.len())?,
            content_digest: blake3::hash(&bytes).into(),
        },
    )?;
    let stripe = publisher.catalog().protected_stripe(request, 0)?;
    assert_eq!(stripe.coding_layout().data_slices(), 2);
    assert_eq!(stripe.coding_layout().recovery_slices(), 2);
    assert_eq!(
        publisher
            .catalog()
            .pending_protected_shards(request, None, 10)?
            .shards
            .len(),
        1
    );

    control.set_offline(required_targets[0])?;
    let content = PublishedContentReference {
        publication_operation_id: request.operation_id,
        manifest,
    };
    let mut recovered = Vec::new();
    publisher.stream_range(read_request(content, 50)?, &mut recovered)?;
    assert_eq!(recovered, bytes);

    control.set_offline(required_targets[1])?;
    assert!(matches!(
        publisher.stream_range(read_request(content, 51)?, &mut Vec::new()),
        Err(ContentReadError::Unavailable)
    ));
    Ok(())
}

fn open_provider(
    root: &std::path::Path,
    mesh_id: MeshId,
    target_id: TargetId,
    index: u8,
) -> Result<FolderShardStore, Box<dyn std::error::Error>> {
    let storage = root.join(format!("storage-{index}"));
    let state = root.join(format!("storage-state-{index}"));
    fs::create_dir(&storage)?;
    let registration = FolderRegistration {
        mesh_id,
        target_id,
        generation: 1,
        usage_limit: UsageLimit::DEFAULT,
    };
    let folder = RegisteredFolder::register_new(&storage, registration, &mut FixedRandom)?;
    Ok(FolderShardStore::open(
        folder,
        &state,
        CapacityPolicy {
            usage_limit: UsageLimit::DEFAULT,
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(
            mesh_id,
            1,
            Revision::new(1),
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        )?,
        UnixMicros::new(1),
        &mut FixedRandom,
    )?)
}

fn publication_request(
    volume_id: VolumeId,
) -> Result<ContentPublicationRequest, Box<dyn std::error::Error>> {
    Ok(ContentPublicationRequest {
        operation_id: OperationId::from_bytes([5; 16])?,
        volume_id,
        request_digest: [6; 32],
        manifest_id: ContentManifestId::from_bytes([7; 16])?,
        format_version: 2,
        logical_length: 300_000,
        authorization_revision: Revision::new(1),
        deadline: UnixMicros::new(1_000),
        observed_at: UnixMicros::new(10),
    })
}

fn read_request(
    content: PublishedContentReference,
    operation: u8,
) -> Result<ContentReadRequest, meshspan_domain::IdentifierError> {
    Ok(ContentReadRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        content,
        offset: 0,
        length: content.manifest.logical_length,
        authorization_revision: Revision::new(1),
        deadline: UnixMicros::new(1_000),
        observed_at: UnixMicros::new(20),
    })
}

fn fixture_bytes() -> Vec<u8> {
    (0_u32..300_000)
        .map(|index| u8::try_from(index % 251).unwrap_or_default())
        .collect()
}

#[derive(Clone)]
struct TestRouter {
    state: Arc<Mutex<RouterState>>,
}

struct RouterState {
    providers: BTreeMap<TargetId, FolderShardStore>,
    offline: BTreeSet<TargetId>,
}

impl TestRouter {
    fn new(providers: BTreeMap<TargetId, FolderShardStore>) -> Self {
        Self {
            state: Arc::new(Mutex::new(RouterState {
                providers,
                offline: BTreeSet::new(),
            })),
        }
    }

    fn set_offline(&self, target_id: TargetId) -> Result<(), ContractError> {
        self.state
            .lock()
            .map_err(|_| ContractError::Unavailable)?
            .offline
            .insert(target_id);
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, RouterState>, ContractError> {
        self.state.lock().map_err(|_| ContractError::Unavailable)
    }
}

impl ContentShardRouter for TestRouter {
    fn reserve(
        &mut self,
        request: ReserveStorageRequest,
    ) -> Result<StorageReservation, ContractError> {
        let mut state = self.lock()?;
        if state.offline.contains(&request.target_id) {
            return Err(ContractError::Unavailable);
        }
        let provider = state
            .providers
            .get_mut(&request.target_id)
            .ok_or(ContractError::NotFound)?;
        StorageProvider::reserve(provider, request)
    }

    fn put_exact(
        &mut self,
        request: PutShardRequest,
        observed_at: UnixMicros,
    ) -> Result<ShardReceipt, ContractError> {
        let mut state = self.lock()?;
        let target_id = request.reservation.target_id;
        if state.offline.contains(&target_id) {
            return Err(ContractError::Unavailable);
        }
        let provider = state
            .providers
            .get_mut(&target_id)
            .ok_or(ContractError::NotFound)?;
        StorageProvider::put_exact(provider, request, observed_at)
    }

    fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
        observed_at: UnixMicros,
    ) -> Result<BoundedBytes, ContractError> {
        let state = self.lock()?;
        if state.offline.contains(&permit.target_id) {
            return Err(ContractError::Unavailable);
        }
        let provider = state
            .providers
            .get(&permit.target_id)
            .ok_or(ContractError::NotFound)?;
        StorageProvider::get_exact(provider, context, permit, observed_at)
    }
}

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(9);
        Ok(())
    }
}
