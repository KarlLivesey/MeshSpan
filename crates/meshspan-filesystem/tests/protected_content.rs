// SPDX-License-Identifier: GPL-2.0-only

//! Real-folder proof for placement, erasure coding, eventual durability and degraded reads.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::sync::{Arc, Mutex};

use meshspan_coding::ReedSolomonCoding;
use meshspan_contracts::{
    BoundedBytes, BoundedItems, ContractError, PlacementCandidate, PlacementCellRequirement,
    PlacementCellRole, PutShardRequest, RequestContext, ReserveStorageRequest, ShardReadPermit,
    ShardReceipt, StoragePermitMacKey, StorageProvider, StorageReservation,
};
use meshspan_domain::{
    AvailabilityCellId, ContentManifestId, EntropyError, FailureScenario, FailureTerm,
    FaultGroupClassId, FaultGroupId, FaultGroupMember, HostId, MeshId, OperationId, RandomSource,
    Revision, TargetId, Topology, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    CompletedStage, ContentChunkLimits, ContentPublicationRequest, ContentReadError,
    ContentReadRequest, ContentShardRouter, DurableContentPublisher, DurableContentReader,
    ProtectedContentAccess, ProtectedContentPublisher, ProtectionConfiguration,
    ProtectionPolicySource, PublishedContentReference, VolumeContentKeyring,
    VolumeKeyEncryptionKey,
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
    let fixture = protection_fixture(root.path(), mesh_id)?;
    fixture.control.set_offline(fixture.eventual_target)?;
    let state = root.path().join("filesystem-state");
    let volume_id = VolumeId::from_bytes([3; 16])?;
    let request = publication_request(volume_id, 5)?;
    let bytes = fixture_bytes();
    let mut publisher = ProtectedContentPublisher::open(
        &state,
        UnixMicros::new(1),
        fixture.router,
        ReedSolomonCoding::new(),
        FaultAwarePlacement::new(),
        VolumeBoundProtection::new(volume_id, fixture.protection),
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

    fixture.control.set_offline(fixture.required_targets[0])?;
    let content = PublishedContentReference {
        publication_operation_id: request.operation_id,
        manifest,
    };
    let mut recovered = Vec::new();
    publisher.stream_range(read_request(content, 50)?, &mut recovered)?;
    assert_eq!(recovered, bytes);

    fixture.control.set_offline(fixture.required_targets[1])?;
    assert!(matches!(
        publisher.stream_range(read_request(content, 51)?, &mut Vec::new()),
        Err(ContentReadError::Unavailable)
    ));
    Ok(())
}

#[test]
fn six_machines_keep_exact_bytes_after_combined_loss_and_cell_isolation()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let mesh_id = MeshId::from_bytes([80; 16])?;
    let fixture = campus_fixture(root.path(), mesh_id)?;
    let bytes = fixture_bytes();

    let strict_volume = VolumeId::from_bytes([81; 16])?;
    let strict_request = publication_request(strict_volume, 82)?;
    let mut strict = protected_publisher(
        &root.path().join("strict-state"),
        fixture.router.clone(),
        strict_volume,
        fixture.strict_protection,
        mesh_id,
        83,
    )?;
    let strict_content = publish(&mut strict, strict_request, &bytes)?;
    let strict_stripe = strict
        .catalog()
        .committed_protected_stripe(strict_content, 0)?;
    assert_eq!(strict_stripe.stripe.coding_layout().data_slices(), 2);
    assert!(strict_stripe.stripe.coding_layout().recovery_slices() >= 7);

    fixture.control.set_offline_many(&[
        fixture.targets[0][0],
        fixture.targets[0][1],
        fixture.targets[1][0],
        fixture.targets[1][1],
        fixture.targets[2][0],
        fixture.targets[3][0],
        fixture.targets[4][0],
    ])?;
    assert_exact_read(&mut strict, strict_content, &bytes, 84)?;

    fixture.control.set_all_online()?;
    fixture.control.set_offline_many(&fixture.cell_targets[2])?;
    let available_volume = VolumeId::from_bytes([85; 16])?;
    let available_request = publication_request(available_volume, 86)?;
    let mut available = protected_publisher(
        &root.path().join("available-state"),
        fixture.router,
        available_volume,
        fixture.cell_availability,
        mesh_id,
        87,
    )?;
    let available_content = publish(&mut available, available_request, &bytes)?;
    assert!(
        !available
            .catalog()
            .pending_protected_shards(available_request, None, 24)?
            .shards
            .is_empty()
    );

    fixture.control.set_offline_many(&fixture.cell_targets[1])?;
    assert_exact_read(&mut available, available_content, &bytes, 88)?;
    fixture.control.set_all_online()?;
    fixture.control.set_offline_many(&fixture.cell_targets[0])?;
    fixture.control.set_offline_many(&fixture.cell_targets[2])?;
    assert_exact_read(&mut available, available_content, &bytes, 89)?;
    Ok(())
}

struct ProtectionFixture {
    router: TestRouter,
    control: TestRouter,
    protection: ProtectionConfiguration,
    eventual_target: TargetId,
    required_targets: Vec<TargetId>,
}

struct CampusFixture {
    router: TestRouter,
    control: TestRouter,
    strict_protection: ProtectionConfiguration,
    cell_availability: ProtectionConfiguration,
    targets: Vec<[TargetId; 2]>,
    cell_targets: [Vec<TargetId>; 3],
}

struct CampusStorage {
    topology: Topology,
    candidates: Vec<PlacementCandidate>,
    providers: BTreeMap<TargetId, FolderShardStore>,
    machine_class: FaultGroupClassId,
    device_class: FaultGroupClassId,
    cells: [AvailabilityCellId; 3],
    targets: Vec<[TargetId; 2]>,
    cell_targets: [Vec<TargetId>; 3],
}

fn campus_fixture(
    root: &std::path::Path,
    mesh_id: MeshId,
) -> Result<CampusFixture, Box<dyn std::error::Error>> {
    let storage = campus_storage(root, mesh_id)?;
    let machine_class = storage.machine_class;
    let device_class = storage.device_class;
    let cells = storage.cells;
    let topology = storage.topology;
    let candidates = storage.candidates;
    let providers = storage.providers;
    let targets = storage.targets;
    let cell_targets = storage.cell_targets;
    let combined = FailureScenario::new(vec![
        FailureTerm {
            class_id: machine_class,
            failure_count: 2,
        },
        FailureTerm {
            class_id: device_class,
            failure_count: 3,
        },
    ])?;
    let cell_requirements = campus_cell_requirements(cells, device_class)?;
    let strict_protection = ProtectionConfiguration::from_policy_snapshot(
        topology.clone(),
        Revision::new(1),
        Revision::new(1),
        vec![combined.clone()],
        candidates.clone(),
        vec![combined.clone()],
        6,
        4,
        cell_requirements.clone(),
    )?;
    let cell_availability = ProtectionConfiguration::from_policy_snapshot(
        topology,
        Revision::new(1),
        Revision::new(1),
        vec![combined],
        candidates,
        Vec::new(),
        6,
        4,
        cell_requirements,
    )?;
    let router = TestRouter::new(providers);
    Ok(CampusFixture {
        control: router.clone(),
        router,
        strict_protection,
        cell_availability,
        targets,
        cell_targets,
    })
}

fn campus_storage(
    root: &std::path::Path,
    mesh_id: MeshId,
) -> Result<CampusStorage, Box<dyn std::error::Error>> {
    let machine_class = FaultGroupClassId::from_bytes([90; 16])?;
    let device_class = FaultGroupClassId::from_bytes([91; 16])?;
    let cells = [
        AvailabilityCellId::from_bytes([92; 16])?,
        AvailabilityCellId::from_bytes([93; 16])?,
        AvailabilityCellId::from_bytes([94; 16])?,
    ];
    let mut topology = Topology::default();
    let mut candidates = Vec::new();
    let mut providers = BTreeMap::new();
    let mut targets = Vec::new();
    let mut cell_targets: [Vec<TargetId>; 3] = std::array::from_fn(|_| Vec::new());
    for machine in 0_u8..6 {
        let host_id = HostId::from_bytes([100 + machine; 16])?;
        topology.register_host(host_id)?;
        let machine_group = FaultGroupId::from_bytes([110 + machine; 16])?;
        topology.register_fault_group(machine_group, machine_class)?;
        topology.add_fault_group_member(machine_group, FaultGroupMember::Host(host_id))?;
        let mut host_targets = Vec::new();
        for device in 0_u8..2 {
            let ordinal = machine * 2 + device;
            let target_id = TargetId::from_bytes([120 + ordinal; 16])?;
            topology.register_target(target_id, host_id)?;
            let device_group = FaultGroupId::from_bytes([140 + ordinal; 16])?;
            topology.register_fault_group(device_group, device_class)?;
            topology.add_fault_group_member(device_group, FaultGroupMember::Target(target_id))?;
            let cell_index = usize::from(machine / 2);
            cell_targets[cell_index].push(target_id);
            host_targets.push(target_id);
            candidates.push(PlacementCandidate {
                target_id,
                host_id,
                target_generation: 1,
                writable_bytes: 2 * 1_024 * 1_024,
                performance_weight: 100,
                availability_cells: BoundedItems::new(vec![cells[cell_index]], 256)?,
            });
            providers.insert(
                target_id,
                open_provider(root, mesh_id, target_id, 20 + ordinal)?,
            );
        }
        targets.push(host_targets.try_into().map_err(|_| "missing host target")?);
    }
    Ok(CampusStorage {
        topology,
        candidates,
        providers,
        machine_class,
        device_class,
        cells,
        targets,
        cell_targets,
    })
}

fn campus_cell_requirements(
    cells: [AvailabilityCellId; 3],
    device_class: FaultGroupClassId,
) -> Result<Vec<PlacementCellRequirement>, Box<dyn std::error::Error>> {
    let local_device = FailureScenario::new(vec![FailureTerm {
        class_id: device_class,
        failure_count: 1,
    }])?;
    Ok(vec![
        placement_cell(
            cells[0],
            PlacementCellRole::RequiredBeforeCommit,
            &local_device,
        )?,
        placement_cell(
            cells[1],
            PlacementCellRole::RequiredBeforeCommit,
            &local_device,
        )?,
        PlacementCellRequirement {
            cell_id: cells[2],
            role: PlacementCellRole::Eventual,
            complete_local: false,
            minimum_durable_targets: None,
            minimum_distinct_nodes: None,
            local_scenarios: BoundedItems::new(Vec::new(), 16)?,
        },
    ])
}

fn placement_cell(
    cell_id: AvailabilityCellId,
    role: PlacementCellRole,
    local_scenario: &FailureScenario,
) -> Result<PlacementCellRequirement, Box<dyn std::error::Error>> {
    Ok(PlacementCellRequirement {
        cell_id,
        role,
        complete_local: true,
        minimum_durable_targets: Some(3),
        minimum_distinct_nodes: Some(2),
        local_scenarios: BoundedItems::new(vec![local_scenario.clone()], 16)?,
    })
}

fn protection_fixture(
    root: &std::path::Path,
    mesh_id: MeshId,
) -> Result<ProtectionFixture, Box<dyn std::error::Error>> {
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
        if index == 3 {
            eventual_target = Some(target_id);
        } else {
            required_targets.push(target_id);
        }
        candidates.push(PlacementCandidate {
            target_id,
            host_id,
            target_generation: 1,
            writable_bytes: 2 * 1_024 * 1_024,
            performance_weight: 100,
            availability_cells: BoundedItems::new(Vec::new(), 256)?,
        });
        providers.insert(target_id, open_provider(root, mesh_id, target_id, index)?);
    }

    let router = TestRouter::new(providers);
    let control = router.clone();
    let protection = ProtectionConfiguration::from_policy_snapshot(
        topology,
        Revision::new(1),
        Revision::new(1),
        vec![FailureScenario::new(vec![FailureTerm {
            class_id: device_class,
            failure_count: 2,
        }])?],
        candidates,
        Vec::new(),
        3,
        3,
        Vec::new(),
    )?;
    Ok(ProtectionFixture {
        router,
        control,
        protection,
        eventual_target: eventual_target.ok_or("missing eventual target")?,
        required_targets,
    })
}

struct VolumeBoundProtection {
    volume_id: VolumeId,
    configuration: ProtectionConfiguration,
}

impl VolumeBoundProtection {
    const fn new(volume_id: VolumeId, configuration: ProtectionConfiguration) -> Self {
        Self {
            volume_id,
            configuration,
        }
    }
}

impl ProtectionPolicySource for VolumeBoundProtection {
    fn configuration(
        &self,
        volume_id: VolumeId,
    ) -> Result<ProtectionConfiguration, meshspan_filesystem::ContentPublicationError> {
        if volume_id != self.volume_id {
            return Err(meshspan_filesystem::ContentPublicationError::InvalidInput);
        }
        Ok(self.configuration.clone())
    }
}

type TestProtectedPublisher = ProtectedContentPublisher<
    TestRouter,
    ReedSolomonCoding,
    FaultAwarePlacement,
    FixedRandom,
    VolumeContentKeyring,
    VolumeBoundProtection,
>;

fn protected_publisher(
    state: &std::path::Path,
    router: TestRouter,
    volume_id: VolumeId,
    protection: ProtectionConfiguration,
    mesh_id: MeshId,
    key_byte: u8,
) -> Result<TestProtectedPublisher, Box<dyn std::error::Error>> {
    Ok(ProtectedContentPublisher::open(
        state,
        UnixMicros::new(1),
        router,
        ReedSolomonCoding::new(),
        FaultAwarePlacement::new(),
        VolumeBoundProtection::new(volume_id, protection),
        FixedRandom,
        VolumeContentKeyring::new(
            volume_id,
            VolumeKeyEncryptionKey::from_bytes(1, [key_byte; 32])?,
        ),
        ContentChunkLimits::new(350_000)?,
        ProtectedContentAccess::new(mesh_id, StoragePermitMacKey::from_bytes(PERMIT_KEY)?),
    )?)
}

fn publish(
    publisher: &mut TestProtectedPublisher,
    request: ContentPublicationRequest,
    bytes: &[u8],
) -> Result<PublishedContentReference, Box<dyn std::error::Error>> {
    let mut sink = publisher.begin(request)?;
    sink.write_all(bytes)?;
    let manifest = publisher.finish(
        request,
        sink,
        CompletedStage {
            logical_length: u64::try_from(bytes.len())?,
            content_digest: blake3::hash(bytes).into(),
        },
    )?;
    Ok(PublishedContentReference {
        publication_operation_id: request.operation_id,
        manifest,
    })
}

fn assert_exact_read(
    publisher: &mut TestProtectedPublisher,
    content: PublishedContentReference,
    expected: &[u8],
    operation: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut recovered = Vec::new();
    publisher.stream_range(read_request(content, operation)?, &mut recovered)?;
    if recovered != expected {
        return Err("degraded read returned different bytes".into());
    }
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
    operation: u8,
) -> Result<ContentPublicationRequest, Box<dyn std::error::Error>> {
    Ok(ContentPublicationRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        volume_id,
        request_digest: [operation.wrapping_add(1); 32],
        manifest_id: ContentManifestId::from_bytes([operation.wrapping_add(2); 16])?,
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

    fn set_offline_many(&self, targets: &[TargetId]) -> Result<(), ContractError> {
        let mut state = self.lock()?;
        state.offline.extend(targets.iter().copied());
        Ok(())
    }

    fn set_all_online(&self) -> Result<(), ContractError> {
        self.lock()?.offline.clear();
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
