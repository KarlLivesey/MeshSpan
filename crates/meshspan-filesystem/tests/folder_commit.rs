// SPDX-License-Identifier: GPL-2.0-only

//! Vertical proof from a durable random-write stage through the real registered-folder provider.

use std::fs;

use meshspan_contracts::{
    BoundedBytes, ContractError, ContractVersion, PutShardRequest, RequestContext,
    ReservationClass, ReserveStorageRequest, ShardIdentity, ShardReadPermit, StoragePermitMacKey,
    StorageProvider, read_permit_mac,
};
use meshspan_domain::{
    BranchId, ContentManifestId, EntropyError, FileVersionId, MeshId, NamespaceCommitId, ObjectId,
    ObjectRevisionId, OperationId, PrincipalId, RandomSource, Revision, StageId, TargetId,
    UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    CompletedStage, ContentPublicationError, ContentPublicationRequest, DurableContentPublisher,
    FilesystemCommitService, ManifestPublication, NamespaceComponent, NamespaceLimits,
    PublicationDisposition, RootFileCommitRequest, StageCompletionRequest, StageRegistration,
    StageWrite,
};
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder, StoragePermitVerifier,
    UsageLimit,
};
use tempfile::tempdir;

const PERMIT_KEY: [u8; 32] = [42; 32];

#[test]
fn staged_file_commits_through_the_real_folder_provider_and_reads_exactly()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let storage_path = directory.path().join("storage");
    let storage_state = directory.path().join("storage-state");
    let filesystem_state = directory.path().join("filesystem-state");
    fs::create_dir(&storage_path)?;
    fs::write(storage_path.join("ordinary-file.txt"), b"untouched")?;
    let registration = folder_registration()?;
    let mut random = FixedRandom;
    let folder = RegisteredFolder::register_new(&storage_path, registration, &mut random)?;
    let provider = FolderShardStore::open(
        folder,
        &storage_state,
        CapacityPolicy {
            usage_limit: UsageLimit::DEFAULT,
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(
            registration.mesh_id,
            1,
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        )?,
        UnixMicros::new(1),
        &mut random,
    )?;
    let publisher = FolderPublisher {
        provider,
        registration,
        durable: None,
    };
    let mut service =
        FilesystemCommitService::open(&filesystem_state, UnixMicros::new(1), publisher)?;
    prepare_stage(&mut service)?;
    let request = commit_request()?;
    let receipt = service.commit_root_file(&request)?;
    assert_eq!(receipt.disposition, PublicationDisposition::Applied);
    assert_eq!(
        service.commit_root_file(&request)?.disposition,
        PublicationDisposition::Replayed
    );

    let publisher = service.into_content_publisher();
    let durable = publisher.durable.ok_or("missing durable manifest")?;
    let read_context = RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([31; 16])?,
        deadline: UnixMicros::new(500),
        expected_revision: Some(Revision::new(9)),
    };
    let mut permit = ShardReadPermit {
        operation_id: read_context.operation_id,
        mesh_id: registration.mesh_id,
        target_id: registration.target_id,
        target_generation: registration.generation,
        shard: durable.shard,
        authorization_revision: Revision::new(9),
        expires_at: UnixMicros::new(500),
        permit_digest: [0; 32],
    };
    permit.permit_digest = read_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, permit);
    let bytes = StorageProvider::get_exact(
        &publisher.provider,
        read_context,
        permit,
        UnixMicros::new(20),
    )?;
    assert_eq!(bytes.as_slice(), b"helloworld");
    assert_eq!(
        fs::read(storage_path.join("ordinary-file.txt"))?,
        b"untouched"
    );
    Ok(())
}

struct FolderPublisher {
    provider: FolderShardStore,
    registration: FolderRegistration,
    durable: Option<DurableManifest>,
}

struct DurableManifest {
    request: ContentPublicationRequest,
    manifest: ManifestPublication,
    shard: ShardIdentity,
}

impl DurableContentPublisher for FolderPublisher {
    type Sink = Vec<u8>;

    fn resolve(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Option<ManifestPublication>, ContentPublicationError> {
        self.durable
            .as_ref()
            .map(|durable| {
                if durable.request == request {
                    Ok(durable.manifest)
                } else {
                    Err(ContentPublicationError::Conflict)
                }
            })
            .transpose()
    }

    fn begin(
        &mut self,
        _request: ContentPublicationRequest,
    ) -> Result<Self::Sink, ContentPublicationError> {
        Ok(Vec::new())
    }

    fn finish(
        &mut self,
        request: ContentPublicationRequest,
        bytes: Self::Sink,
        completed: CompletedStage,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        validate_completed(&bytes, completed)?;
        let root_digest = manifest_root(completed);
        let shard = ShardIdentity {
            manifest_digest: root_digest,
            stripe_index: 0,
            shard_index: 0,
            generation: 1,
        };
        let context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: request.operation_id,
            deadline: UnixMicros::new(500),
            expected_revision: Some(Revision::new(9)),
        };
        let length =
            u64::try_from(bytes.len()).map_err(|_| ContentPublicationError::InvalidInput)?;
        let reservation = StorageProvider::reserve(
            &mut self.provider,
            ReserveStorageRequest {
                context,
                target_id: self.registration.target_id,
                target_generation: self.registration.generation,
                class: ReservationClass::ForegroundWrite,
                bytes: length,
                observed_at: UnixMicros::new(10),
            },
        )
        .map_err(map_contract)?;
        let bounded = BoundedBytes::copy_from(&bytes, 64)
            .map_err(|_| ContentPublicationError::InvalidInput)?;
        StorageProvider::put_exact(
            &mut self.provider,
            PutShardRequest {
                context,
                reservation,
                shard,
                expected_length: length,
                expected_digest: blake3::hash(&bytes).into(),
                bytes: bounded,
            },
            UnixMicros::new(11),
        )
        .map_err(map_contract)?;
        let manifest = ManifestPublication {
            manifest_id: request.manifest_id,
            format_version: request.format_version,
            logical_length: completed.logical_length,
            content_digest: completed.content_digest,
            root_digest,
        };
        self.durable = Some(DurableManifest {
            request,
            manifest,
            shard,
        });
        Ok(manifest)
    }
}

fn validate_completed(
    bytes: &[u8],
    completed: CompletedStage,
) -> Result<(), ContentPublicationError> {
    let length = u64::try_from(bytes.len()).map_err(|_| ContentPublicationError::InvalidInput)?;
    if length == completed.logical_length
        && blake3::hash(bytes).as_bytes() == &completed.content_digest
    {
        Ok(())
    } else {
        Err(ContentPublicationError::Corrupt)
    }
}

fn manifest_root(completed: CompletedStage) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.test.unprotected-layout.v1\0");
    digest.update(&completed.logical_length.to_be_bytes());
    digest.update(&completed.content_digest);
    digest.finalize().into()
}

fn map_contract(error: ContractError) -> ContentPublicationError {
    match error {
        ContractError::InvalidInput | ContractError::UnsupportedVersion => {
            ContentPublicationError::InvalidInput
        }
        ContractError::Conflict => ContentPublicationError::Conflict,
        ContractError::Corrupt | ContractError::InternalContract => {
            ContentPublicationError::Corrupt
        }
        ContractError::Unauthorized
        | ContractError::Stale
        | ContractError::NotFound
        | ContractError::ResourceExhausted
        | ContractError::DeadlineExceeded
        | ContractError::Unavailable => ContentPublicationError::Unavailable,
    }
}

fn prepare_stage(
    service: &mut FilesystemCommitService<FolderPublisher>,
) -> Result<(), Box<dyn std::error::Error>> {
    let stage_id = StageId::from_bytes([1; 16])?;
    service.stages_mut().register(StageRegistration {
        stage_id,
        stage_fence: 2,
        maximum_bytes: 64,
        created_at: UnixMicros::new(1),
        expires_at: UnixMicros::new(100),
    })?;
    for write in [stage_write(3, 5, b"world")?, stage_write(4, 0, b"hello")?] {
        service
            .stages_mut()
            .write(stage_id, &write, UnixMicros::new(3))?;
    }
    Ok(())
}

fn stage_write(
    operation: u8,
    offset: u64,
    bytes: &[u8],
) -> Result<StageWrite, Box<dyn std::error::Error>> {
    Ok(StageWrite {
        operation_id: OperationId::from_bytes([operation; 16])?,
        stage_fence: 2,
        offset,
        digest: blake3::hash(bytes).into(),
        bytes: BoundedBytes::copy_from(bytes, 64)?,
    })
}

fn commit_request() -> Result<RootFileCommitRequest, Box<dyn std::error::Error>> {
    Ok(RootFileCommitRequest {
        completion: StageCompletionRequest {
            operation_id: OperationId::from_bytes([10; 16])?,
            stage_id: StageId::from_bytes([1; 16])?,
            stage_fence: 2,
            expected_sequence: 2,
            final_length: 10,
            sparse: false,
            observed_at: UnixMicros::new(4),
        },
        branch_id: BranchId::from_bytes([11; 16])?,
        volume_id: VolumeId::from_bytes([12; 16])?,
        object_id: ObjectId::from_bytes([13; 16])?,
        expected_current_version_id: None,
        version_id: FileVersionId::from_bytes([14; 16])?,
        manifest_id: ContentManifestId::from_bytes([15; 16])?,
        manifest_format_version: 1,
        root_object_id: ObjectId::from_bytes([16; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([17; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([18; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([19; 16])?,
        entry_name: NamespaceComponent::new("report.txt", NamespaceLimits::PORTABLE)?,
        entry_generation: 1,
        created_by: PrincipalId::from_bytes([20; 16])?,
        created_at: UnixMicros::new(4),
    })
}

fn folder_registration() -> Result<FolderRegistration, Box<dyn std::error::Error>> {
    Ok(FolderRegistration {
        mesh_id: MeshId::from_bytes([21; 16])?,
        target_id: TargetId::from_bytes([22; 16])?,
        generation: 1,
        usage_limit: UsageLimit::DEFAULT,
    })
}

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(23);
        Ok(())
    }
}
