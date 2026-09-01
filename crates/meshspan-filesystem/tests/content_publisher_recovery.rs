// SPDX-License-Identifier: GPL-2.0-only

//! Restart proof for partially published encrypted content through the real folder provider.

use std::fs;

use meshspan_contracts::{
    BoundedBytes, ContractError, ImplementationDescriptor, InventoryEntry, InventoryPage,
    PutShardRequest, RemovalAuthorityFence, RemovalPermit, RequestContext, ReserveStorageRequest,
    ScrubObservation, ScrubPage, ShardReadPermit, ShardReceipt, StoragePermitMacKey,
    StorageProvider, StorageReservation, TombstoneReceipt, read_permit_mac,
};
use meshspan_domain::{
    BranchId, ContentManifestId, EntropyError, FileVersionId, MeshId, NamespaceCommitId, ObjectId,
    ObjectRevisionId, OperationId, PrincipalId, RandomSource, Revision, StageId, TargetId,
    UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    ContentChunkCipher, ContentChunkLimits, ContentKeyEnvelopeCipher, ContentPublicationError,
    EncryptedContentChunk, FilesystemCommitError, FilesystemCommitService, NamespaceLimits,
    NamespacePath, NamespacePublicationPath, RootFileCommitRequest, StageCompletionRequest,
    StageRegistration, StageWrite, UnprotectedContentAccess, UnprotectedContentPublisher,
    VolumeContentKeyring, VolumeKeyEncryptionKey,
};
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder, StoragePermitVerifier,
    UsageLimit,
};
use tempfile::tempdir;

const PERMIT_KEY: [u8; 32] = [42; 32];

#[test]
fn interrupted_provider_publication_resumes_after_complete_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let storage_path = directory.path().join("storage");
    let storage_state = directory.path().join("storage-state");
    let filesystem_state = directory.path().join("filesystem-state");
    fs::create_dir(&storage_path)?;
    let registration = folder_registration()?;
    let mut random = FixedRandom;
    let folder = RegisteredFolder::register_new(&storage_path, registration, &mut random)?;
    let fingerprint = folder.marker().fingerprint();
    let provider = open_provider(folder, &storage_state, UnixMicros::new(1))?;
    let publisher = open_publisher(
        &filesystem_state,
        InterruptSecondPut::new(provider),
        registration,
        UnixMicros::new(1),
    )?;
    let mut service =
        FilesystemCommitService::open(&filesystem_state, UnixMicros::new(1), publisher)?;
    prepare_stage(&mut service)?;
    let request = commit_request()?;

    assert!(matches!(
        service.commit_root_file(&request),
        Err(FilesystemCommitError::Content(
            ContentPublicationError::Unavailable
        ))
    ));
    let interrupted = service.into_content_publisher().into_provider();
    assert_eq!(interrupted.put_calls, 2);
    drop(interrupted.into_inner());

    let folder = RegisteredFolder::reopen(&storage_path, registration, fingerprint)?;
    let provider = open_provider(folder, &storage_state, UnixMicros::new(5))?;
    let publisher = open_publisher(
        &filesystem_state,
        provider,
        registration,
        UnixMicros::new(5),
    )?;
    let mut service =
        FilesystemCommitService::open(&filesystem_state, UnixMicros::new(5), publisher)?;
    let mut retry = request.clone();
    retry.completion.observed_at = UnixMicros::new(6);
    service.commit_root_file(&retry)?;
    let publisher = service.into_content_publisher();

    assert_eq!(
        read_prepared_file(&publisher, registration, &retry)?,
        b"helloworld"
    );
    assert!(
        publisher
            .catalog()
            .pending_chunks(retry.content_publication_request(), None, 10)?
            .chunks
            .is_empty()
    );
    Ok(())
}

fn open_provider(
    folder: RegisteredFolder,
    state_directory: &std::path::Path,
    opened_at: UnixMicros,
) -> Result<FolderShardStore, Box<dyn std::error::Error>> {
    Ok(FolderShardStore::open(
        folder,
        state_directory,
        CapacityPolicy {
            usage_limit: UsageLimit::DEFAULT,
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(
            folder_registration()?.mesh_id,
            1,
            Revision::new(1),
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        )?,
        opened_at,
        &mut FixedRandom,
    )?)
}

fn open_publisher<P: StorageProvider>(
    state_directory: &std::path::Path,
    provider: P,
    registration: FolderRegistration,
    opened_at: UnixMicros,
) -> Result<UnprotectedContentPublisher<P, FixedRandom>, ContentPublicationError> {
    UnprotectedContentPublisher::open(
        state_directory,
        opened_at,
        provider,
        FixedRandom,
        VolumeContentKeyring::new(
            VolumeId::from_bytes([12; 16]).map_err(|_| ContentPublicationError::InvalidInput)?,
            VolumeKeyEncryptionKey::from_bytes(1, [24; 32])
                .map_err(|_| ContentPublicationError::InvalidInput)?,
        ),
        ContentChunkLimits::new(4).map_err(|_| ContentPublicationError::InvalidInput)?,
        UnprotectedContentAccess::new(
            registration.mesh_id,
            registration.target_id,
            registration.generation,
            StoragePermitMacKey::from_bytes(PERMIT_KEY)
                .map_err(|_| ContentPublicationError::InvalidInput)?,
        )?,
    )
}

fn prepare_stage<P: meshspan_filesystem::DurableContentPublisher>(
    service: &mut FilesystemCommitService<P>,
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
        retain_superseded_history: true,
        retention_policy_sequence: 1,
        manifest_id: ContentManifestId::from_bytes([15; 16])?,
        manifest_format_version: 1,
        content_authorization_revision: Revision::new(9),
        content_deadline: UnixMicros::new(500),
        root_object_id: ObjectId::from_bytes([16; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([17; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([18; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([19; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["report.txt"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
        created_by: PrincipalId::from_bytes([20; 16])?,
        created_at: UnixMicros::new(4),
    })
}

fn read_prepared_file<P: StorageProvider, R: RandomSource>(
    publisher: &UnprotectedContentPublisher<P, R>,
    registration: FolderRegistration,
    request: &RootFileCommitRequest,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let content_request = request.content_publication_request();
    let layout = publisher
        .catalog()
        .prepared_layout(content_request)?
        .ok_or("missing prepared layout")?;
    let key = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(1, [24; 32])?)
        .unwrap(request.manifest_id, layout.wrapped_key)?;
    let cipher = ContentChunkCipher::new(key, ContentChunkLimits::new(4)?);
    let mut recovered = Vec::new();
    for index in 0_u64..3 {
        let chunk = publisher.catalog().content_chunk(content_request, index)?;
        let context = RequestContext {
            contract_version: meshspan_contracts::ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([u8::try_from(50 + index)?; 16])?,
            deadline: UnixMicros::new(500),
            expected_revision: Some(Revision::new(9)),
        };
        let mut permit = ShardReadPermit {
            operation_id: context.operation_id,
            mesh_id: registration.mesh_id,
            target_id: registration.target_id,
            target_generation: registration.generation,
            shard: meshspan_contracts::ShardIdentity {
                manifest_digest: layout.manifest.root_digest,
                stripe_index: index,
                shard_index: 0,
                generation: 1,
            },
            authorization_revision: Revision::new(9),
            expires_at: UnixMicros::new(500),
            permit_digest: [0; 32],
        };
        permit.permit_digest =
            read_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, permit);
        let ciphertext = publisher
            .provider()
            .get_exact(context, permit, UnixMicros::new(20))?;
        let plaintext = cipher.decrypt(
            request.manifest_id,
            1,
            index,
            &EncryptedContentChunk {
                plaintext_length: chunk.plaintext_length,
                plaintext_digest: chunk.plaintext_digest,
                ciphertext_digest: chunk.ciphertext_digest,
                ciphertext,
            },
        )?;
        recovered.extend_from_slice(plaintext.as_slice());
    }
    Ok(recovered)
}

fn folder_registration() -> Result<FolderRegistration, Box<dyn std::error::Error>> {
    Ok(FolderRegistration {
        mesh_id: MeshId::from_bytes([21; 16])?,
        target_id: TargetId::from_bytes([22; 16])?,
        generation: 1,
        usage_limit: UsageLimit::DEFAULT,
    })
}

struct InterruptSecondPut<P> {
    inner: P,
    put_calls: usize,
}

impl<P> InterruptSecondPut<P> {
    const fn new(inner: P) -> Self {
        Self {
            inner,
            put_calls: 0,
        }
    }

    fn into_inner(self) -> P {
        self.inner
    }
}

impl<P: StorageProvider> StorageProvider for InterruptSecondPut<P> {
    fn describe(&self) -> ImplementationDescriptor {
        self.inner.describe()
    }

    fn reserve(
        &mut self,
        request: ReserveStorageRequest,
    ) -> Result<StorageReservation, ContractError> {
        self.inner.reserve(request)
    }

    fn put_exact(
        &mut self,
        request: PutShardRequest,
        observed_at: UnixMicros,
    ) -> Result<ShardReceipt, ContractError> {
        self.put_calls += 1;
        if self.put_calls == 2 {
            Err(ContractError::Unavailable)
        } else {
            self.inner.put_exact(request, observed_at)
        }
    }

    fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
        observed_at: UnixMicros,
    ) -> Result<BoundedBytes, ContractError> {
        self.inner.get_exact(context, permit, observed_at)
    }

    fn removal_authority_fence(&self) -> RemovalAuthorityFence {
        self.inner.removal_authority_fence()
    }

    fn tombstone(
        &mut self,
        permit: RemovalPermit,
        observed_at: UnixMicros,
    ) -> Result<TombstoneReceipt, ContractError> {
        self.inner.tombstone(permit, observed_at)
    }

    fn unlink_tombstoned(
        &mut self,
        receipt: TombstoneReceipt,
        observed_at: UnixMicros,
    ) -> Result<meshspan_contracts::ReclamationReceipt, ContractError> {
        self.inner.unlink_tombstoned(receipt, observed_at)
    }

    fn inventory(
        &self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
    ) -> Result<InventoryPage, ContractError> {
        self.inner.inventory(cursor, limit)
    }

    fn inventory_exact(
        &self,
        shard: meshspan_contracts::ShardIdentity,
    ) -> Result<Option<InventoryEntry>, ContractError> {
        self.inner.inventory_exact(shard)
    }

    fn scrub_exact(
        &mut self,
        expected: InventoryEntry,
        observed_at: UnixMicros,
    ) -> Result<ScrubObservation, ContractError> {
        self.inner.scrub_exact(expected, observed_at)
    }

    fn scrub(
        &mut self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
        observed_at: UnixMicros,
    ) -> Result<ScrubPage, ContractError> {
        self.inner.scrub(cursor, limit, observed_at)
    }
}

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(23);
        Ok(())
    }
}
