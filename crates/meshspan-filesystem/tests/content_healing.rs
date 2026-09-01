// SPDX-License-Identifier: GPL-2.0-only

//! Real-folder proof for restart-safe encrypted content recovery and exact byte reads.

use std::fs;
use std::io::Write;

use meshspan_contracts::{
    BoundedBytes, ContractVersion, RequestContext, ShardReadPermit, StoragePermitMacKey,
    read_permit_mac,
};
use meshspan_domain::{
    ContentManifestId, EntropyError, MeshId, OperationId, RandomSource, Revision, TargetId,
    UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    CompletedStage, ContentChunkLimits, ContentEncryptionKey, ContentKeyEnvelopeCipher,
    ContentLayoutTransferHeader, ContentPublicationError, ContentPublicationRequest,
    ContentReadRequest, DurableContentPublisher, DurableContentReader, PublishedContentReference,
    UnprotectedContentAccess, UnprotectedContentPublisher, VolumeContentKeyring,
    VolumeKeyEncryptionKey,
};
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder, StoragePermitVerifier,
    UsageLimit,
};
use tempfile::tempdir;

const PERMIT_KEY: [u8; 32] = [42; 32];

#[test]
fn encrypted_non_empty_content_recovers_exactly_after_restart_and_corruption_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let source = StorageFixture::create(root.path(), "source", 1)?;
    let target = StorageFixture::create(root.path(), "target", 2)?;
    let source_state = root.path().join("source-filesystem");
    let target_state = root.path().join("target-filesystem");
    let source_request = publication_request(10, UnixMicros::new(2))?;
    let mut source_publisher = open_publisher(
        &source_state,
        source.open(UnixMicros::new(1))?,
        source.registration,
        24,
        7,
        UnixMicros::new(1),
    )?;
    let content = publish_source(&mut source_publisher, source_request)?;
    let (source_header, pages) = export_layout(&source_publisher, content)?;
    let encrypted = read_source_chunks(&source_publisher, source.registration, source_request)?;
    drop(source_publisher.into_provider());

    let receiver_header = rewrap_for_receiver(source_header)?;
    let receiver_request = recovery_request(content, UnixMicros::new(10))?;
    let mut receiver = open_publisher(
        &target_state,
        target.open(UnixMicros::new(10))?,
        target.registration,
        25,
        8,
        UnixMicros::new(10),
    )?;
    receiver.begin_content_recovery(receiver_request, receiver_header)?;
    receiver.append_content_recovery_layout(receiver_request, receiver_header, &pages[0])?;
    drop(receiver.into_provider());

    let resumed_request = ContentPublicationRequest {
        observed_at: UnixMicros::new(20),
        ..receiver_request
    };
    let mut receiver = open_publisher(
        &target_state,
        target.reopen(UnixMicros::new(20))?,
        target.registration,
        25,
        9,
        UnixMicros::new(20),
    )?;
    receiver.begin_content_recovery(resumed_request, receiver_header)?;
    receiver.append_content_recovery_layout(resumed_request, receiver_header, &pages[0])?;
    for page in &pages[1..] {
        receiver.append_content_recovery_layout(resumed_request, receiver_header, page)?;
    }
    assert_eq!(
        receiver.seal_content_recovery_layout(resumed_request, receiver_header)?,
        content.manifest
    );
    reject_corrupt_chunk_before_provider_io(&mut receiver, resumed_request, &encrypted[0])?;
    receiver.store_recovered_content_chunk(resumed_request, 0, encrypted[0].clone())?;
    receiver.store_recovered_content_chunk(resumed_request, 0, encrypted[0].clone())?;
    assert!(matches!(
        receiver.finish_content_recovery(resumed_request),
        Err(ContentPublicationError::Unavailable)
    ));
    drop(receiver.into_provider());

    let final_request = ContentPublicationRequest {
        observed_at: UnixMicros::new(30),
        ..receiver_request
    };
    let mut receiver = open_publisher(
        &target_state,
        target.reopen(UnixMicros::new(30))?,
        target.registration,
        25,
        10,
        UnixMicros::new(30),
    )?;
    assert_eq!(
        receiver
            .pending_content_recovery(final_request, None, 10)?
            .chunks
            .len(),
        2
    );
    for (index, bytes) in encrypted.iter().enumerate().skip(1) {
        receiver.store_recovered_content_chunk(
            final_request,
            u64::try_from(index)?,
            bytes.clone(),
        )?;
    }
    assert_eq!(
        receiver.finish_content_recovery(final_request)?,
        content.manifest
    );
    assert_eq!(read_exact(&mut receiver, content)?, b"helloworld");
    Ok(())
}

fn publish_source(
    publisher: &mut UnprotectedContentPublisher<FolderShardStore, FixedRandom>,
    request: ContentPublicationRequest,
) -> Result<PublishedContentReference, Box<dyn std::error::Error>> {
    let mut sink = publisher.begin(request)?;
    sink.write_all(b"helloworld")?;
    let manifest = publisher.finish(
        request,
        sink,
        CompletedStage {
            logical_length: 10,
            content_digest: blake3::hash(b"helloworld").into(),
        },
    )?;
    Ok(PublishedContentReference {
        publication_operation_id: request.operation_id,
        manifest,
    })
}

fn export_layout(
    publisher: &UnprotectedContentPublisher<FolderShardStore, FixedRandom>,
    content: PublishedContentReference,
) -> Result<
    (
        ContentLayoutTransferHeader,
        Vec<meshspan_filesystem::ContentLayoutTransferPage>,
    ),
    Box<dyn std::error::Error>,
> {
    let transfer = publisher.catalog().committed_layout_transfer(content)?;
    let header = transfer.header();
    let mut pages = Vec::new();
    let mut cursor = None;
    loop {
        let page = transfer.page(cursor, 2)?;
        cursor = page.next_index();
        pages.push(page);
        if cursor.is_none() {
            break;
        }
    }
    Ok((header, pages))
}

fn read_source_chunks(
    publisher: &UnprotectedContentPublisher<FolderShardStore, FixedRandom>,
    registration: FolderRegistration,
    request: ContentPublicationRequest,
) -> Result<Vec<BoundedBytes>, Box<dyn std::error::Error>> {
    let layout = publisher
        .catalog()
        .prepared_layout(request)?
        .ok_or("missing source layout")?;
    let mut result = Vec::new();
    for index in 0..3 {
        let chunk = publisher.catalog().content_chunk(request, index)?;
        let operation_id = OperationId::from_bytes([u8::try_from(50 + index)?; 16])?;
        let context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id,
            deadline: request.deadline,
            expected_revision: Some(request.authorization_revision),
        };
        let mut permit = ShardReadPermit {
            operation_id,
            mesh_id: registration.mesh_id,
            target_id: registration.target_id,
            target_generation: registration.generation,
            shard: meshspan_contracts::ShardIdentity {
                manifest_digest: layout.manifest.root_digest,
                stripe_index: index,
                shard_index: 0,
                generation: 1,
            },
            authorization_revision: request.authorization_revision,
            expires_at: request.deadline,
            permit_digest: [0; 32],
        };
        permit.permit_digest =
            read_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, permit);
        let bytes = publisher
            .provider()
            .get_exact(context, permit, request.observed_at)?;
        assert_eq!(u64::try_from(bytes.len())?, chunk.ciphertext_length);
        result.push(bytes);
    }
    Ok(result)
}

fn rewrap_for_receiver(
    source: ContentLayoutTransferHeader,
) -> Result<ContentLayoutTransferHeader, Box<dyn std::error::Error>> {
    let target_cipher =
        ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(2, [25; 32])?);
    let wrapped_key = target_cipher.wrap(
        source.manifest.manifest_id,
        &ContentEncryptionKey::from_bytes([7; 32])?,
        &mut FixedRandom(8),
    )?;
    Ok(ContentLayoutTransferHeader {
        wrapped_key,
        ..source
    })
}

fn reject_corrupt_chunk_before_provider_io(
    receiver: &mut UnprotectedContentPublisher<FolderShardStore, FixedRandom>,
    request: ContentPublicationRequest,
    correct: &BoundedBytes,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut corrupt = correct.as_slice().to_vec();
    corrupt[0] ^= 1;
    let corrupt = BoundedBytes::copy_from(&corrupt, correct.len())?;
    assert!(matches!(
        receiver.store_recovered_content_chunk(request, 0, corrupt),
        Err(ContentPublicationError::Corrupt)
    ));
    assert!(
        receiver
            .provider()
            .inventory_exact(meshspan_contracts::ShardIdentity {
                manifest_digest: request_manifest(receiver, request)?.root_digest,
                stripe_index: 0,
                shard_index: 0,
                generation: 1,
            })?
            .is_none()
    );
    Ok(())
}

fn request_manifest(
    publisher: &UnprotectedContentPublisher<FolderShardStore, FixedRandom>,
    request: ContentPublicationRequest,
) -> Result<meshspan_filesystem::ManifestPublication, Box<dyn std::error::Error>> {
    Ok(publisher
        .catalog()
        .prepared_layout(request)?
        .ok_or("missing recovered layout")?
        .manifest)
}

fn read_exact(
    publisher: &mut UnprotectedContentPublisher<FolderShardStore, FixedRandom>,
    content: PublishedContentReference,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    publisher.stream_range(
        ContentReadRequest {
            operation_id: OperationId::from_bytes([90; 16])?,
            content: PublishedContentReference {
                publication_operation_id: OperationId::from_bytes([40; 16])?,
                ..content
            },
            offset: 0,
            length: content.manifest.logical_length,
            authorization_revision: Revision::new(42),
            deadline: UnixMicros::new(500),
            observed_at: UnixMicros::new(40),
        },
        &mut bytes,
    )?;
    Ok(bytes)
}

fn publication_request(
    operation: u8,
    observed_at: UnixMicros,
) -> Result<ContentPublicationRequest, Box<dyn std::error::Error>> {
    Ok(ContentPublicationRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        volume_id: VolumeId::from_bytes([13; 16])?,
        request_digest: [11; 32],
        manifest_id: ContentManifestId::from_bytes([12; 16])?,
        format_version: 1,
        logical_length: 10,
        authorization_revision: Revision::new(9),
        deadline: UnixMicros::new(500),
        observed_at,
    })
}

fn recovery_request(
    content: PublishedContentReference,
    observed_at: UnixMicros,
) -> Result<ContentPublicationRequest, Box<dyn std::error::Error>> {
    Ok(ContentPublicationRequest {
        operation_id: OperationId::from_bytes([40; 16])?,
        volume_id: VolumeId::from_bytes([13; 16])?,
        request_digest: [41; 32],
        manifest_id: content.manifest.manifest_id,
        format_version: content.manifest.format_version,
        logical_length: content.manifest.logical_length,
        authorization_revision: Revision::new(42),
        deadline: UnixMicros::new(500),
        observed_at,
    })
}

fn open_publisher(
    state_directory: &std::path::Path,
    provider: FolderShardStore,
    registration: FolderRegistration,
    volume_key_byte: u8,
    random_byte: u8,
    opened_at: UnixMicros,
) -> Result<UnprotectedContentPublisher<FolderShardStore, FixedRandom>, Box<dyn std::error::Error>>
{
    Ok(UnprotectedContentPublisher::open(
        state_directory,
        opened_at,
        provider,
        FixedRandom(random_byte),
        VolumeContentKeyring::new(
            VolumeId::from_bytes([13; 16])?,
            VolumeKeyEncryptionKey::from_bytes(
                if volume_key_byte == 24 { 1 } else { 2 },
                [volume_key_byte; 32],
            )?,
        ),
        ContentChunkLimits::new(4)?,
        UnprotectedContentAccess::new(
            registration.mesh_id,
            registration.target_id,
            registration.generation,
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        )?,
    )?)
}

struct StorageFixture {
    storage_path: std::path::PathBuf,
    state_path: std::path::PathBuf,
    registration: FolderRegistration,
    fingerprint: meshspan_storage::MarkerFingerprint,
}

impl StorageFixture {
    fn create(
        root: &std::path::Path,
        name: &str,
        seed: u8,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let storage_path = root.join(format!("{name}-storage"));
        let state_path = root.join(format!("{name}-state"));
        fs::create_dir(&storage_path)?;
        let registration = FolderRegistration {
            mesh_id: MeshId::from_bytes([seed; 16])?,
            target_id: TargetId::from_bytes([seed.saturating_add(2); 16])?,
            generation: 1,
            usage_limit: UsageLimit::DEFAULT,
        };
        let folder = RegisteredFolder::register_new(
            &storage_path,
            registration,
            &mut FixedRandom(seed.saturating_add(3)),
        )?;
        let fingerprint = folder.marker().fingerprint();
        drop(folder);
        Ok(Self {
            storage_path,
            state_path,
            registration,
            fingerprint,
        })
    }

    fn open(&self, opened_at: UnixMicros) -> Result<FolderShardStore, Box<dyn std::error::Error>> {
        let folder =
            RegisteredFolder::reopen(&self.storage_path, self.registration, self.fingerprint)?;
        open_provider(folder, &self.state_path, self.registration, opened_at)
    }

    fn reopen(
        &self,
        opened_at: UnixMicros,
    ) -> Result<FolderShardStore, Box<dyn std::error::Error>> {
        self.open(opened_at)
    }
}

fn open_provider(
    folder: RegisteredFolder,
    state_directory: &std::path::Path,
    registration: FolderRegistration,
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
            registration.mesh_id,
            1,
            Revision::new(1),
            StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
        )?,
        opened_at,
        &mut FixedRandom(99),
    )?)
}

struct FixedRandom(u8);

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(self.0);
        Ok(())
    }
}
