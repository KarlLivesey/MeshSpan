// SPDX-License-Identifier: GPL-2.0-only

//! Recoverable encrypted chunk publication through the replaceable storage-provider contract.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use meshspan_contracts::{
    ContractError, ContractVersion, PutShardRequest, RequestContext, ReservationClass,
    ReserveStorageRequest, ShardIdentity, ShardReadPermit, StoragePermitMacKey, StorageProvider,
    read_permit_mac,
};
use meshspan_domain::{MeshId, OperationId, RandomSource, TargetId};

use crate::content_transfer::provider_operation_id;
use crate::{
    CompletedStage, ContentCatalogError, ContentChunkCipher, ContentChunkLimits,
    ContentEncryptionKey, ContentKeyEnvelopeCipher, ContentPublicationError,
    ContentPublicationRequest, ContentReadError, ContentReadRequest, DurableContentCatalog,
    DurableContentPublisher, DurableContentReader, EncryptedContentChunk, ManifestPublication,
    PreparedContentChunk,
};

mod recovery;

const SPOOL_DIRECTORY: &str = "content-spools";
const PREPARE_PAGE_ITEMS: usize = 1_000;
const COPY_BUFFER_BYTES: usize = 64 * 1_024;

/// Single-target placement and read capability for the initial unprotected layout.
pub struct UnprotectedContentAccess {
    /// Mesh whose authority signs storage reads.
    mesh_id: MeshId,
    /// Registered provider target identity.
    target_id: TargetId,
    /// Positive target incarnation admitted by authority.
    target_generation: u64,
    /// Non-exportable authority for short-lived exact-shard read permits.
    read_permit_key: StoragePermitMacKey,
}

impl UnprotectedContentAccess {
    /// Binds one target generation to its mesh read authority.
    ///
    /// # Errors
    ///
    /// Rejects the reserved zero target generation.
    pub const fn new(
        mesh_id: MeshId,
        target_id: TargetId,
        target_generation: u64,
        read_permit_key: StoragePermitMacKey,
    ) -> Result<Self, ContentPublicationError> {
        if target_generation == 0 {
            Err(ContentPublicationError::InvalidInput)
        } else {
            Ok(Self {
                mesh_id,
                target_id,
                target_generation,
                read_permit_key,
            })
        }
    }
}

/// Private file-backed sink used while a stage is not yet content-durable.
pub struct DurableContentSink {
    operation_id: OperationId,
    file: cap_std::fs::File,
}

struct ContentReadTraversal<'a> {
    read: ContentReadRequest,
    read_end: u64,
    publication: ContentPublicationRequest,
    layout: crate::PreparedContentLayout,
    cipher: &'a ContentChunkCipher,
}

impl Write for DurableContentSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.file.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Production initial publisher: encrypted fixed-size chunks with one unprotected provider shard.
///
/// Stage 8 replaces the one-shard layout selection with placement and erasure coding while
/// retaining this durable catalogue, wrapped-key, bounded-spool and exact-receipt lifecycle.
pub struct UnprotectedContentPublisher<P, R> {
    catalog: DurableContentCatalog,
    spools: Dir,
    provider: P,
    random: R,
    key_envelopes: ContentKeyEnvelopeCipher,
    chunk_limits: ContentChunkLimits,
    access: UnprotectedContentAccess,
}

impl<P: StorageProvider, R: RandomSource> UnprotectedContentPublisher<P, R> {
    /// Opens the durable catalogue and private spool directory.
    ///
    /// # Errors
    ///
    /// Rejects invalid target generation, migration/integrity failure and filesystem IO.
    pub fn open(
        state_directory: &Path,
        opened_at: meshspan_domain::UnixMicros,
        provider: P,
        random: R,
        key_envelopes: ContentKeyEnvelopeCipher,
        chunk_limits: ContentChunkLimits,
        access: UnprotectedContentAccess,
    ) -> Result<Self, ContentPublicationError> {
        fs::create_dir_all(state_directory)?;
        let root = Dir::open_ambient_dir(state_directory, ambient_authority())?;
        match root.create_dir(SPOOL_DIRECTORY) {
            Ok(()) => sync_directory(&root)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Self {
            catalog: DurableContentCatalog::open(state_directory, opened_at)
                .map_err(map_catalog)?,
            spools: root.open_dir(SPOOL_DIRECTORY)?,
            provider,
            random,
            key_envelopes,
            chunk_limits,
            access,
        })
    }

    /// Returns the owned provider after orderly shutdown or for integration verification.
    #[must_use]
    pub fn into_provider(self) -> P {
        self.provider
    }

    /// Borrows the provider for verified read integration.
    #[must_use]
    pub const fn provider(&self) -> &P {
        &self.provider
    }

    /// Borrows the independently verified durable manifest catalogue.
    #[must_use]
    pub const fn catalog(&self) -> &DurableContentCatalog {
        &self.catalog
    }

    fn publish_pending(
        &mut self,
        request: ContentPublicationRequest,
        file: &mut cap_std::fs::File,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        let layout = self
            .catalog
            .prepared_layout(request)
            .map_err(map_catalog)?
            .ok_or(ContentPublicationError::Corrupt)?;
        let content_key = self
            .key_envelopes
            .unwrap(request.manifest_id, layout.wrapped_key)
            .map_err(|_| ContentPublicationError::Corrupt)?;
        let limits = ContentChunkLimits::new(
            usize::try_from(layout.chunk_bytes).map_err(|_| ContentPublicationError::Corrupt)?,
        )
        .map_err(|_| ContentPublicationError::Corrupt)?;
        let cipher = ContentChunkCipher::new(content_key, limits);
        loop {
            let page = self
                .catalog
                .pending_chunks(request, None, PREPARE_PAGE_ITEMS)
                .map_err(map_catalog)?;
            if page.chunks.is_empty() {
                return self
                    .catalog
                    .finish(request, request.observed_at)
                    .map_err(map_catalog);
            }
            for chunk in page.chunks.as_slice() {
                let plaintext = read_plaintext(file, *chunk, layout.chunk_bytes)?;
                let encrypted = cipher
                    .encrypt(
                        request.manifest_id,
                        request.format_version,
                        chunk.chunk_index,
                        &plaintext,
                    )
                    .map_err(|_| ContentPublicationError::Corrupt)?;
                if encrypted.plaintext_length != chunk.plaintext_length
                    || encrypted.plaintext_digest != chunk.plaintext_digest
                    || u64::try_from(encrypted.ciphertext.len())
                        .map_err(|_| ContentPublicationError::Corrupt)?
                        != chunk.ciphertext_length
                    || encrypted.ciphertext_digest != chunk.ciphertext_digest
                {
                    return Err(ContentPublicationError::Corrupt);
                }
                let context = RequestContext {
                    contract_version: ContractVersion::V1_0,
                    operation_id: chunk.provider_operation_id,
                    deadline: request.deadline,
                    expected_revision: Some(request.authorization_revision),
                };
                let reservation = self
                    .provider
                    .reserve(ReserveStorageRequest {
                        context,
                        target_id: self.access.target_id,
                        target_generation: self.access.target_generation,
                        class: ReservationClass::ForegroundWrite,
                        bytes: chunk.ciphertext_length,
                        observed_at: request.observed_at,
                    })
                    .map_err(map_contract)?;
                let receipt = self
                    .provider
                    .put_exact(
                        PutShardRequest {
                            context,
                            reservation,
                            shard: ShardIdentity {
                                manifest_digest: layout.manifest.root_digest,
                                stripe_index: chunk.chunk_index,
                                shard_index: 0,
                                generation: 1,
                            },
                            expected_length: chunk.ciphertext_length,
                            expected_digest: chunk.ciphertext_digest,
                            bytes: encrypted.ciphertext,
                        },
                        request.observed_at,
                    )
                    .map_err(map_contract)?;
                self.catalog
                    .record_receipt(request, chunk.chunk_index, receipt, request.observed_at)
                    .map_err(map_catalog)?;
            }
        }
    }

    fn prepare_layout(
        &mut self,
        request: ContentPublicationRequest,
        completed: CompletedStage,
        file: &mut cap_std::fs::File,
    ) -> Result<(), ContentPublicationError> {
        let content_key = ContentEncryptionKey::generate(&mut self.random)
            .map_err(|_| ContentPublicationError::Unavailable)?;
        let wrapped_key = self
            .key_envelopes
            .wrap(request.manifest_id, &content_key, &mut self.random)
            .map_err(|_| ContentPublicationError::Unavailable)?;
        let cipher = ContentChunkCipher::new(content_key, self.chunk_limits);
        file.seek(SeekFrom::Start(0))?;
        let mut remaining = completed.logical_length;
        let mut index = 0_u64;
        let mut page = Vec::with_capacity(PREPARE_PAGE_ITEMS);
        while remaining != 0 {
            let requested = usize::try_from(
                remaining.min(
                    u64::try_from(self.chunk_limits.maximum_plaintext_bytes())
                        .map_err(|_| ContentPublicationError::InvalidInput)?,
                ),
            )
            .map_err(|_| ContentPublicationError::InvalidInput)?;
            let mut bytes = vec![0_u8; requested];
            file.read_exact(&mut bytes)?;
            let plaintext = meshspan_contracts::BoundedBytes::copy_from(&bytes, requested)
                .map_err(|_| ContentPublicationError::InvalidInput)?;
            let encrypted = cipher
                .encrypt(
                    request.manifest_id,
                    request.format_version,
                    index,
                    &plaintext,
                )
                .map_err(|_| ContentPublicationError::Corrupt)?;
            page.push(PreparedContentChunk {
                chunk_index: index,
                plaintext_length: encrypted.plaintext_length,
                plaintext_digest: encrypted.plaintext_digest,
                ciphertext_length: u64::try_from(encrypted.ciphertext.len())
                    .map_err(|_| ContentPublicationError::InvalidInput)?,
                ciphertext_digest: encrypted.ciphertext_digest,
                provider_operation_id: provider_operation_id(request.operation_id, index)
                    .map_err(|_| ContentPublicationError::Corrupt)?,
            });
            if page.len() == PREPARE_PAGE_ITEMS {
                self.catalog
                    .append_chunks(request, &page)
                    .map_err(map_catalog)?;
                page.clear();
            }
            remaining -=
                u64::try_from(requested).map_err(|_| ContentPublicationError::InvalidInput)?;
            index = index
                .checked_add(1)
                .ok_or(ContentPublicationError::InvalidInput)?;
        }
        if !page.is_empty() {
            self.catalog
                .append_chunks(request, &page)
                .map_err(map_catalog)?;
        }
        self.catalog
            .seal_layout(
                request,
                completed,
                u64::try_from(self.chunk_limits.maximum_plaintext_bytes())
                    .map_err(|_| ContentPublicationError::InvalidInput)?,
                wrapped_key,
            )
            .map_err(map_catalog)?;
        Ok(())
    }
}

impl<P: StorageProvider, R: RandomSource> DurableContentPublisher
    for UnprotectedContentPublisher<P, R>
{
    type Sink = DurableContentSink;

    fn resolve(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Option<ManifestPublication>, ContentPublicationError> {
        if let Some(manifest) = self.catalog.resolve(request).map_err(map_catalog)? {
            let _cleanup_result = self.cleanup_spool(request.operation_id);
            return Ok(Some(manifest));
        }
        if self
            .catalog
            .prepared_layout(request)
            .map_err(map_catalog)?
            .is_none()
        {
            return Ok(None);
        }
        let mut file = self.spools.open(spool_name(request.operation_id))?;
        let manifest = self.publish_pending(request, &mut file)?;
        drop(file);
        let _cleanup_result = self.cleanup_spool(request.operation_id);
        Ok(Some(manifest))
    }

    fn begin(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Self::Sink, ContentPublicationError> {
        self.catalog.begin(request).map_err(map_catalog)?;
        if self
            .catalog
            .prepared_layout(request)
            .map_err(map_catalog)?
            .is_some()
        {
            return Err(ContentPublicationError::Conflict);
        }
        let name = spool_name(request.operation_id);
        match self.spools.remove_file(&name) {
            Ok(()) => sync_directory(&self.spools)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        Ok(DurableContentSink {
            operation_id: request.operation_id,
            file: self.spools.open_with(&name, &options)?,
        })
    }

    fn finish(
        &mut self,
        request: ContentPublicationRequest,
        mut sink: Self::Sink,
        completed: CompletedStage,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        if sink.operation_id != request.operation_id {
            return Err(ContentPublicationError::Conflict);
        }
        sink.file.sync_all()?;
        verify_spool(&mut sink.file, completed)?;
        self.prepare_layout(request, completed, &mut sink.file)?;
        let manifest = self.publish_pending(request, &mut sink.file)?;
        drop(sink);
        let _cleanup_result = self.cleanup_spool(request.operation_id);
        Ok(manifest)
    }
}

impl<P: StorageProvider, R: RandomSource> DurableContentReader
    for UnprotectedContentPublisher<P, R>
{
    fn stream_range(
        &mut self,
        request: ContentReadRequest,
        destination: &mut dyn Write,
    ) -> Result<(), ContentReadError> {
        let end = validate_content_read(request)?;
        let committed = self
            .catalog
            .committed_layout(request.content)
            .map_err(map_catalog_read)?;
        if request.length == 0 {
            return Ok(());
        }
        let content_key = self
            .key_envelopes
            .unwrap(
                request.content.manifest.manifest_id,
                committed.layout.wrapped_key,
            )
            .map_err(|_| ContentReadError::Corrupt)?;
        let limits = ContentChunkLimits::new(
            usize::try_from(committed.layout.chunk_bytes).map_err(|_| ContentReadError::Corrupt)?,
        )
        .map_err(|_| ContentReadError::Corrupt)?;
        let cipher = ContentChunkCipher::new(content_key, limits);
        let first_chunk = request.offset / committed.layout.chunk_bytes;
        let last_chunk = end.div_ceil(committed.layout.chunk_bytes);
        let traversal = ContentReadTraversal {
            read: request,
            read_end: end,
            publication: committed.request,
            layout: committed.layout,
            cipher: &cipher,
        };
        for chunk_index in first_chunk..last_chunk {
            self.stream_chunk_slice(&traversal, chunk_index, destination)?;
        }
        Ok(())
    }
}

impl<P: StorageProvider, R> UnprotectedContentPublisher<P, R> {
    fn stream_chunk_slice(
        &self,
        traversal: &ContentReadTraversal<'_>,
        chunk_index: u64,
        destination: &mut dyn Write,
    ) -> Result<(), ContentReadError> {
        let chunk = self
            .catalog
            .content_chunk(traversal.publication, chunk_index)
            .map_err(map_catalog_read)?;
        let chunk_start = chunk_index
            .checked_mul(traversal.layout.chunk_bytes)
            .ok_or(ContentReadError::Corrupt)?;
        let expected_length = traversal
            .layout
            .manifest
            .logical_length
            .checked_sub(chunk_start)
            .ok_or(ContentReadError::Corrupt)?
            .min(traversal.layout.chunk_bytes);
        if chunk.plaintext_length != expected_length {
            return Err(ContentReadError::Corrupt);
        }
        let encrypted = self.read_encrypted_chunk(traversal.read, traversal.layout, chunk)?;
        let plaintext = traversal
            .cipher
            .decrypt(
                traversal.layout.manifest.manifest_id,
                traversal.layout.manifest.format_version,
                chunk_index,
                &encrypted,
            )
            .map_err(|_| ContentReadError::Corrupt)?;
        let start = usize::try_from(traversal.read.offset.max(chunk_start) - chunk_start)
            .map_err(|_| ContentReadError::Corrupt)?;
        let end = usize::try_from(
            traversal.read_end.min(chunk_start + chunk.plaintext_length) - chunk_start,
        )
        .map_err(|_| ContentReadError::Corrupt)?;
        destination.write_all(&plaintext.as_slice()[start..end])?;
        Ok(())
    }

    fn read_encrypted_chunk(
        &self,
        read: ContentReadRequest,
        layout: crate::PreparedContentLayout,
        chunk: PreparedContentChunk,
    ) -> Result<EncryptedContentChunk, ContentReadError> {
        let operation_id = read_operation_id(read.operation_id, chunk.chunk_index)?;
        let context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id,
            deadline: read.deadline,
            expected_revision: Some(read.authorization_revision),
        };
        let mut permit = ShardReadPermit {
            operation_id,
            mesh_id: self.access.mesh_id,
            target_id: self.access.target_id,
            target_generation: self.access.target_generation,
            shard: ShardIdentity {
                manifest_digest: layout.manifest.root_digest,
                stripe_index: chunk.chunk_index,
                shard_index: 0,
                generation: 1,
            },
            authorization_revision: read.authorization_revision,
            expires_at: read.deadline,
            permit_digest: [0; 32],
        };
        permit.permit_digest = read_permit_mac(&self.access.read_permit_key, permit);
        let ciphertext = self
            .provider
            .get_exact(context, permit, read.observed_at)
            .map_err(map_contract_read)?;
        if u64::try_from(ciphertext.len()).ok() != Some(chunk.ciphertext_length)
            || blake3::hash(ciphertext.as_slice()).as_bytes() != &chunk.ciphertext_digest
        {
            return Err(ContentReadError::Corrupt);
        }
        Ok(EncryptedContentChunk {
            plaintext_length: chunk.plaintext_length,
            plaintext_digest: chunk.plaintext_digest,
            ciphertext_digest: chunk.ciphertext_digest,
            ciphertext,
        })
    }
}

impl<P, R> UnprotectedContentPublisher<P, R> {
    fn cleanup_spool(&self, operation_id: OperationId) -> std::io::Result<()> {
        match self.spools.remove_file(spool_name(operation_id)) {
            Ok(()) => sync_directory(&self.spools),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn validate_content_read(request: ContentReadRequest) -> Result<u64, ContentReadError> {
    let end = request
        .offset
        .checked_add(request.length)
        .ok_or(ContentReadError::InvalidInput)?;
    if request.authorization_revision.get() == 0
        || request.observed_at >= request.deadline
        || end > request.content.manifest.logical_length
        || request.content.manifest.format_version == 0
    {
        Err(ContentReadError::InvalidInput)
    } else {
        Ok(end)
    }
}

fn read_operation_id(
    operation_id: OperationId,
    chunk_index: u64,
) -> Result<OperationId, ContentReadError> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.content.read-operation.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&chunk_index.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    OperationId::from_bytes(meshspan_domain::uuid_v8(bytes)).map_err(|_| ContentReadError::Corrupt)
}

fn read_plaintext(
    file: &mut cap_std::fs::File,
    chunk: PreparedContentChunk,
    chunk_bytes: u64,
) -> Result<meshspan_contracts::BoundedBytes, ContentPublicationError> {
    let offset = chunk
        .chunk_index
        .checked_mul(chunk_bytes)
        .ok_or(ContentPublicationError::Corrupt)?;
    file.seek(SeekFrom::Start(offset))?;
    let length =
        usize::try_from(chunk.plaintext_length).map_err(|_| ContentPublicationError::Corrupt)?;
    let mut bytes = vec![0_u8; length];
    file.read_exact(&mut bytes)?;
    meshspan_contracts::BoundedBytes::copy_from(&bytes, length)
        .map_err(|_| ContentPublicationError::Corrupt)
}

fn verify_spool(
    file: &mut cap_std::fs::File,
    completed: CompletedStage,
) -> Result<(), ContentPublicationError> {
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = completed.logical_length;
    let mut digest = blake3::Hasher::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    while remaining != 0 {
        let requested = usize::try_from(remaining.min(
            u64::try_from(COPY_BUFFER_BYTES).map_err(|_| ContentPublicationError::InvalidInput)?,
        ))
        .map_err(|_| ContentPublicationError::InvalidInput)?;
        let read = file.read(&mut buffer[..requested])?;
        if read == 0 {
            return Err(ContentPublicationError::Corrupt);
        }
        digest.update(&buffer[..read]);
        remaining -= u64::try_from(read).map_err(|_| ContentPublicationError::Corrupt)?;
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 || digest.finalize().as_bytes() != &completed.content_digest {
        Err(ContentPublicationError::Corrupt)
    } else {
        Ok(())
    }
}

fn spool_name(operation_id: OperationId) -> String {
    format!("{operation_id}.pending")
}

fn sync_directory(directory: &Dir) -> std::io::Result<()> {
    directory.open(".")?.sync_all()
}

fn map_catalog(error: ContentCatalogError) -> ContentPublicationError {
    match error {
        ContentCatalogError::InvalidInput => ContentPublicationError::InvalidInput,
        ContentCatalogError::Conflict => ContentPublicationError::Conflict,
        ContentCatalogError::Incomplete | ContentCatalogError::Sqlite(_) => {
            ContentPublicationError::Unavailable
        }
        ContentCatalogError::Corrupt => ContentPublicationError::Corrupt,
        ContentCatalogError::Io(error) => ContentPublicationError::Io(error),
    }
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

fn map_catalog_read(error: ContentCatalogError) -> ContentReadError {
    match error {
        ContentCatalogError::InvalidInput => ContentReadError::InvalidInput,
        ContentCatalogError::Conflict => ContentReadError::Conflict,
        ContentCatalogError::Corrupt => ContentReadError::Corrupt,
        ContentCatalogError::Incomplete | ContentCatalogError::Sqlite(_) => {
            ContentReadError::Unavailable
        }
        ContentCatalogError::Io(error) => ContentReadError::Io(error),
    }
}

fn map_contract_read(error: ContractError) -> ContentReadError {
    match error {
        ContractError::InvalidInput | ContractError::UnsupportedVersion => {
            ContentReadError::InvalidInput
        }
        ContractError::Conflict => ContentReadError::Conflict,
        ContractError::Corrupt | ContractError::InternalContract => ContentReadError::Corrupt,
        ContractError::Unauthorized
        | ContractError::Stale
        | ContractError::NotFound
        | ContractError::ResourceExhausted
        | ContractError::DeadlineExceeded
        | ContractError::Unavailable => ContentReadError::Unavailable,
    }
}
