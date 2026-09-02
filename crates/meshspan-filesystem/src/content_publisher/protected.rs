// SPDX-License-Identifier: GPL-2.0-only

//! Protected content publication and reconstruction across routed storage targets.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use cap_std::fs::{Dir, OpenOptions};
use meshspan_contracts::{
    BoundedBytes, BoundedItems, CodingScheme, ContractError, ContractVersion, PlacementCandidate,
    PlacementPolicy, PlacementRequest, PutShardRequest, ReconstructionRequest, RequestContext,
    ReservationClass, ReserveStorageRequest, ShardAcknowledgement, ShardIdentity, ShardReadPermit,
    ShardReceipt, StoragePermitMacKey, StorageProvider, StorageReservation, read_permit_mac,
};
use meshspan_domain::{FailureScenario, MeshId, OperationId, RandomSource, Revision, Topology};

use super::{
    PREPARE_PAGE_ITEMS, cleanup_spool, map_catalog, map_catalog_read, map_contract,
    map_contract_read, map_key_publication, map_key_read, open_spools, provider_operation_id,
    read_operation_id, read_plaintext, spool_name, sync_directory, validate_content_read,
    verify_spool,
};
use crate::{
    CompletedStage, ContentChunkCipher, ContentChunkLimits, ContentEncryptionKey,
    ContentPublicationError, ContentPublicationRequest, ContentReadError, ContentReadRequest,
    DurableContentCatalog, DurableContentPublisher, DurableContentReader, DurableContentSink,
    EncryptedContentChunk, ManifestPublication, PreparedContentChunk, PreparedProtectedShard,
    PreparedProtectedStripe, ProtectedShardCursor, VolumeContentKeyring, VolumeContentKeys,
};

const MAXIMUM_CANDIDATES: usize = 256;
const MAXIMUM_SCENARIOS: usize = 16;

/// Narrow target-aware byte path used by protected publication and reads.
pub trait ContentShardRouter {
    /// Reserves bytes on the exact target incarnation.
    ///
    /// # Errors
    ///
    /// Rejects unknown/stale routes, insufficient capacity and unavailable storage.
    fn reserve(
        &mut self,
        request: ReserveStorageRequest,
    ) -> Result<StorageReservation, ContractError>;

    /// Makes one exact shard durable on its routed target.
    ///
    /// # Errors
    ///
    /// Rejects changed reservations, malformed bytes and unavailable storage.
    fn put_exact(
        &mut self,
        request: PutShardRequest,
        observed_at: meshspan_domain::UnixMicros,
    ) -> Result<ShardReceipt, ContractError>;

    /// Reads one exact verified shard from its routed target.
    ///
    /// # Errors
    ///
    /// Rejects invalid authority, unknown/stale routes, missing bytes and corruption.
    fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
        observed_at: meshspan_domain::UnixMicros,
    ) -> Result<BoundedBytes, ContractError>;
}

impl<Provider: StorageProvider> ContentShardRouter for Provider {
    fn reserve(
        &mut self,
        request: ReserveStorageRequest,
    ) -> Result<StorageReservation, ContractError> {
        StorageProvider::reserve(self, request)
    }

    fn put_exact(
        &mut self,
        request: PutShardRequest,
        observed_at: meshspan_domain::UnixMicros,
    ) -> Result<ShardReceipt, ContractError> {
        StorageProvider::put_exact(self, request, observed_at)
    }

    fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
        observed_at: meshspan_domain::UnixMicros,
    ) -> Result<BoundedBytes, ContractError> {
        StorageProvider::get_exact(self, context, permit, observed_at)
    }
}

/// Fixed-revision topology, capacity and failure promises used for one publication attempt.
#[derive(Clone, Debug)]
pub struct ProtectionConfiguration {
    topology: Topology,
    topology_revision: Revision,
    capacity_revision: Revision,
    scenarios: Vec<FailureScenario>,
    candidates: Vec<PlacementCandidate>,
}

impl ProtectionConfiguration {
    /// Validates one bounded placement snapshot.
    ///
    /// # Errors
    ///
    /// Rejects empty/excessive inputs, zero revisions and duplicate or malformed targets.
    pub fn from_untrusted(
        topology: Topology,
        topology_revision: Revision,
        capacity_revision: Revision,
        scenarios: Vec<FailureScenario>,
        candidates: Vec<PlacementCandidate>,
    ) -> Result<Self, ContentPublicationError> {
        let mut targets = BTreeSet::new();
        if topology_revision == Revision::ZERO
            || capacity_revision == Revision::ZERO
            || scenarios.is_empty()
            || scenarios.len() > MAXIMUM_SCENARIOS
            || candidates.is_empty()
            || candidates.len() > MAXIMUM_CANDIDATES
            || candidates.iter().any(|candidate| {
                candidate.target_generation == 0
                    || candidate.writable_bytes == 0
                    || candidate.performance_weight == 0
                    || !targets.insert(candidate.target_id)
            })
        {
            return Err(ContentPublicationError::InvalidInput);
        }
        Ok(Self {
            topology,
            topology_revision,
            capacity_revision,
            scenarios,
            candidates,
        })
    }
}

/// Shared read authority for every exact target selected by protected placement.
pub struct ProtectedContentAccess {
    mesh_id: MeshId,
    read_permit_key: StoragePermitMacKey,
}

impl ProtectedContentAccess {
    /// Binds protected reads to one mesh authority.
    #[must_use]
    pub const fn new(mesh_id: MeshId, read_permit_key: StoragePermitMacKey) -> Self {
        Self {
            mesh_id,
            read_permit_key,
        }
    }
}

/// Durable encrypted publisher using injected placement, coding and target routing boundaries.
pub struct ProtectedContentPublisher<Router, Coding, Placement, Random, Keys = VolumeContentKeyring>
{
    catalog: DurableContentCatalog,
    spools: Dir,
    router: Router,
    coding: Coding,
    placement: Placement,
    protection: ProtectionConfiguration,
    random: Random,
    key_envelopes: Keys,
    chunk_limits: ContentChunkLimits,
    access: ProtectedContentAccess,
}

impl<Router, Coding, Placement, Random, Keys>
    ProtectedContentPublisher<Router, Coding, Placement, Random, Keys>
where
    Router: ContentShardRouter,
    Coding: CodingScheme,
    Placement: PlacementPolicy,
    Random: RandomSource,
    Keys: VolumeContentKeys,
{
    /// Opens the durable publication journal and private write-spool directory.
    ///
    /// # Errors
    ///
    /// Rejects migration/integrity failure and inaccessible private state.
    #[allow(
        clippy::too_many_arguments,
        reason = "every injected safety boundary is explicit"
    )]
    pub fn open(
        state_directory: &Path,
        opened_at: meshspan_domain::UnixMicros,
        router: Router,
        coding: Coding,
        placement: Placement,
        protection: ProtectionConfiguration,
        random: Random,
        key_envelopes: Keys,
        chunk_limits: ContentChunkLimits,
        access: ProtectedContentAccess,
    ) -> Result<Self, ContentPublicationError> {
        Ok(Self {
            catalog: DurableContentCatalog::open(state_directory, opened_at)
                .map_err(map_catalog)?,
            spools: open_spools(state_directory)?,
            router,
            coding,
            placement,
            protection,
            random,
            key_envelopes,
            chunk_limits,
            access,
        })
    }

    /// Borrows the independently verified durable catalogue.
    #[must_use]
    pub const fn catalog(&self) -> &DurableContentCatalog {
        &self.catalog
    }

    /// Returns the owned routed storage implementation.
    #[must_use]
    pub fn into_router(self) -> Router {
        self.router
    }

    fn prepare_layout(
        &mut self,
        request: ContentPublicationRequest,
        completed: CompletedStage,
        file: &mut cap_std::fs::File,
    ) -> Result<(), ContentPublicationError> {
        if request.format_version != 2 {
            return Err(ContentPublicationError::InvalidInput);
        }
        let content_key = ContentEncryptionKey::generate(&mut self.random)
            .map_err(|_| ContentPublicationError::Unavailable)?;
        let wrapped_key = self
            .key_envelopes
            .wrap_content_key(
                request.volume_id,
                request.manifest_id,
                &content_key,
                &mut self.random,
            )
            .map_err(map_key_publication)?;
        let cipher = ContentChunkCipher::new(content_key, self.chunk_limits);
        let mut candidates = self.protection.candidates.clone();
        file.seek(SeekFrom::Start(0))?;
        let mut remaining = completed.logical_length;
        let mut chunk_index = 0_u64;
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
            let plaintext = BoundedBytes::copy_from(&bytes, requested)
                .map_err(|_| ContentPublicationError::InvalidInput)?;
            let encrypted = cipher
                .encrypt(
                    request.manifest_id,
                    request.format_version,
                    chunk_index,
                    &plaintext,
                )
                .map_err(|_| ContentPublicationError::Corrupt)?;
            let chunk = PreparedContentChunk {
                chunk_index,
                plaintext_length: encrypted.plaintext_length,
                plaintext_digest: encrypted.plaintext_digest,
                ciphertext_length: u64::try_from(encrypted.ciphertext.len())
                    .map_err(|_| ContentPublicationError::InvalidInput)?,
                ciphertext_digest: encrypted.ciphertext_digest,
                storage_layout_digest: [0; 32],
                provider_operation_id: provider_operation_id(request.operation_id, chunk_index)
                    .map_err(|_| ContentPublicationError::Corrupt)?,
            };
            let plan = self.plan_stripe(request, chunk, &candidates)?;
            let slices =
                self.encode_stripe(request, chunk, plan.coding_layout, &encrypted.ciphertext)?;
            let stripe = build_stripe(request, chunk, plan, &slices, &candidates)?;
            consume_capacity(&mut candidates, &stripe)?;
            page.push(stripe);
            if page.len() == PREPARE_PAGE_ITEMS {
                self.catalog
                    .append_protected_stripes(request, &page)
                    .map_err(map_catalog)?;
                page.clear();
            }
            remaining -=
                u64::try_from(requested).map_err(|_| ContentPublicationError::InvalidInput)?;
            chunk_index = chunk_index
                .checked_add(1)
                .ok_or(ContentPublicationError::InvalidInput)?;
        }
        if !page.is_empty() {
            self.catalog
                .append_protected_stripes(request, &page)
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

    fn plan_stripe(
        &self,
        request: ContentPublicationRequest,
        chunk: PreparedContentChunk,
        candidates: &[PlacementCandidate],
    ) -> Result<meshspan_contracts::PlacementPlan, ContentPublicationError> {
        self.placement
            .plan_write(PlacementRequest {
                context: RequestContext {
                    contract_version: ContractVersion::V1_0,
                    operation_id: chunk.provider_operation_id,
                    deadline: request.deadline,
                    expected_revision: Some(request.authorization_revision),
                },
                logical_stripe_bytes: u32::try_from(chunk.ciphertext_length)
                    .map_err(|_| ContentPublicationError::InvalidInput)?,
                scenarios: &self.protection.scenarios,
                topology: &self.protection.topology,
                topology_revision: self.protection.topology_revision,
                capacity_revision: self.protection.capacity_revision,
                candidates,
            })
            .map_err(map_contract)
    }

    fn encode_stripe(
        &self,
        request: ContentPublicationRequest,
        chunk: PreparedContentChunk,
        layout: meshspan_contracts::CodingLayout,
        ciphertext: &BoundedBytes,
    ) -> Result<BoundedItems<BoundedBytes>, ContentPublicationError> {
        self.coding
            .encode(
                RequestContext {
                    contract_version: ContractVersion::V1_0,
                    operation_id: chunk.provider_operation_id,
                    deadline: request.deadline,
                    expected_revision: Some(request.authorization_revision),
                },
                layout,
                ciphertext,
            )
            .map_err(map_contract)
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
            .unwrap_content_key(request.volume_id, request.manifest_id, layout.wrapped_key)
            .map_err(map_key_publication)?;
        let limits = ContentChunkLimits::new(
            usize::try_from(layout.chunk_bytes).map_err(|_| ContentPublicationError::Corrupt)?,
        )
        .map_err(|_| ContentPublicationError::Corrupt)?;
        let cipher = ContentChunkCipher::new(content_key, limits);
        loop {
            let page = self
                .catalog
                .pending_protected_shards(request, None, PREPARE_PAGE_ITEMS)
                .map_err(map_catalog)?;
            if page.shards.is_empty() {
                return self
                    .catalog
                    .finish(request, request.observed_at)
                    .map_err(map_catalog);
            }
            let mut progress = false;
            let mut encoded = None;
            for (cursor, shard) in page.shards.as_slice() {
                if encoded.as_ref().is_none_or(|value: &EncodedStripe| {
                    value.chunk.chunk_index != cursor.chunk_index
                }) {
                    encoded = Some(self.reload_stripe(
                        request,
                        *cursor,
                        file,
                        &cipher,
                        layout.chunk_bytes,
                    )?);
                }
                let value = encoded.as_ref().ok_or(ContentPublicationError::Corrupt)?;
                match self.publish_shard(request, layout.manifest, value, *shard) {
                    Ok(receipt) => {
                        self.catalog
                            .record_protected_receipt(request, receipt, request.observed_at)
                            .map_err(map_catalog)?;
                        progress = true;
                    }
                    Err(ContentPublicationError::Unavailable)
                        if shard.acknowledgement == ShardAcknowledgement::Eventual => {}
                    Err(error) => return Err(error),
                }
            }
            match self.catalog.finish(request, request.observed_at) {
                Ok(manifest) => return Ok(manifest),
                Err(crate::ContentCatalogError::Incomplete) if progress => {}
                Err(crate::ContentCatalogError::Incomplete) => {
                    return Err(ContentPublicationError::Unavailable);
                }
                Err(error) => return Err(map_catalog(error)),
            }
        }
    }

    fn reload_stripe(
        &self,
        request: ContentPublicationRequest,
        cursor: ProtectedShardCursor,
        file: &mut cap_std::fs::File,
        cipher: &ContentChunkCipher,
        chunk_bytes: u64,
    ) -> Result<EncodedStripe, ContentPublicationError> {
        let stripe = self
            .catalog
            .protected_stripe(request, cursor.chunk_index)
            .map_err(map_catalog)?;
        let chunk = stripe.chunk();
        let plaintext = read_plaintext(file, chunk, chunk_bytes)?;
        let encrypted = cipher
            .encrypt(
                request.manifest_id,
                request.format_version,
                chunk.chunk_index,
                &plaintext,
            )
            .map_err(|_| ContentPublicationError::Corrupt)?;
        verify_encrypted_chunk(chunk, &encrypted)?;
        let slices = self.encode_stripe(
            request,
            chunk,
            stripe.coding_layout(),
            &encrypted.ciphertext,
        )?;
        verify_slices(&stripe, &slices)?;
        Ok(EncodedStripe { chunk, slices })
    }

    fn publish_shard(
        &mut self,
        request: ContentPublicationRequest,
        manifest: ManifestPublication,
        encoded: &EncodedStripe,
        shard: PreparedProtectedShard,
    ) -> Result<ShardReceipt, ContentPublicationError> {
        let context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: shard.provider_operation_id,
            deadline: request.deadline,
            expected_revision: Some(request.authorization_revision),
        };
        let reservation = self
            .router
            .reserve(ReserveStorageRequest {
                context,
                target_id: shard.target_id,
                target_generation: shard.target_generation,
                class: ReservationClass::ForegroundWrite,
                bytes: shard.expected_length,
                observed_at: request.observed_at,
            })
            .map_err(map_contract)?;
        self.router
            .put_exact(
                PutShardRequest {
                    context,
                    reservation,
                    shard: ShardIdentity {
                        manifest_digest: manifest.root_digest,
                        stripe_index: encoded.chunk.chunk_index,
                        shard_index: shard.shard_index,
                        generation: shard.shard_generation,
                    },
                    expected_length: shard.expected_length,
                    expected_digest: shard.expected_digest,
                    bytes: encoded.slices.as_slice()[usize::from(shard.shard_index)].clone(),
                },
                request.observed_at,
            )
            .map_err(map_contract)
    }
}

impl<Router, Coding, Placement, Random, Keys> DurableContentPublisher
    for ProtectedContentPublisher<Router, Coding, Placement, Random, Keys>
where
    Router: ContentShardRouter,
    Coding: CodingScheme,
    Placement: PlacementPolicy,
    Random: RandomSource,
    Keys: VolumeContentKeys,
{
    type Sink = DurableContentSink;

    fn resolve(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Option<ManifestPublication>, ContentPublicationError> {
        if request.format_version != 2 {
            return Err(ContentPublicationError::InvalidInput);
        }
        if let Some(manifest) = self.catalog.resolve(request).map_err(map_catalog)? {
            let _cleanup_result = cleanup_spool(&self.spools, request.operation_id);
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
        let _cleanup_result = cleanup_spool(&self.spools, request.operation_id);
        Ok(Some(manifest))
    }

    fn begin(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Self::Sink, ContentPublicationError> {
        if request.format_version != 2 {
            return Err(ContentPublicationError::InvalidInput);
        }
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
        let _cleanup_result = cleanup_spool(&self.spools, request.operation_id);
        Ok(manifest)
    }
}

impl<Router, Coding, Placement, Random, Keys> DurableContentReader
    for ProtectedContentPublisher<Router, Coding, Placement, Random, Keys>
where
    Router: ContentShardRouter,
    Coding: CodingScheme,
    Placement: PlacementPolicy,
    Random: RandomSource,
    Keys: VolumeContentKeys,
{
    fn stream_range(
        &mut self,
        request: ContentReadRequest,
        destination: &mut dyn Write,
    ) -> Result<(), ContentReadError> {
        let end = validate_content_read(request)?;
        if request.content.manifest.format_version != 2 {
            return Err(ContentReadError::InvalidInput);
        }
        let committed = self
            .catalog
            .committed_layout(request.content)
            .map_err(map_catalog_read)?;
        if request.length == 0 {
            return Ok(());
        }
        let content_key = self
            .key_envelopes
            .unwrap_content_key(
                committed.request.volume_id,
                request.content.manifest.manifest_id,
                committed.layout.wrapped_key,
            )
            .map_err(map_key_read)?;
        let limits = ContentChunkLimits::new(
            usize::try_from(committed.layout.chunk_bytes).map_err(|_| ContentReadError::Corrupt)?,
        )
        .map_err(|_| ContentReadError::Corrupt)?;
        let cipher = ContentChunkCipher::new(content_key, limits);
        let first_chunk = request.offset / committed.layout.chunk_bytes;
        let last_chunk = end.div_ceil(committed.layout.chunk_bytes);
        for chunk_index in first_chunk..last_chunk {
            let stripe = self
                .catalog
                .protected_stripe(committed.request, chunk_index)
                .map_err(map_catalog_read)?;
            let encrypted = self.reconstruct_stripe(request, committed.layout.manifest, &stripe)?;
            let plaintext = cipher
                .decrypt(
                    committed.layout.manifest.manifest_id,
                    committed.layout.manifest.format_version,
                    chunk_index,
                    &encrypted,
                )
                .map_err(|_| ContentReadError::Corrupt)?;
            let chunk_start = chunk_index
                .checked_mul(committed.layout.chunk_bytes)
                .ok_or(ContentReadError::Corrupt)?;
            let start = usize::try_from(request.offset.max(chunk_start) - chunk_start)
                .map_err(|_| ContentReadError::Corrupt)?;
            let stop = usize::try_from(
                end.min(chunk_start + stripe.chunk().plaintext_length) - chunk_start,
            )
            .map_err(|_| ContentReadError::Corrupt)?;
            destination.write_all(&plaintext.as_slice()[start..stop])?;
        }
        Ok(())
    }
}

impl<Router, Coding, Placement, Random, Keys>
    ProtectedContentPublisher<Router, Coding, Placement, Random, Keys>
where
    Router: ContentShardRouter,
    Coding: CodingScheme,
{
    fn reconstruct_stripe(
        &self,
        read: ContentReadRequest,
        manifest: ManifestPublication,
        stripe: &PreparedProtectedStripe,
    ) -> Result<EncryptedContentChunk, ContentReadError> {
        let chunk = stripe.chunk();
        let mut available = Vec::with_capacity(stripe.shards().len());
        let mut digests = Vec::with_capacity(stripe.shards().len());
        let mut valid = 0_usize;
        for shard in stripe.shards() {
            digests.push(shard.expected_digest);
            let bytes = self.read_shard(read, manifest, chunk.chunk_index, *shard)?;
            if bytes.is_some() {
                valid += 1;
            }
            available.push(bytes);
        }
        if valid < usize::from(stripe.coding_layout().data_slices()) {
            return Err(ContentReadError::Unavailable);
        }
        let ciphertext = self
            .coding
            .reconstruct(&ReconstructionRequest {
                context: RequestContext {
                    contract_version: ContractVersion::V1_0,
                    operation_id: read_operation_id(read.operation_id, chunk.chunk_index)?,
                    deadline: read.deadline,
                    expected_revision: Some(read.authorization_revision),
                },
                layout: stripe.coding_layout(),
                available_slices: BoundedItems::new(available, stripe.shards().len())
                    .map_err(|_| ContentReadError::Corrupt)?,
                slice_digests: BoundedItems::new(digests, stripe.shards().len())
                    .map_err(|_| ContentReadError::Corrupt)?,
                logical_length: chunk.ciphertext_length,
                logical_digest: chunk.ciphertext_digest,
            })
            .map_err(map_contract_read)?;
        Ok(EncryptedContentChunk {
            plaintext_length: chunk.plaintext_length,
            plaintext_digest: chunk.plaintext_digest,
            ciphertext_digest: chunk.ciphertext_digest,
            ciphertext,
        })
    }

    fn read_shard(
        &self,
        read: ContentReadRequest,
        manifest: ManifestPublication,
        chunk_index: u64,
        shard: PreparedProtectedShard,
    ) -> Result<Option<BoundedBytes>, ContentReadError> {
        let operation_id =
            protected_read_operation_id(read.operation_id, chunk_index, shard.shard_index)?;
        let context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id,
            deadline: read.deadline,
            expected_revision: Some(read.authorization_revision),
        };
        let mut permit = ShardReadPermit {
            operation_id,
            mesh_id: self.access.mesh_id,
            target_id: shard.target_id,
            target_generation: shard.target_generation,
            shard: ShardIdentity {
                manifest_digest: manifest.root_digest,
                stripe_index: chunk_index,
                shard_index: shard.shard_index,
                generation: shard.shard_generation,
            },
            authorization_revision: read.authorization_revision,
            expires_at: read.deadline,
            permit_digest: [0; 32],
        };
        permit.permit_digest = read_permit_mac(&self.access.read_permit_key, permit);
        match self.router.get_exact(context, permit, read.observed_at) {
            Ok(bytes)
                if u64::try_from(bytes.len()).ok() == Some(shard.expected_length)
                    && blake3::hash(bytes.as_slice()).as_bytes() == &shard.expected_digest =>
            {
                Ok(Some(bytes))
            }
            Ok(_)
            | Err(ContractError::Corrupt | ContractError::NotFound | ContractError::Unavailable) => {
                Ok(None)
            }
            Err(error) => Err(map_contract_read(error)),
        }
    }
}

struct EncodedStripe {
    chunk: PreparedContentChunk,
    slices: BoundedItems<BoundedBytes>,
}

fn build_stripe(
    request: ContentPublicationRequest,
    chunk: PreparedContentChunk,
    plan: meshspan_contracts::PlacementPlan,
    slices: &BoundedItems<BoundedBytes>,
    candidates: &[PlacementCandidate],
) -> Result<PreparedProtectedStripe, ContentPublicationError> {
    if slices.len() != plan.slice_targets.len() || slices.len() != plan.acknowledgement_roles.len()
    {
        return Err(ContentPublicationError::Corrupt);
    }
    let shards = slices
        .as_slice()
        .iter()
        .zip(plan.slice_targets.as_slice())
        .zip(plan.acknowledgement_roles.as_slice())
        .enumerate()
        .map(|(index, ((bytes, target_id), acknowledgement))| {
            let candidate = candidates
                .iter()
                .find(|candidate| candidate.target_id == *target_id)
                .ok_or(ContentPublicationError::Corrupt)?;
            Ok::<PreparedProtectedShard, ContentPublicationError>(PreparedProtectedShard {
                shard_index: u16::try_from(index).map_err(|_| ContentPublicationError::Corrupt)?,
                shard_generation: 1,
                provider_operation_id: protected_provider_operation_id(
                    request.operation_id,
                    chunk.chunk_index,
                    u16::try_from(index).map_err(|_| ContentPublicationError::Corrupt)?,
                )?,
                expected_length: u64::try_from(bytes.len())
                    .map_err(|_| ContentPublicationError::Corrupt)?,
                expected_digest: blake3::hash(bytes.as_slice()).into(),
                target_id: *target_id,
                target_generation: candidate.target_generation,
                acknowledgement: *acknowledgement,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    PreparedProtectedStripe::from_untrusted(
        request,
        chunk,
        plan.coding_layout,
        plan.topology_revision,
        plan.capacity_revision,
        plan.policy_evidence,
        shards,
    )
    .map_err(map_catalog)
}

fn consume_capacity(
    candidates: &mut [PlacementCandidate],
    stripe: &PreparedProtectedStripe,
) -> Result<(), ContentPublicationError> {
    for shard in stripe.shards() {
        let candidate = candidates
            .iter_mut()
            .find(|candidate| candidate.target_id == shard.target_id)
            .ok_or(ContentPublicationError::Corrupt)?;
        candidate.writable_bytes = candidate
            .writable_bytes
            .checked_sub(shard.expected_length)
            .ok_or(ContentPublicationError::Unavailable)?;
    }
    Ok(())
}

fn verify_encrypted_chunk(
    expected: PreparedContentChunk,
    actual: &EncryptedContentChunk,
) -> Result<(), ContentPublicationError> {
    if actual.plaintext_length == expected.plaintext_length
        && actual.plaintext_digest == expected.plaintext_digest
        && u64::try_from(actual.ciphertext.len()).ok() == Some(expected.ciphertext_length)
        && actual.ciphertext_digest == expected.ciphertext_digest
    {
        Ok(())
    } else {
        Err(ContentPublicationError::Corrupt)
    }
}

fn verify_slices(
    stripe: &PreparedProtectedStripe,
    slices: &BoundedItems<BoundedBytes>,
) -> Result<(), ContentPublicationError> {
    if slices.len() != stripe.shards().len()
        || slices
            .as_slice()
            .iter()
            .zip(stripe.shards())
            .any(|(bytes, shard)| {
                u64::try_from(bytes.len()).ok() != Some(shard.expected_length)
                    || blake3::hash(bytes.as_slice()).as_bytes() != &shard.expected_digest
            })
    {
        Err(ContentPublicationError::Corrupt)
    } else {
        Ok(())
    }
}

fn protected_provider_operation_id(
    operation_id: OperationId,
    chunk_index: u64,
    shard_index: u16,
) -> Result<OperationId, ContentPublicationError> {
    derived_operation_id(
        b"meshspan.content.protected-provider-operation.v1\0",
        operation_id,
        chunk_index,
        shard_index,
    )
    .map_err(|_| ContentPublicationError::Corrupt)
}

fn protected_read_operation_id(
    operation_id: OperationId,
    chunk_index: u64,
    shard_index: u16,
) -> Result<OperationId, ContentReadError> {
    derived_operation_id(
        b"meshspan.content.protected-read-operation.v1\0",
        operation_id,
        chunk_index,
        shard_index,
    )
    .map_err(|_| ContentReadError::Corrupt)
}

fn derived_operation_id(
    domain: &[u8],
    operation_id: OperationId,
    chunk_index: u64,
    shard_index: u16,
) -> Result<OperationId, meshspan_domain::IdentifierError> {
    let mut digest = blake3::Hasher::new();
    digest.update(domain);
    digest.update(&operation_id.as_bytes());
    digest.update(&chunk_index.to_be_bytes());
    digest.update(&shard_index.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    OperationId::from_bytes(meshspan_domain::uuid_v8(bytes))
}
