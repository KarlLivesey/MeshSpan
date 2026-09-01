// SPDX-License-Identifier: GPL-2.0-only

//! Verified receiver-side installation of transferred encrypted content.

use meshspan_contracts::{
    BoundedBytes, ContractVersion, PutShardRequest, RequestContext, ReservationClass,
    ReserveStorageRequest, ShardIdentity, StorageProvider,
};
use meshspan_domain::RandomSource;

use super::{UnprotectedContentPublisher, map_catalog, map_contract};
use crate::{
    ContentChunkCipher, ContentChunkLimits, ContentLayoutTransferHeader, ContentLayoutTransferPage,
    ContentPublicationError, ContentPublicationRequest, EncryptedContentChunk, ManifestPublication,
    PendingContentChunkPage,
};

impl<P: StorageProvider, R: RandomSource> UnprotectedContentPublisher<P, R> {
    /// Begins or exactly resumes one receiver-local transferred-layout journal.
    ///
    /// The receiver-wrapped key is authenticated and opened before any untrusted layout state is
    /// accepted. The temporary plaintext key is cleared when this call returns.
    ///
    /// # Errors
    ///
    /// Rejects wrong key authority, malformed headers, expired work and conflicting replay.
    pub fn begin_content_recovery(
        &mut self,
        request: ContentPublicationRequest,
        header: ContentLayoutTransferHeader,
    ) -> Result<(), ContentPublicationError> {
        self.key_envelopes
            .cipher(request.volume_id, header.wrapped_key.key_generation)
            .map_err(map_key)?
            .unwrap(header.manifest.manifest_id, header.wrapped_key)
            .map_err(map_key)?;
        self.catalog
            .begin_layout_import(request, header)
            .map_err(map_catalog)
    }

    /// Appends or exactly replays one bounded provider-neutral layout page.
    ///
    /// # Errors
    ///
    /// Rejects gaps, partial overlap, pagination substitution and conflicting durable state.
    pub fn append_content_recovery_layout(
        &mut self,
        request: ContentPublicationRequest,
        header: ContentLayoutTransferHeader,
        page: &ContentLayoutTransferPage,
    ) -> Result<(), ContentPublicationError> {
        self.catalog
            .append_layout_import_page(request, header, page)
            .map_err(map_catalog)
    }

    /// Seals complete transferred metadata only when it reconstructs the advertised manifest.
    ///
    /// # Errors
    ///
    /// Rejects incomplete, substituted, conflicting or corrupt layout evidence.
    pub fn seal_content_recovery_layout(
        &mut self,
        request: ContentPublicationRequest,
        header: ContentLayoutTransferHeader,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        self.catalog
            .seal_layout_import(request, header)
            .map_err(map_catalog)
    }

    /// Returns a bounded page of encrypted chunks still lacking receiver-local durability.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds, conflicting operation input and corrupt durable metadata.
    pub fn pending_content_recovery(
        &self,
        request: ContentPublicationRequest,
        after_index: Option<u64>,
        limit: usize,
    ) -> Result<PendingContentChunkPage, ContentPublicationError> {
        self.catalog
            .pending_chunks(request, after_index, limit)
            .map_err(map_catalog)
    }

    /// Authenticates and installs one exact encrypted chunk under receiver-local repair authority.
    ///
    /// Ciphertext length/digest, AEAD tag and recovered plaintext identity are all verified before
    /// provider IO. Success is retained only with the destination provider's exact local receipt.
    ///
    /// # Errors
    ///
    /// Rejects chunk substitution, wrong key material, stale authority, provider failure and
    /// conflicting replay.
    pub fn store_recovered_content_chunk(
        &mut self,
        request: ContentPublicationRequest,
        chunk_index: u64,
        ciphertext: BoundedBytes,
    ) -> Result<(), ContentPublicationError> {
        let layout = self
            .catalog
            .prepared_layout(request)
            .map_err(map_catalog)?
            .ok_or(ContentPublicationError::Corrupt)?;
        let chunk = self
            .catalog
            .content_chunk(request, chunk_index)
            .map_err(map_catalog)?;
        let encrypted = EncryptedContentChunk {
            plaintext_length: chunk.plaintext_length,
            plaintext_digest: chunk.plaintext_digest,
            ciphertext_digest: chunk.ciphertext_digest,
            ciphertext,
        };
        verify_recovered_chunk(
            &self.key_envelopes,
            request.volume_id,
            layout,
            chunk_index,
            &encrypted,
        )?;
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
                class: ReservationClass::Repair,
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
                        stripe_index: chunk_index,
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
            .record_receipt(request, chunk_index, receipt, request.observed_at)
            .map_err(map_catalog)
    }

    /// Marks recovered content durable only after every exact local provider receipt exists.
    ///
    /// # Errors
    ///
    /// Rejects incomplete/corrupt layouts and conflicting operation input.
    pub fn finish_content_recovery(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        self.catalog
            .finish(request, request.observed_at)
            .map_err(map_catalog)
    }
}

fn verify_recovered_chunk(
    key_envelopes: &crate::VolumeContentKeyring,
    volume_id: meshspan_domain::VolumeId,
    layout: crate::PreparedContentLayout,
    chunk_index: u64,
    encrypted: &EncryptedContentChunk,
) -> Result<(), ContentPublicationError> {
    if u64::try_from(encrypted.ciphertext.len()).ok()
        != Some(encrypted.plaintext_length.saturating_add(16))
        || blake3::hash(encrypted.ciphertext.as_slice()).as_bytes() != &encrypted.ciphertext_digest
    {
        return Err(ContentPublicationError::Corrupt);
    }
    let content_key = key_envelopes
        .cipher(volume_id, layout.wrapped_key.key_generation)
        .map_err(map_key)?
        .unwrap(layout.manifest.manifest_id, layout.wrapped_key)
        .map_err(map_key)?;
    let limits = ContentChunkLimits::new(
        usize::try_from(layout.chunk_bytes).map_err(|_| ContentPublicationError::Corrupt)?,
    )
    .map_err(|_| ContentPublicationError::Corrupt)?;
    ContentChunkCipher::new(content_key, limits)
        .decrypt(
            layout.manifest.manifest_id,
            layout.manifest.format_version,
            chunk_index,
            encrypted,
        )
        .map_err(|_| ContentPublicationError::Corrupt)?;
    Ok(())
}

fn map_key(error: crate::ContentKeyError) -> ContentPublicationError {
    match error {
        crate::ContentKeyError::InvalidInput | crate::ContentKeyError::Corrupt => {
            ContentPublicationError::Corrupt
        }
        crate::ContentKeyError::Unavailable => ContentPublicationError::Unavailable,
    }
}
