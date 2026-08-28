// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{ShardIdentity, ShardReceipt};
use meshspan_domain::{
    ContentManifestId, EntropyError, OperationId, RandomSource, Revision, TargetId, UnixMicros,
};
use tempfile::tempdir;

use super::{ContentCatalogError, DurableContentCatalog, PreparedContentChunk};
use crate::{
    CompletedStage, ContentEncryptionKey, ContentKeyEnvelopeCipher, ContentPublicationRequest,
    VolumeKeyEncryptionKey,
};

#[test]
fn paged_layout_receipts_restart_and_exact_replay_are_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let request = request()?;
    let mut catalog = DurableContentCatalog::open(directory.path(), UnixMicros::new(1))?;
    catalog.begin(request)?;
    let chunks = chunks()?;
    catalog.append_chunks(request, &chunks[..2])?;
    catalog.append_chunks(request, &chunks[2..])?;
    let completed = CompletedStage {
        logical_length: 6,
        content_digest: [9; 32],
    };
    let manifest = catalog.seal_layout(request, completed, 2, wrapped_key()?)?;
    assert!(matches!(
        catalog.finish(request, UnixMicros::new(5)),
        Err(ContentCatalogError::Incomplete)
    ));
    let first = catalog.pending_chunks(request, None, 2)?;
    assert_eq!(first.chunks.as_slice(), &chunks[..2]);
    assert_eq!(first.next_index, Some(1));
    let second = catalog.pending_chunks(request, first.next_index, 2)?;
    assert_eq!(second.chunks.as_slice(), &chunks[2..]);
    assert_eq!(second.next_index, None);

    for chunk in chunks {
        let receipt = receipt(chunk, manifest.root_digest)?;
        catalog.record_receipt(request, chunk.chunk_index, receipt, UnixMicros::new(4))?;
        catalog.record_receipt(request, chunk.chunk_index, receipt, UnixMicros::new(4))?;
    }
    assert!(catalog.pending_chunks(request, None, 10)?.chunks.is_empty());
    assert_eq!(catalog.finish(request, UnixMicros::new(5))?, manifest);
    drop(catalog);

    let reopened = DurableContentCatalog::open(directory.path(), UnixMicros::new(6))?;
    let expired_resolution = ContentPublicationRequest {
        observed_at: UnixMicros::new(101),
        ..request
    };
    assert_eq!(reopened.resolve(expired_resolution)?, Some(manifest));
    let mut conflict = request;
    conflict.request_digest[0] ^= 1;
    assert!(matches!(
        reopened.resolve(conflict),
        Err(ContentCatalogError::Conflict)
    ));
    Ok(())
}

#[test]
fn gaps_wrong_receipts_and_conflicting_reseal_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let request = request()?;
    let mut catalog = DurableContentCatalog::open(directory.path(), UnixMicros::new(1))?;
    catalog.begin(request)?;
    let mut chunk = chunks()?[0];
    chunk.chunk_index = 1;
    assert!(matches!(
        catalog.append_chunks(request, &[chunk]),
        Err(ContentCatalogError::InvalidInput)
    ));
    let chunks = chunks()?;
    catalog.append_chunks(request, &chunks)?;
    let completed = CompletedStage {
        logical_length: 6,
        content_digest: [9; 32],
    };
    let manifest = catalog.seal_layout(request, completed, 2, wrapped_key()?)?;
    let mut wrong = receipt(chunks[0], manifest.root_digest)?;
    wrong.digest[0] ^= 1;
    assert!(matches!(
        catalog.record_receipt(request, 0, wrong, UnixMicros::new(4)),
        Err(ContentCatalogError::InvalidInput)
    ));
    let mut different = wrapped_key()?;
    different.envelope_digest[0] ^= 1;
    assert!(matches!(
        catalog.seal_layout(request, completed, 2, different),
        Err(ContentCatalogError::Conflict)
    ));
    Ok(())
}

fn request() -> Result<ContentPublicationRequest, Box<dyn std::error::Error>> {
    Ok(ContentPublicationRequest {
        operation_id: OperationId::from_bytes([1; 16])?,
        request_digest: [2; 32],
        manifest_id: ContentManifestId::from_bytes([3; 16])?,
        format_version: 1,
        logical_length: 6,
        authorization_revision: Revision::new(4),
        deadline: UnixMicros::new(100),
        observed_at: UnixMicros::new(2),
    })
}

fn chunks() -> Result<[PreparedContentChunk; 3], Box<dyn std::error::Error>> {
    Ok([chunk(0, 20)?, chunk(1, 21)?, chunk(2, 22)?])
}

fn chunk(
    chunk_index: u64,
    operation_byte: u8,
) -> Result<PreparedContentChunk, Box<dyn std::error::Error>> {
    Ok(PreparedContentChunk {
        chunk_index,
        plaintext_length: 2,
        plaintext_digest: [operation_byte; 32],
        ciphertext_length: 18,
        ciphertext_digest: [operation_byte.saturating_add(10); 32],
        provider_operation_id: OperationId::from_bytes([operation_byte; 16])?,
    })
}

fn wrapped_key() -> Result<crate::WrappedContentKey, Box<dyn std::error::Error>> {
    let cipher = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(1, [5; 32])?);
    Ok(cipher.wrap(
        ContentManifestId::from_bytes([3; 16])?,
        &ContentEncryptionKey::from_bytes([6; 32])?,
        &mut FixedRandom,
    )?)
}

fn receipt(
    chunk: PreparedContentChunk,
    root_digest: [u8; 32],
) -> Result<ShardReceipt, Box<dyn std::error::Error>> {
    Ok(ShardReceipt {
        operation_id: chunk.provider_operation_id,
        shard: ShardIdentity {
            manifest_digest: root_digest,
            stripe_index: chunk.chunk_index,
            shard_index: 0,
            generation: 1,
        },
        length: chunk.ciphertext_length,
        digest: chunk.ciphertext_digest,
        target_id: TargetId::from_bytes([30; 16])?,
        target_generation: 1,
    })
}

struct FixedRandom;

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(7);
        Ok(())
    }
}
