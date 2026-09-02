// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{
    BoundedBytes, CodingLayout, ShardAcknowledgement, ShardIdentity, ShardReceipt, VersionedPayload,
};
use meshspan_domain::{
    ContentManifestId, DurationMicros, EntropyError, NodeId, OperationId, RandomSource, Revision,
    TargetId, UnixMicros, VolumeId,
};
use tempfile::tempdir;

use super::{
    ContentCatalogError, DurableContentCatalog, PreparedContentChunk, PreparedProtectedShard,
    PreparedProtectedStripe, ProtectedShardCursor, ShardRepairTransition,
};
use crate::{
    CompletedStage, ContentAcknowledgementClass, ContentAcknowledgementPolicy,
    ContentEncryptionKey, ContentKeyEnvelopeCipher, ContentLayoutChunk,
    ContentLayoutTransferHeader, ContentLayoutTransferPage, ContentPublicationRequest,
    ContentStrongFallback, PublishedContentReference, VolumeKeyEncryptionKey,
};

struct SourceLayoutFixture {
    manifest: crate::ManifestPublication,
    header: ContentLayoutTransferHeader,
    first_page: ContentLayoutTransferPage,
    second_page: ContentLayoutTransferPage,
    chunks: [PreparedContentChunk; 3],
}

#[test]
fn protected_stripe_plan_and_receipts_survive_restart_before_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (request, stripe) = protected_fixture()?;
    assert_ne!(stripe.chunk().storage_layout_digest, [0; 32]);

    let manifest = {
        let mut catalog = DurableContentCatalog::open(directory.path(), UnixMicros::new(1))?;
        catalog.begin(request)?;
        assert!(matches!(
            catalog.append_chunks(request, &[stripe.chunk()]),
            Err(ContentCatalogError::InvalidInput)
        ));
        catalog.append_protected_stripes(request, std::slice::from_ref(&stripe))?;
        let manifest = catalog.seal_layout(
            request,
            CompletedStage {
                logical_length: 2,
                content_digest: [9; 32],
            },
            2,
            wrapped_key()?,
        )?;
        assert!(matches!(
            catalog.finish(request, UnixMicros::new(4)),
            Err(ContentCatalogError::Incomplete)
        ));
        let first = catalog.pending_protected_shards(request, None, 2)?;
        assert_eq!(first.shards.len(), 2);
        assert_eq!(
            first.next,
            Some(ProtectedShardCursor {
                chunk_index: 0,
                shard_index: 1,
            })
        );
        manifest
    };

    let mut catalog = DurableContentCatalog::open(directory.path(), UnixMicros::new(5))?;
    assert_eq!(catalog.protected_stripe(request, 0)?, stripe);
    let pending = catalog.pending_protected_shards(request, None, 10)?;
    assert_eq!(pending.shards.len(), 4);
    for (cursor, shard) in pending
        .shards
        .as_slice()
        .iter()
        .filter(|(_, shard)| shard.acknowledgement == ShardAcknowledgement::Required)
    {
        let receipt = protected_receipt(manifest.root_digest, *cursor, *shard);
        catalog.record_protected_receipt(request, receipt, UnixMicros::new(6))?;
        catalog.record_protected_receipt(request, receipt, UnixMicros::new(7))?;
    }
    let eventual = catalog.pending_protected_shards(request, None, 10)?;
    assert_eq!(eventual.shards.len(), 1);
    assert_eq!(catalog.finish(request, UnixMicros::new(8))?, manifest);
    let (cursor, shard) = eventual.shards.as_slice()[0];
    catalog.record_protected_receipt(
        request,
        protected_receipt(manifest.root_digest, cursor, shard),
        UnixMicros::new(9),
    )?;
    assert!(
        catalog
            .pending_protected_shards(request, None, 10)?
            .shards
            .is_empty()
    );
    drop(catalog);

    let catalog = DurableContentCatalog::open(directory.path(), UnixMicros::new(9))?;
    assert_eq!(catalog.resolve(request)?, Some(manifest));
    Ok(())
}

#[test]
fn strong_deadline_never_silently_falls_back_and_persists_an_explicit_eventual_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    for fallback in [
        ContentStrongFallback::RemainPending,
        ContentStrongFallback::FailAtDeadline,
    ] {
        let directory = tempdir()?;
        let (request, _) = protected_fixture()?;
        let mut catalog = DurableContentCatalog::open(directory.path(), UnixMicros::new(1))?;
        catalog.begin(request)?;
        catalog.configure_protected_acknowledgement(
            request,
            strong_policy(fallback),
            meshspan_domain::DurabilityScope::CellReplicated,
        )?;
        let before_deadline = ContentPublicationRequest {
            observed_at: UnixMicros::new(14),
            ..request
        };
        assert_eq!(
            catalog.strong_fallback_for_attempt(before_deadline)?,
            Some(ContentStrongFallback::RemainPending)
        );
        let at_deadline = ContentPublicationRequest {
            observed_at: UnixMicros::new(15),
            ..request
        };
        assert_eq!(
            catalog.strong_fallback_for_attempt(at_deadline)?,
            Some(fallback)
        );
        assert!(matches!(
            catalog.finish_eventual_fallback(at_deadline),
            Err(ContentCatalogError::InvalidInput)
        ));
    }

    let directory = tempdir()?;
    let (request, stripe) = protected_fixture()?;
    let mut catalog = DurableContentCatalog::open(directory.path(), UnixMicros::new(1))?;
    catalog.begin(request)?;
    catalog.configure_protected_acknowledgement(
        request,
        strong_policy(ContentStrongFallback::Eventual),
        meshspan_domain::DurabilityScope::CellReplicated,
    )?;
    catalog.append_protected_stripes(request, std::slice::from_ref(&stripe))?;
    let manifest = catalog.seal_layout(
        request,
        CompletedStage {
            logical_length: 2,
            content_digest: [9; 32],
        },
        2,
        wrapped_key()?,
    )?;
    for (index, shard) in stripe.shards().iter().enumerate().take(2) {
        let cursor = ProtectedShardCursor {
            chunk_index: 0,
            shard_index: u16::try_from(index)?,
        };
        catalog.record_protected_receipt(
            request,
            protected_receipt(manifest.root_digest, cursor, *shard),
            UnixMicros::new(12),
        )?;
    }
    let at_deadline = ContentPublicationRequest {
        observed_at: UnixMicros::new(15),
        ..request
    };
    assert_eq!(catalog.finish_eventual_fallback(at_deadline)?, manifest);
    let evidence = catalog.protected_acknowledgement_evidence(at_deadline)?;
    assert_eq!(
        evidence.configured_class,
        ContentAcknowledgementClass::Strong
    );
    assert_eq!(
        evidence.acknowledged_class,
        ContentAcknowledgementClass::Eventual
    );
    assert!(evidence.fallback_applied);
    assert_eq!(evidence.required_shard_receipts, 2);
    assert_eq!(evidence.pending_eventual_shards, 2);
    drop(catalog);

    let reopened = DurableContentCatalog::open(directory.path(), UnixMicros::new(20))?;
    assert_eq!(
        reopened.protected_acknowledgement_evidence(at_deadline)?,
        evidence
    );
    Ok(())
}

fn strong_policy(fallback: ContentStrongFallback) -> ContentAcknowledgementPolicy {
    ContentAcknowledgementPolicy {
        class: ContentAcknowledgementClass::Strong,
        strong_wait: Some(DurationMicros::new(13)),
        fallback,
    }
}

#[test]
fn protected_layout_import_replays_exact_pages_and_receipts()
-> Result<(), Box<dyn std::error::Error>> {
    let source_directory = tempdir()?;
    let (request, stripe) = protected_fixture()?;
    let mut source = DurableContentCatalog::open(source_directory.path(), UnixMicros::new(1))?;
    source.begin(request)?;
    source.append_protected_stripes(request, std::slice::from_ref(&stripe))?;
    let manifest = source.seal_layout(
        request,
        CompletedStage {
            logical_length: 2,
            content_digest: [9; 32],
        },
        2,
        wrapped_key()?,
    )?;
    for (cursor, shard) in source
        .pending_protected_shards(request, None, 10)?
        .shards
        .as_slice()
    {
        if shard.acknowledgement == ShardAcknowledgement::Required {
            source.record_protected_receipt(
                request,
                protected_receipt(manifest.root_digest, *cursor, *shard),
                UnixMicros::new(3),
            )?;
        }
    }
    source.finish(request, UnixMicros::new(4))?;
    let committed = source.committed_protected_stripe(
        PublishedContentReference {
            publication_operation_id: request.operation_id,
            manifest,
        },
        0,
    )?;
    let transfer = source.committed_layout_transfer(PublishedContentReference {
        publication_operation_id: request.operation_id,
        manifest,
    })?;
    let header = transfer.header();
    let page = transfer.page(None, 1)?;

    let receiver_directory = tempdir()?;
    let import_request = ContentPublicationRequest {
        observed_at: UnixMicros::new(5),
        ..request
    };
    let mut receiver = DurableContentCatalog::open(receiver_directory.path(), UnixMicros::new(5))?;
    receiver.begin_layout_import(import_request, header)?;
    receiver.append_layout_import_page(import_request, header, &page)?;
    receiver.append_layout_import_page(import_request, header, &page)?;
    let mut imported_chunk = receiver.content_chunk(import_request, 0)?;
    imported_chunk.storage_layout_digest = [0; 32];
    let imported_stripe = PreparedProtectedStripe::from_untrusted(
        import_request,
        imported_chunk,
        committed.stripe.coding_layout(),
        committed.stripe.topology_revision(),
        committed.stripe.capacity_revision(),
        committed.stripe.policy_evidence().clone(),
        committed.stripe.shards().to_vec(),
    )?;
    receiver.append_protected_layout_import_page(
        import_request,
        std::slice::from_ref(&imported_stripe),
    )?;
    receiver.append_protected_layout_import_page(
        import_request,
        std::slice::from_ref(&imported_stripe),
    )?;
    receiver.seal_layout_import(import_request, header)?;
    for receipt in committed.receipts.as_slice() {
        receiver.record_protected_receipt(import_request, *receipt, UnixMicros::new(6))?;
        receiver.record_protected_receipt(import_request, *receipt, UnixMicros::new(7))?;
    }
    receiver.finish(import_request, UnixMicros::new(8))?;
    let received_stripe = receiver.committed_protected_stripe(
        PublishedContentReference {
            publication_operation_id: import_request.operation_id,
            manifest,
        },
        0,
    )?;
    assert_eq!(received_stripe.stripe, imported_stripe);
    assert_eq!(received_stripe.receipts, committed.receipts);
    Ok(())
}

#[test]
fn scrub_identity_resolves_only_the_current_protected_shard_route()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (request, stripe) = protected_fixture()?;
    let mut catalog = DurableContentCatalog::open(directory.path(), UnixMicros::new(1))?;
    catalog.begin(request)?;
    catalog.append_protected_stripes(request, std::slice::from_ref(&stripe))?;
    let manifest = catalog.seal_layout(
        request,
        CompletedStage {
            logical_length: 2,
            content_digest: [9; 32],
        },
        2,
        wrapped_key()?,
    )?;
    for (cursor, planned) in catalog
        .pending_protected_shards(request, None, 10)?
        .shards
        .as_slice()
    {
        catalog.record_protected_receipt(
            request,
            protected_receipt(manifest.root_digest, *cursor, *planned),
            UnixMicros::new(3),
        )?;
    }
    catalog.finish(request, UnixMicros::new(4))?;

    let source = protected_receipt(
        manifest.root_digest,
        ProtectedShardCursor {
            chunk_index: 0,
            shard_index: 1,
        },
        stripe.shards()[1],
    );
    let initial = catalog
        .shard_repair_candidate(source.target_id, source.target_generation, source.shard)?
        .ok_or("current source route was not resolved")?;
    assert_eq!(initial.volume_id, request.volume_id);
    assert_eq!(initial.manifest_id, request.manifest_id);
    assert_eq!(initial.source_layout_generation, 1);
    assert_eq!(initial.source_receipt, source);
    assert_eq!(
        catalog.shard_repair_candidate(
            TargetId::from_bytes([99; 16])?,
            source.target_generation,
            source.shard,
        )?,
        None
    );

    let replacement = ShardReceipt {
        operation_id: OperationId::from_bytes([98; 16])?,
        target_id: TargetId::from_bytes([97; 16])?,
        target_generation: 3,
        ..source
    };
    let content = PublishedContentReference {
        publication_operation_id: request.operation_id,
        manifest,
    };
    catalog.install_shard_repair(
        content,
        &ShardRepairTransition {
            effect_operation_id: OperationId::from_bytes([96; 16])?,
            source_layout_generation: 1,
            replacement_layout_generation: 2,
            source_receipt: source,
            replacement_receipt: replacement,
            committed_revision: Revision::new(7),
        },
    )?;
    assert_eq!(
        catalog.shard_repair_candidate(source.target_id, source.target_generation, source.shard)?,
        None
    );
    let current = catalog
        .shard_repair_candidate(
            replacement.target_id,
            replacement.target_generation,
            replacement.shard,
        )?
        .ok_or("replacement route was not resolved")?;
    assert_eq!(current.source_layout_generation, 2);
    assert_eq!(current.source_receipt, replacement);
    Ok(())
}

fn protected_fixture()
-> Result<(ContentPublicationRequest, PreparedProtectedStripe), Box<dyn std::error::Error>> {
    let request = ContentPublicationRequest {
        format_version: 2,
        logical_length: 2,
        ..request()?
    };
    let chunk = PreparedContentChunk {
        storage_layout_digest: [0; 32],
        ..chunk(0, 20)?
    };
    let shards = (0_u8..4)
        .map(|index| {
            Ok(PreparedProtectedShard {
                shard_index: u16::from(index),
                shard_generation: 1,
                provider_operation_id: OperationId::from_bytes([30 + index; 16])?,
                expected_length: 16,
                expected_digest: [50 + index; 32],
                target_id: TargetId::from_bytes([70 + index; 16])?,
                target_generation: 2,
                acknowledgement: if index == 3 {
                    ShardAcknowledgement::Eventual
                } else {
                    ShardAcknowledgement::Required
                },
                eventual_fallback: if index < 2 {
                    ShardAcknowledgement::Required
                } else {
                    ShardAcknowledgement::Eventual
                },
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let stripe = PreparedProtectedStripe::from_untrusted(
        request,
        chunk,
        CodingLayout::new(2, 2, 16)?,
        Revision::new(5),
        Revision::new(6),
        VersionedPayload {
            format_version: 1,
            bytes: BoundedBytes::copy_from(b"two-device-loss", 64)?,
        },
        shards,
    )?;
    Ok((request, stripe))
}

const fn protected_receipt(
    manifest_digest: [u8; 32],
    cursor: ProtectedShardCursor,
    shard: PreparedProtectedShard,
) -> ShardReceipt {
    ShardReceipt {
        operation_id: shard.provider_operation_id,
        shard: ShardIdentity {
            manifest_digest,
            stripe_index: cursor.chunk_index,
            shard_index: shard.shard_index,
            generation: shard.shard_generation,
        },
        length: shard.expected_length,
        digest: shard.expected_digest,
        target_id: shard.target_id,
        target_generation: shard.target_generation,
    }
}

#[test]
fn absent_exact_and_conflicting_lookups_are_distinct() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let request = request()?;
    let mut catalog = DurableContentCatalog::open(directory.path(), UnixMicros::new(1))?;

    assert_eq!(catalog.resolve(request)?, None);
    assert_eq!(catalog.prepared_layout(request)?, None);
    catalog.begin(request)?;
    assert_eq!(catalog.resolve(request)?, None);
    assert_eq!(catalog.prepared_layout(request)?, None);

    let mut conflict = request;
    conflict.request_digest[0] ^= 1;
    assert!(matches!(
        catalog.resolve(conflict),
        Err(ContentCatalogError::Conflict)
    ));
    assert!(matches!(
        catalog.prepared_layout(conflict),
        Err(ContentCatalogError::Conflict)
    ));
    let mut wrong_volume = request;
    wrong_volume.volume_id = VolumeId::from_bytes([10; 16])?;
    assert!(matches!(
        catalog.resolve(wrong_volume),
        Err(ContentCatalogError::Conflict)
    ));
    Ok(())
}

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
    let content = crate::PublishedContentReference {
        publication_operation_id: request.operation_id,
        manifest,
    };
    {
        let inventory = catalog.committed_shard_inventory(content)?;
        let first_inventory = inventory.page(None, 2)?;
        assert_eq!(first_inventory.shards.len(), 2);
        assert_eq!(first_inventory.next_index, Some(1));
        let second_inventory = inventory.page(first_inventory.next_index, 2)?;
        assert_eq!(second_inventory.shards.len(), 1);
        assert_eq!(second_inventory.next_index, None);
        assert_eq!(
            first_inventory.shards.as_slice()[0],
            receipt(chunks[0], manifest.root_digest)?
        );
        assert!(matches!(
            inventory.page(None, 0),
            Err(ContentCatalogError::InvalidInput)
        ));
    }
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
fn committed_inventory_rejects_missing_receipt_state() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let request = request()?;
    let mut catalog = DurableContentCatalog::open(directory.path(), UnixMicros::new(1))?;
    catalog.begin(request)?;
    let chunks = chunks()?;
    catalog.append_chunks(request, &chunks)?;
    let manifest = catalog.seal_layout(
        request,
        CompletedStage {
            logical_length: 6,
            content_digest: [9; 32],
        },
        2,
        wrapped_key()?,
    )?;
    for chunk in chunks {
        catalog.record_receipt(
            request,
            chunk.chunk_index,
            receipt(chunk, manifest.root_digest)?,
            UnixMicros::new(4),
        )?;
    }
    catalog.finish(request, UnixMicros::new(5))?;
    catalog.connection.execute(
        "UPDATE content_chunks SET receipt_target_id = NULL,
            receipt_target_generation = NULL, receipt_recorded_at = NULL
         WHERE operation_id = ?1 AND chunk_index = 1",
        [request.operation_id.as_bytes().as_slice()],
    )?;
    let inventory = catalog.committed_shard_inventory(crate::PublishedContentReference {
        publication_operation_id: request.operation_id,
        manifest,
    })?;
    assert!(matches!(
        inventory.page(None, 10),
        Err(ContentCatalogError::Sqlite(_))
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

#[test]
fn portable_layout_import_resumes_rewraps_and_collects_only_local_receipts()
-> Result<(), Box<dyn std::error::Error>> {
    let source_directory = tempdir()?;
    let fixture = export_committed_source_layout(source_directory.path())?;
    let source_manifest = fixture.manifest;
    let source_header = fixture.header;
    let first = fixture.first_page;
    let second = fixture.second_page;
    let chunks = fixture.chunks;
    assert_eq!(first.chunks().len(), 2);
    assert_eq!(first.next_index(), Some(1));
    assert_eq!(second.chunks().len(), 1);
    assert_eq!(second.next_index(), None);

    let receiver_header = ContentLayoutTransferHeader {
        wrapped_key: wrapped_key_for(2, 6)?,
        ..source_header
    };
    assert_eq!(receiver_header.manifest, source_header.manifest);
    assert_ne!(receiver_header.digest(), source_header.digest());

    let receiver_directory = tempdir()?;
    let receiver_request = imported_request(source_manifest)?;
    let mut receiver = DurableContentCatalog::open(receiver_directory.path(), UnixMicros::new(6))?;
    receiver.begin_layout_import(receiver_request, receiver_header)?;
    receiver.append_layout_import_page(receiver_request, receiver_header, &first)?;
    receiver.append_layout_import_page(receiver_request, receiver_header, &first)?;
    assert!(matches!(
        receiver.seal_layout_import(receiver_request, receiver_header),
        Err(ContentCatalogError::Incomplete)
    ));
    drop(receiver);

    let mut receiver = DurableContentCatalog::open(receiver_directory.path(), UnixMicros::new(7))?;
    let resumed_request = ContentPublicationRequest {
        observed_at: UnixMicros::new(7),
        ..receiver_request
    };
    receiver.begin_layout_import(resumed_request, receiver_header)?;
    receiver.append_layout_import_page(resumed_request, receiver_header, &second)?;
    assert_eq!(
        receiver.seal_layout_import(resumed_request, receiver_header)?,
        source_manifest
    );
    assert_eq!(
        receiver
            .prepared_layout(resumed_request)?
            .ok_or("missing imported layout")?
            .wrapped_key,
        receiver_header.wrapped_key
    );
    for index in 0..receiver_header.chunk_count {
        let local = receiver.content_chunk(resumed_request, index)?;
        assert_ne!(
            local.provider_operation_id,
            chunks[usize::try_from(index)?].provider_operation_id
        );
        receiver.record_receipt(
            resumed_request,
            index,
            receipt(local, source_manifest.root_digest)?,
            UnixMicros::new(8),
        )?;
    }
    assert_eq!(
        receiver.finish(resumed_request, UnixMicros::new(9))?,
        source_manifest
    );
    let imported = receiver.committed_layout_transfer(PublishedContentReference {
        publication_operation_id: resumed_request.operation_id,
        manifest: source_manifest,
    })?;
    assert_eq!(imported.header(), receiver_header);
    assert_eq!(
        receiver
            .connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get::<_, u32>(0)
            })?,
        u32::try_from(super::repository::SCHEMA_VERSION)?
    );
    Ok(())
}

#[test]
fn remote_route_replay_ignores_observation_time_but_rejects_a_different_source()
-> Result<(), Box<dyn std::error::Error>> {
    let source_directory = tempdir()?;
    let fixture = export_committed_source_layout(source_directory.path())?;
    let receiver_directory = tempdir()?;
    let request = imported_request(fixture.manifest)?;
    let mut receiver = DurableContentCatalog::open(receiver_directory.path(), UnixMicros::new(6))?;
    receiver.begin_layout_import(request, fixture.header)?;
    receiver.append_layout_import_page(request, fixture.header, &fixture.first_page)?;
    receiver.append_layout_import_page(request, fixture.header, &fixture.second_page)?;
    receiver.seal_layout_import(request, fixture.header)?;
    let source = NodeId::from_bytes([41; 16])?;
    let receipt = receipt(fixture.chunks[0], fixture.manifest.root_digest)?;

    receiver.record_remote_shard_route(request, 0, source, receipt, UnixMicros::new(7))?;
    receiver.record_remote_shard_route(request, 0, source, receipt, UnixMicros::new(8))?;
    assert!(matches!(
        receiver.record_remote_shard_route(
            request,
            0,
            NodeId::from_bytes([42; 16])?,
            receipt,
            UnixMicros::new(8)
        ),
        Err(ContentCatalogError::Conflict)
    ));
    Ok(())
}

fn export_committed_source_layout(
    state_directory: &std::path::Path,
) -> Result<SourceLayoutFixture, Box<dyn std::error::Error>> {
    let source_request = request()?;
    let chunks = chunks()?;
    let mut source = DurableContentCatalog::open(state_directory, UnixMicros::new(1))?;
    source.begin(source_request)?;
    source.append_chunks(source_request, &chunks)?;
    let manifest = source.seal_layout(
        source_request,
        CompletedStage {
            logical_length: 6,
            content_digest: [9; 32],
        },
        2,
        wrapped_key_for(1, 5)?,
    )?;
    for chunk in chunks {
        source.record_receipt(
            source_request,
            chunk.chunk_index,
            receipt(chunk, manifest.root_digest)?,
            UnixMicros::new(4),
        )?;
    }
    source.finish(source_request, UnixMicros::new(5))?;
    let transfer = source.committed_layout_transfer(PublishedContentReference {
        publication_operation_id: source_request.operation_id,
        manifest,
    })?;
    let header = transfer.header();
    let first = transfer.page(None, 2)?;
    let second = transfer.page(first.next_index(), 2)?;
    Ok(SourceLayoutFixture {
        manifest,
        header,
        first_page: first,
        second_page: second,
        chunks,
    })
}

#[test]
fn imported_layout_rejects_page_and_header_substitution() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let request = request()?;
    let chunks = chunks()?;
    let mut source = DurableContentCatalog::open(directory.path(), UnixMicros::new(1))?;
    source.begin(request)?;
    source.append_chunks(request, &chunks)?;
    let manifest = source.seal_layout(
        request,
        CompletedStage {
            logical_length: 6,
            content_digest: [9; 32],
        },
        2,
        wrapped_key()?,
    )?;
    for chunk in chunks {
        source.record_receipt(
            request,
            chunk.chunk_index,
            receipt(chunk, manifest.root_digest)?,
            UnixMicros::new(4),
        )?;
    }
    source.finish(request, UnixMicros::new(5))?;
    let transfer = source.committed_layout_transfer(PublishedContentReference {
        publication_operation_id: request.operation_id,
        manifest,
    })?;
    let header = transfer.header();
    let page = transfer.page(None, 3)?;

    let receiver_directory = tempdir()?;
    let receiver_request = imported_request(manifest)?;
    let mut receiver = DurableContentCatalog::open(receiver_directory.path(), UnixMicros::new(6))?;
    receiver.begin_layout_import(receiver_request, header)?;
    let mut substituted = page.chunks().to_vec();
    substituted[1].ciphertext_digest[0] ^= 1;
    let substituted = ContentLayoutTransferPage::from_untrusted(substituted, None)?;
    receiver.append_layout_import_page(receiver_request, header, &substituted)?;
    assert!(matches!(
        receiver.seal_layout_import(receiver_request, header),
        Err(ContentCatalogError::Corrupt)
    ));
    let wrong_header = ContentLayoutTransferHeader {
        chunk_bytes: 3,
        ..header
    };
    assert!(matches!(
        receiver.begin_layout_import(receiver_request, wrong_header),
        Err(ContentCatalogError::Conflict)
    ));
    let discontinuous = vec![
        ContentLayoutChunk::from(chunks[0]),
        ContentLayoutChunk::from(chunks[2]),
    ];
    assert!(ContentLayoutTransferPage::from_untrusted(discontinuous, None).is_err());
    Ok(())
}

#[test]
fn committed_manifest_lookup_hides_incomplete_state_and_reconstructs_exact_reference()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let request = request()?;
    let mut catalog = DurableContentCatalog::open(directory.path(), UnixMicros::new(1))?;
    assert_eq!(
        catalog.committed_content_by_manifest(request.manifest_id)?,
        None
    );
    catalog.begin(request)?;
    assert_eq!(
        catalog.committed_content_by_manifest(request.manifest_id)?,
        None
    );
    let chunks = chunks()?;
    catalog.append_chunks(request, &chunks)?;
    let manifest = catalog.seal_layout(
        request,
        CompletedStage {
            logical_length: 6,
            content_digest: [9; 32],
        },
        2,
        wrapped_key()?,
    )?;
    for chunk in chunks {
        catalog.record_receipt(
            request,
            chunk.chunk_index,
            receipt(chunk, manifest.root_digest)?,
            UnixMicros::new(4),
        )?;
    }
    catalog.finish(request, UnixMicros::new(5))?;
    assert_eq!(
        catalog.committed_content_by_manifest(request.manifest_id)?,
        Some(PublishedContentReference {
            publication_operation_id: request.operation_id,
            manifest,
        })
    );
    let unknown = meshspan_domain::ContentManifestId::from_bytes([99; 16])?;
    assert_eq!(catalog.committed_content_by_manifest(unknown)?, None);
    Ok(())
}

fn request() -> Result<ContentPublicationRequest, Box<dyn std::error::Error>> {
    Ok(ContentPublicationRequest {
        operation_id: OperationId::from_bytes([1; 16])?,
        volume_id: VolumeId::from_bytes([9; 16])?,
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
        storage_layout_digest: [0; 32],
        provider_operation_id: OperationId::from_bytes([operation_byte; 16])?,
    })
}

fn wrapped_key() -> Result<crate::WrappedContentKey, Box<dyn std::error::Error>> {
    wrapped_key_for(1, 5)
}

fn wrapped_key_for(
    generation: u64,
    key_byte: u8,
) -> Result<crate::WrappedContentKey, Box<dyn std::error::Error>> {
    let cipher = ContentKeyEnvelopeCipher::new(VolumeKeyEncryptionKey::from_bytes(
        generation,
        [key_byte; 32],
    )?);
    Ok(cipher.wrap(
        ContentManifestId::from_bytes([3; 16])?,
        &ContentEncryptionKey::from_bytes([6; 32])?,
        &mut FixedRandom,
    )?)
}

fn imported_request(
    manifest: crate::ManifestPublication,
) -> Result<ContentPublicationRequest, Box<dyn std::error::Error>> {
    Ok(ContentPublicationRequest {
        operation_id: OperationId::from_bytes([40; 16])?,
        volume_id: VolumeId::from_bytes([9; 16])?,
        request_digest: [41; 32],
        manifest_id: manifest.manifest_id,
        format_version: manifest.format_version,
        logical_length: manifest.logical_length,
        authorization_revision: Revision::new(42),
        deadline: UnixMicros::new(100),
        observed_at: UnixMicros::new(6),
    })
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
