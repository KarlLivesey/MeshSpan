// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::RepairProjectionCursor;
use meshspan_domain::PartitionId;

#[test]
fn committed_effect_and_cursor_replay_after_catalogue_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut fixture = ProjectionFixture::new(directory.path())?;
    fixture.effect.replacement_receipt.shard.generation = 2;
    fixture
        .catalog
        .install_shard_repair(fixture.content, &fixture.effect)?;
    assert_eq!(
        fixture
            .catalog
            .repair_projection_cursor(fixture.partition, fixture.content)?,
        None,
        "a local/provisional route install is not progress through an authoritative feed"
    );
    fixture.catalog.project_shard_repair(
        fixture.partition,
        fixture.content,
        None,
        &fixture.effect,
    )?;
    let cursor = fixture.cursor();
    drop(fixture.catalog);
    let mut reopened = DurableContentCatalog::open(directory.path(), UnixMicros::new(10))?;
    assert_eq!(
        reopened.repair_projection_cursor(fixture.partition, fixture.content)?,
        Some(cursor)
    );
    reopened.project_shard_repair(fixture.partition, fixture.content, None, &fixture.effect)?;
    assert_eq!(
        reopened.repair_projection_cursor(fixture.partition, fixture.content)?,
        Some(cursor)
    );
    let receipt = fixture.effect.replacement_receipt;
    let current = reopened
        .shard_repair_candidate(receipt.target_id, receipt.target_generation, receipt.shard)?
        .ok_or("replayed route")?;
    assert_eq!(current.source_receipt, receipt);
    assert_eq!(current.source_layout_generation, 2);
    Ok(())
}

#[test]
fn cursor_write_failure_rolls_back_the_route_and_retries_exactly()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut fixture = ProjectionFixture::new(directory.path())?;
    fixture.catalog.connection.execute_batch(
        "CREATE TEMP TRIGGER reject_projection_cursor BEFORE INSERT ON content_repair_projection_cursors
         BEGIN SELECT RAISE(ABORT, 'injected cursor failure'); END;",
    )?;
    assert!(matches!(
        fixture.catalog.project_shard_repair(
            fixture.partition,
            fixture.content,
            None,
            &fixture.effect
        ),
        Err(ContentCatalogError::Sqlite(_))
    ));
    assert_eq!(
        fixture
            .catalog
            .repair_projection_cursor(fixture.partition, fixture.content)?,
        None
    );
    let original = fixture.effect.source_receipt;
    let current = fixture
        .catalog
        .shard_repair_candidate(
            original.target_id,
            original.target_generation,
            original.shard,
        )?
        .ok_or("original route survives cursor-write failure")?;
    assert_eq!(current.source_receipt, original);
    assert_eq!(current.source_layout_generation, 1);
    fixture
        .catalog
        .connection
        .execute_batch("DROP TRIGGER reject_projection_cursor")?;
    fixture.catalog.project_shard_repair(
        fixture.partition,
        fixture.content,
        None,
        &fixture.effect,
    )?;
    assert_eq!(
        fixture
            .catalog
            .repair_projection_cursor(fixture.partition, fixture.content)?,
        Some(fixture.cursor())
    );
    Ok(())
}

#[test]
fn stale_cursor_cannot_install_a_route_or_rewind_later_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut fixture = ProjectionFixture::new(directory.path())?;
    fixture.catalog.project_shard_repair(
        fixture.partition,
        fixture.content,
        None,
        &fixture.effect,
    )?;
    let cursor = fixture.cursor();
    let replacement = ShardReceipt {
        operation_id: OperationId::from_bytes([87; 16])?,
        target_id: TargetId::from_bytes([88; 16])?,
        ..fixture.effect.replacement_receipt
    };
    let next = ShardRepairTransition {
        effect_operation_id: OperationId::from_bytes([89; 16])?,
        source_layout_generation: 2,
        replacement_layout_generation: 3,
        source_receipt: fixture.effect.replacement_receipt,
        replacement_receipt: replacement,
        committed_revision: Revision::new(8),
    };
    assert!(matches!(
        fixture
            .catalog
            .project_shard_repair(fixture.partition, fixture.content, None, &next),
        Err(ContentCatalogError::Conflict)
    ));
    assert_eq!(
        fixture
            .catalog
            .repair_projection_cursor(fixture.partition, fixture.content)?,
        Some(cursor)
    );
    assert_eq!(
        fixture.catalog.shard_repair_candidate(
            replacement.target_id,
            replacement.target_generation,
            replacement.shard
        )?,
        None
    );
    fixture.catalog.project_shard_repair(
        fixture.partition,
        fixture.content,
        Some(cursor),
        &next,
    )?;
    fixture.catalog.project_shard_repair(
        fixture.partition,
        fixture.content,
        None,
        &fixture.effect,
    )?;
    let latest = RepairProjectionCursor {
        revision: Revision::new(8),
        effect_operation_id: next.effect_operation_id,
    };
    assert_eq!(
        fixture
            .catalog
            .repair_projection_cursor(fixture.partition, fixture.content)?,
        Some(latest)
    );
    let substituted = ShardRepairTransition {
        replacement_receipt: replacement,
        ..fixture.effect
    };
    assert!(matches!(
        fixture.catalog.project_shard_repair(
            fixture.partition,
            fixture.content,
            None,
            &substituted
        ),
        Err(ContentCatalogError::Conflict)
    ));
    assert_eq!(
        fixture
            .catalog
            .repair_projection_cursor(fixture.partition, fixture.content)?,
        Some(latest)
    );
    Ok(())
}

#[test]
fn later_committed_manifest_enters_the_bounded_projection_inventory()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let empty = DurableContentCatalog::open(directory.path(), UnixMicros::new(1))?;
    assert!(
        empty
            .repair_projection_manifests(None, 1)?
            .manifests
            .is_empty()
    );
    drop(empty);
    let fixture = ProjectionFixture::new(directory.path())?;
    let page = fixture.catalog.repair_projection_manifests(None, 1)?;
    assert_eq!(page.manifests.len(), 1);
    assert_eq!(page.manifests.as_slice()[0].content, fixture.content);
    assert!(page.next.is_none());
    assert!(
        fixture
            .catalog
            .repair_projection_manifests(Some(fixture.content.publication_operation_id), 1)?
            .manifests
            .is_empty()
    );
    for limit in [0, 1_001] {
        assert!(matches!(
            fixture.catalog.repair_projection_manifests(None, limit),
            Err(ContentCatalogError::InvalidInput)
        ));
    }
    Ok(())
}

struct ProjectionFixture {
    catalog: DurableContentCatalog,
    content: PublishedContentReference,
    partition: PartitionId,
    effect: ShardRepairTransition,
}

impl ProjectionFixture {
    fn new(directory: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let (catalog, request, stripe, manifest) = committed_protected_catalog(directory)?;
        let source = protected_receipt(
            manifest.root_digest,
            ProtectedShardCursor {
                chunk_index: 0,
                shard_index: 1,
            },
            stripe.shards()[1],
        );
        let replacement = ShardReceipt {
            operation_id: OperationId::from_bytes([98; 16])?,
            target_id: TargetId::from_bytes([97; 16])?,
            target_generation: 3,
            ..source
        };
        Ok(Self {
            catalog,
            content: PublishedContentReference {
                publication_operation_id: request.operation_id,
                manifest,
            },
            partition: PartitionId::from_bytes([99; 16])?,
            effect: ShardRepairTransition {
                effect_operation_id: OperationId::from_bytes([96; 16])?,
                source_layout_generation: 1,
                replacement_layout_generation: 2,
                source_receipt: source,
                replacement_receipt: replacement,
                committed_revision: Revision::new(7),
            },
        })
    }

    fn cursor(&self) -> RepairProjectionCursor {
        RepairProjectionCursor {
            revision: self.effect.committed_revision,
            effect_operation_id: self.effect.effect_operation_id,
        }
    }
}

#[test]
fn projection_schema_upgrades_existing_committed_content_without_rewriting_history()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fixture = ProjectionFixture::new(directory.path())?;
    let prior: Vec<u8> = fixture.catalog.connection.query_row(
        "SELECT migration_digest FROM schema_migrations WHERE version = 12",
        [],
        |row| row.get(0),
    )?;
    // Recreate schema 12 by removing the subsequent additive objects. Retain
    // a committed protected manifest and all prior immutable migration records.
    fixture.catalog.connection.execute_batch(
        "BEGIN IMMEDIATE;
         DROP TABLE content_repair_projection_cursors;
         DROP INDEX content_publications_repair_projection;
         ALTER TABLE content_shard_repair_effects DROP COLUMN replacement_shard_generation;
         DELETE FROM schema_migrations WHERE version >= 13;
         COMMIT;",
    )?;
    drop(fixture.catalog);
    let reopened = DurableContentCatalog::open(directory.path(), UnixMicros::new(10))?;
    assert_eq!(
        reopened.connection.query_row(
            "SELECT migration_digest FROM schema_migrations WHERE version = 12",
            [],
            |row| row.get::<_, Vec<u8>>(0)
        )?,
        prior
    );
    assert_eq!(
        reopened.repair_projection_cursor(fixture.partition, fixture.content)?,
        None
    );
    let source = fixture.effect.source_receipt;
    assert_eq!(
        reopened
            .shard_repair_candidate(source.target_id, source.target_generation, source.shard)?
            .ok_or("unchanged source after upgrade")?
            .source_receipt,
        source
    );
    let violations: i64 = reopened.connection.query_row(
        "SELECT COUNT(*) FROM pragma_foreign_key_check",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(violations, 0);
    assert_eq!(
        reopened
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?,
        "ok"
    );
    Ok(())
}

#[test]
fn migration14_preserves_legacy_repair_route_and_exact_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut fixture = ProjectionFixture::new(directory.path())?;
    fixture
        .catalog
        .install_shard_repair(fixture.content, &fixture.effect)?;
    // This fixture uses the original same-generation effect representation.
    fixture.catalog.connection.execute_batch(
        "BEGIN;
        ALTER TABLE content_shard_repair_effects DROP COLUMN replacement_shard_generation;
        DELETE FROM schema_migrations WHERE version = 14;
        COMMIT;",
    )?;
    drop(fixture.catalog);
    let mut reopened = DurableContentCatalog::open(directory.path(), UnixMicros::new(10))?;
    reopened.install_shard_repair(fixture.content, &fixture.effect)?;
    let replacement = fixture.effect.replacement_receipt;
    let current = reopened
        .shard_repair_candidate(
            replacement.target_id,
            replacement.target_generation,
            replacement.shard,
        )?
        .ok_or("route missing")?;
    assert_eq!(current.source_receipt, replacement);
    assert_eq!(current.source_receipt.shard.generation, 1);
    assert_eq!(
        reopened
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?,
        "ok"
    );
    assert!(
        !reopened
            .connection
            .prepare("PRAGMA foreign_key_check")?
            .exists([])?
    );
    Ok(())
}

#[test]
fn route_generation_must_match_its_committed_effect() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut fixture = ProjectionFixture::new(directory.path())?;
    fixture
        .catalog
        .install_shard_repair(fixture.content, &fixture.effect)?;
    fixture.catalog.connection.execute(
        "UPDATE content_shard_repair_routes SET shard_generation = 2",
        [],
    )?;
    let mut receipt = fixture.effect.replacement_receipt;
    receipt.shard.generation = 2;
    assert!(
        fixture
            .catalog
            .shard_repair_candidate(receipt.target_id, receipt.target_generation, receipt.shard)
            .is_err()
    );
    Ok(())
}
