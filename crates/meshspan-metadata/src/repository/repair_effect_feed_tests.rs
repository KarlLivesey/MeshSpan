// SPDX-License-Identifier: GPL-2.0-only

use super::{Fixture, shard_receipt};
use crate::{
    AuthoritativeCommand, AuthoritativeRepository, CommitShardRepair, PageLimit, PartitionDatabase,
    RepositoryError, ShardRepairEffectCursor, ShardRepairEffectRecord,
};
use meshspan_domain::{
    ContentManifestId, OperationId, Revision, TargetId, UnixMicros, VolumeId, WorkId,
};
use meshspan_work::WorkSubject;
use std::error::Error;

#[test]
fn repair_effect_feed_is_scoped_ordered_paged_and_reopenable() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("repair.sqlite3");
    let mut fixture = Fixture::at(&path)?;
    fixture.register_target(2, TargetId::from_bytes([40; 16])?, 50)?;
    fixture.register_target(3, TargetId::from_bytes([41; 16])?, 51)?;
    let manifest = ContentManifestId::from_bytes([43; 16])?;
    let first = append_effect(&mut fixture, manifest, 0, 4)?;
    let other = append_effect(&mut fixture, ContentManifestId::from_bytes([44; 16])?, 0, 7)?;
    let second = append_effect(&mut fixture, manifest, 1, 10)?;
    let third = append_effect(&mut fixture, manifest, 2, 13)?;
    let volume = fixture.volume;
    let same_scope = [first, second, third];
    let all =
        fixture
            .repository
            .shard_repair_effects(volume, manifest, None, PageLimit::new(3)?)?;
    assert_eq!(all.items, same_scope);
    assert!(all.next.is_none());
    let first_page =
        fixture
            .repository
            .shard_repair_effects(volume, manifest, None, PageLimit::new(1)?)?;
    assert_eq!(first_page.items, [first]);
    assert_eq!(first_page.next, Some(cursor(&first)));
    drop(fixture);
    let reopened = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &path,
        UnixMicros::new(90),
    )?);
    let remaining =
        reopened.shard_repair_effects(volume, manifest, first_page.next, PageLimit::new(2)?)?;
    assert_eq!(remaining.items, [second, third]);
    assert!(remaining.next.is_none());
    assert!(
        reopened
            .shard_repair_effects(volume, manifest, Some(cursor(&third)), PageLimit::new(1)?)?
            .items
            .is_empty()
    );
    assert_eq!(
        reopened.shard_repair_effect(other.effect_operation_id)?,
        Some(other)
    );
    assert_eq!(
        reopened
            .shard_repair_effects(volume, other.manifest_id, None, PageLimit::new(1)?)?
            .items,
        [other]
    );
    assert!(
        reopened
            .shard_repair_effects(
                VolumeId::from_bytes([99; 16])?,
                manifest,
                None,
                PageLimit::new(1)?
            )?
            .items
            .is_empty()
    );
    for invalid in [
        cursor(&other),
        ShardRepairEffectCursor {
            revision: Revision::ZERO,
            ..cursor(&first)
        },
        ShardRepairEffectCursor {
            revision: Revision::new(u64::MAX),
            ..cursor(&first)
        },
        ShardRepairEffectCursor {
            effect_operation_id: OperationId::from_bytes([98; 16])?,
            ..cursor(&first)
        },
    ] {
        assert!(matches!(
            reopened.shard_repair_effects(volume, manifest, Some(invalid), PageLimit::new(1)?),
            Err(RepositoryError::InvalidCommand)
        ));
    }
    assert!(PageLimit::new(0).is_err());
    assert!(PageLimit::new(usize::MAX).is_err());
    Ok(())
}

#[test]
fn repair_effect_feed_rejects_malformed_record_and_scope_substitution() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("repair.sqlite3");
    let mut fixture = Fixture::at(&path)?;
    fixture.register_target(2, TargetId::from_bytes([40; 16])?, 50)?;
    fixture.register_target(3, TargetId::from_bytes([41; 16])?, 51)?;
    let manifest = ContentManifestId::from_bytes([43; 16])?;
    let effect = append_effect(&mut fixture, manifest, 0, 4)?;
    let volume = fixture.volume;
    let substituted = VolumeId::from_bytes([95; 16])?;
    let connection = fixture.repository.database.connection_mut();
    connection.execute(
        "INSERT INTO volumes(volume_id, display_name, canonical_name, state, created_by, created_at, revision)
         VALUES(?1, 'Other volume', 'other volume', 1, ?2, 1, 1)",
        rusqlite::params![
            substituted.as_bytes().as_slice(),
            fixture.administrator.as_bytes().as_slice()
        ],
    )?;
    connection.execute(
        "UPDATE maintenance_repair_effects SET volume_id = ?1 WHERE effect_operation_id = ?2",
        rusqlite::params![
            substituted.as_bytes().as_slice(),
            effect.effect_operation_id.as_bytes().as_slice()
        ],
    )?;
    assert!(
        fixture
            .repository
            .shard_repair_effects(substituted, manifest, None, PageLimit::new(1)?)
            .is_err()
    );
    assert!(
        fixture
            .repository
            .shard_repair_effect(effect.effect_operation_id)
            .is_err()
    );
    fixture.repository.database.connection_mut().execute(
        "UPDATE maintenance_repair_effects SET volume_id = ?1, expected_digest = zeroblob(32) WHERE effect_operation_id = ?2",
        rusqlite::params![volume.as_bytes().as_slice(), effect.effect_operation_id.as_bytes().as_slice()])?;
    drop(fixture);
    let reopened = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &path,
        UnixMicros::new(90),
    )?);
    assert!(
        reopened
            .shard_repair_effects(volume, manifest, None, PageLimit::new(1)?)
            .is_err()
    );
    assert!(
        reopened
            .shard_repair_effect(effect.effect_operation_id)
            .is_err()
    );
    Ok(())
}

fn append_effect(
    fixture: &mut Fixture,
    manifest: ContentManifestId,
    stripe_index: u64,
    index: u64,
) -> Result<ShardRepairEffectRecord, Box<dyn Error>> {
    let identity = u8::try_from(index)?;
    let work_id = WorkId::from_bytes([identity + 60; 16])?;
    let mut source = shard_receipt(identity + 70, TargetId::from_bytes([40; 16])?, 45)?;
    source.shard.stripe_index = stripe_index;
    let mut replacement = shard_receipt(identity + 80, TargetId::from_bytes([41; 16])?, 45)?;
    replacement.shard.stripe_index = stripe_index;
    let mut queue = fixture.repair_queue(work_id, manifest, source.length);
    queue.deduplication_key = [identity; 32];
    queue.subject = WorkSubject::Repair {
        volume_id: fixture.volume,
        manifest_id: manifest,
        stripe_index,
        shard_index: source.shard.shard_index,
        source_generation: 1,
    };
    fixture.apply(
        index,
        60,
        &AuthoritativeCommand::QueueMaintenanceWork(queue),
    )?;
    fixture.apply(
        index + 1,
        61,
        &AuthoritativeCommand::ClaimMaintenanceWork(fixture.claim(work_id, 1, 777, 100)),
    )?;
    let committed = fixture.apply(
        index + 2,
        62,
        &AuthoritativeCommand::CommitShardRepair(CommitShardRepair {
            work_id,
            claim_generation: 1,
            worker_node_id: fixture.node,
            worker_incarnation: 1,
            fence: 777,
            volume_id: fixture.volume,
            manifest_id: manifest,
            source_layout_generation: 1,
            source_receipt: source,
            replacement_receipt: replacement,
        }),
    )?;
    let record = fixture
        .repository
        .shard_repair_effect(committed.operation_id)?
        .ok_or("repair effect")?;
    assert_eq!(
        (record.volume_id, record.manifest_id),
        (fixture.volume, manifest)
    );
    assert_eq!(
        (record.source_receipt, record.replacement_receipt),
        (source, replacement)
    );
    Ok(record)
}

fn cursor(record: &ShardRepairEffectRecord) -> ShardRepairEffectCursor {
    ShardRepairEffectCursor {
        revision: record.revision,
        effect_operation_id: record.effect_operation_id,
    }
}
