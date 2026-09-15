// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, scope-checked reads of immutable authoritative repair effects.

use super::{ShardRepairEffectCursor, ShardRepairEffectRecord};
use crate::repository::{Page, PageLimit, RepositoryError};
use meshspan_contracts::{ShardIdentity, ShardReceipt};
use meshspan_domain::{ContentManifestId, OperationId, Revision, UnixMicros, VolumeId, WorkId};
use rusqlite::{Connection, OptionalExtension, Row, params};

const EFFECT_SELECT: &str =
    "SELECT e.work_id, e.manifest_digest, e.stripe_index, e.shard_index, e.shard_generation,
    e.source_layout_generation, e.replacement_layout_generation,
    e.source_provider_operation_id, e.source_target_id, e.source_target_generation,
    e.replacement_provider_operation_id, e.replacement_target_id, e.replacement_target_generation,
    e.expected_length, e.expected_digest, e.committed_at, e.revision,
    e.volume_id, e.manifest_id, e.effect_operation_id, j.subject_payload, e.replacement_shard_generation
    FROM maintenance_repair_effects e
    LEFT JOIN maintenance_work_jobs j ON j.work_id = e.work_id";
const FEED_RANGE: &str = " WHERE e.volume_id = ?1 AND e.manifest_id = ?2
    AND (e.revision, e.effect_operation_id) > (?3, ?4)
    ORDER BY e.revision, e.effect_operation_id LIMIT ?5";

pub(super) fn load(
    connection: &Connection,
    operation: OperationId,
) -> Result<Option<ShardRepairEffectRecord>, RepositoryError> {
    connection
        .query_row(
            &format!("{EFFECT_SELECT} WHERE e.effect_operation_id = ?1"),
            [operation.as_bytes().as_slice()],
            decode,
        )
        .optional()
        .map_err(RepositoryError::from)
}

pub(super) fn page(
    connection: &Connection,
    volume: VolumeId,
    manifest: ContentManifestId,
    after: Option<ShardRepairEffectCursor>,
    limit: PageLimit,
) -> Result<Page<ShardRepairEffectRecord, ShardRepairEffectCursor>, RepositoryError> {
    let (revision, operation) = if let Some(cursor) = after {
        let revision =
            i64::try_from(cursor.revision.get()).map_err(|_| RepositoryError::InvalidCommand)?;
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM maintenance_repair_effects
             WHERE volume_id = ?1 AND manifest_id = ?2 AND revision = ?3 AND effect_operation_id = ?4)",
            params![volume.as_bytes().as_slice(), manifest.as_bytes().as_slice(), revision, cursor.effect_operation_id.as_bytes().as_slice()],
            |row| row.get(0))?;
        if revision == 0 || !exists {
            return Err(RepositoryError::InvalidCommand);
        }
        (revision, cursor.effect_operation_id.as_bytes())
    } else {
        (0, [0; 16])
    };
    let mut statement = connection.prepare(&format!("{EFFECT_SELECT}{FEED_RANGE}"))?;
    let rows = statement.query_map(
        params![
            volume.as_bytes().as_slice(),
            manifest.as_bytes().as_slice(),
            revision,
            operation.as_slice(),
            i64::try_from(limit.get() + 1).map_err(|_| RepositoryError::InvalidPageLimit)?
        ],
        decode,
    )?;
    let mut items = rows.collect::<Result<Vec<_>, _>>()?;
    let next = if items.len() > limit.get() {
        items.pop();
        items.last().map(|record| ShardRepairEffectCursor {
            revision: record.revision,
            effect_operation_id: record.effect_operation_id,
        })
    } else {
        None
    };
    Ok(Page { items, next })
}

fn decode(row: &Row<'_>) -> rusqlite::Result<ShardRepairEffectRecord> {
    let shard = ShardIdentity {
        manifest_digest: exact_sql(row.get(1)?)?,
        stripe_index: positive_or_zero_sql(row.get(2)?)?,
        shard_index: u16::try_from(row.get::<_, i64>(3)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        generation: u32::try_from(positive_sql(row.get(4)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    };
    let length = positive_sql(row.get(13)?)?;
    let digest = exact_sql(row.get(14)?)?;
    let record = ShardRepairEffectRecord {
        volume_id: VolumeId::from_bytes(exact_sql(row.get(17)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        manifest_id: ContentManifestId::from_bytes(exact_sql(row.get(18)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,

        effect_operation_id: OperationId::from_bytes(exact_sql(row.get(19)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        work_id: WorkId::from_bytes(exact_sql(row.get(0)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        source_receipt: ShardReceipt {
            operation_id: OperationId::from_bytes(exact_sql(row.get(7)?)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            shard,
            length,
            digest,
            target_id: meshspan_domain::TargetId::from_bytes(exact_sql(row.get(8)?)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            target_generation: positive_sql(row.get(9)?)?,
        },
        replacement_receipt: ShardReceipt {
            operation_id: OperationId::from_bytes(exact_sql(row.get(10)?)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            shard: ShardIdentity {
                generation: u32::try_from(positive_sql(row.get(21)?)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                ..shard
            },
            length,
            digest,
            target_id: meshspan_domain::TargetId::from_bytes(exact_sql(row.get(11)?)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            target_generation: positive_sql(row.get(12)?)?,
        },
        source_layout_generation: positive_sql(row.get(5)?)?,
        replacement_layout_generation: positive_sql(row.get(6)?)?,
        committed_at: UnixMicros::new(row.get(15)?),
        revision: Revision::new(positive_sql(row.get(16)?)?),
    };
    let subject = meshspan_work::WorkSubject::decode(&row.get::<_, Vec<u8>>(20)?)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    if subject
        != (meshspan_work::WorkSubject::Repair {
            volume_id: record.volume_id,
            manifest_id: record.manifest_id,
            stripe_index: record.source_receipt.shard.stripe_index,
            shard_index: record.source_receipt.shard.shard_index,
            source_generation: record.source_layout_generation,
        })
        || !super::valid_replacement_identity(
            record.source_receipt.shard,
            record.replacement_receipt.shard,
        )
        || !super::valid_receipt(record.source_receipt)
        || !super::valid_receipt(record.replacement_receipt)
        || record.source_layout_generation.checked_add(1)
            != Some(record.replacement_layout_generation)
        || record.source_receipt.operation_id == record.replacement_receipt.operation_id
        || (
            record.source_receipt.target_id,
            record.source_receipt.target_generation,
        ) == (
            record.replacement_receipt.target_id,
            record.replacement_receipt.target_generation,
        )
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(record)
}

fn exact_sql<const LENGTH: usize>(value: Vec<u8>) -> rusqlite::Result<[u8; LENGTH]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn positive_sql(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn positive_or_zero_sql(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

#[cfg(test)]
mod tests {
    use super::{EFFECT_SELECT, FEED_RANGE};

    #[test]
    fn migration120_upgrades_and_uses_the_scope_order_index()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("upgrade.sqlite3");
        let mut connection = rusqlite::Connection::open(&path)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        crate::migration::migrate_partition_through(&mut connection, 119, 1)?;
        let prior: Vec<u8> = connection.query_row(
            "SELECT migration_digest FROM schema_migrations WHERE version = 119",
            [],
            |row| row.get(0),
        )?;
        crate::migration::migrate_partition(&mut connection, 2)?;
        drop(connection);
        let mut reopened = rusqlite::Connection::open(&path)?;
        reopened.pragma_update(None, "foreign_keys", "ON")?;
        crate::migration::migrate_partition(&mut reopened, 3)?;
        assert_eq!(
            reopened.query_row(
                "SELECT migration_digest FROM schema_migrations WHERE version = 119",
                [],
                |row| row.get::<_, Vec<u8>>(0)
            )?,
            prior
        );
        let version: i64 =
            reopened.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })?;
        assert_eq!(
            version,
            i64::from(crate::migration::PARTITION_SCHEMA_VERSION)
        );
        let mut statement =
            reopened.prepare(&format!("EXPLAIN QUERY PLAN {EFFECT_SELECT}{FEED_RANGE}"))?;
        let details = statement
            .query_map(
                rusqlite::params![
                    [7_u8; 16].as_slice(),
                    [43_u8; 16].as_slice(),
                    1_i64,
                    [1_u8; 16].as_slice(),
                    3_i64
                ],
                |row| row.get::<_, String>(3),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        assert!(
            details.iter().any(|detail| detail
                .contains("SEARCH e USING INDEX maintenance_repair_effects_scope_order")),
            "{details:?}"
        );
        assert!(
            details.iter().all(|detail| !detail.contains("TEMP B-TREE")),
            "{details:?}"
        );
        assert_eq!(
            reopened.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))?,
            "ok"
        );
        assert!(!reopened.prepare("PRAGMA foreign_key_check")?.exists([])?);
        Ok(())
    }
}
