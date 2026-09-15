// SPDX-License-Identifier: GPL-2.0-only

//! Atomic private-copy catalogue. Pending packs never participate in shard lookup.

use std::path::Path;

use meshspan_contracts::ShardIdentity;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use super::{Error, RecoveryInventorySummary, RecoveryShardRetention};
use crate::{
    TargetMarker,
    recovery::RecoveryShardRecord,
    shard::{decode_shard, encode_shard},
};

// Choose the next physical generation first, then use the exact-key suffix to order copies.
// SQLite otherwise sorts the copy suffix after a generation range, despite fixed length/digest.
const CANDIDATE_QUERY: &str =
    "SELECT packs.id, packs.sequence, CASE WHEN length(packs.marker) = 116 THEN packs.marker END,
                CASE WHEN length(shard_identity) = 46 THEN shard_identity END
     FROM shards INDEXED BY shards_exact JOIN packs ON packs.id = shards.pack_id
     WHERE shard_identity = (
        SELECT MIN(candidate.shard_identity) FROM shards AS candidate INDEXED BY shards_exact
        WHERE candidate.shard_identity BETWEEN ?1 AND ?2
            AND candidate.stored_length = ?3 AND candidate.digest = ?4
            AND (candidate.shard_identity, candidate.pack_id) > (?5, ?6)
            AND EXISTS (SELECT 1 FROM packs WHERE id = candidate.pack_id AND complete = 1)
     ) AND stored_length = ?3 AND digest = ?4
        AND (shard_identity, pack_id) > (?5, ?6) AND complete = 1
     ORDER BY pack_id LIMIT 1";

const SCHEMA: &str = "
CREATE TABLE inventory_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
 scope BLOB NOT NULL CHECK(length(scope) = 32),
 schema_digest BLOB NOT NULL CHECK(length(schema_digest) = 32),
 maximum_bytes INTEGER NOT NULL CHECK(maximum_bytes > 0),
 copied_bytes INTEGER NOT NULL CHECK(copied_bytes BETWEEN 0 AND maximum_bytes)
) STRICT;
CREATE TABLE packs (
 id INTEGER PRIMARY KEY,
 mesh_id BLOB NOT NULL CHECK(length(mesh_id) = 16),
 target_id BLOB NOT NULL CHECK(length(target_id) = 16),
 generation INTEGER NOT NULL CHECK(generation > 0),
 sequence INTEGER NOT NULL CHECK(sequence > 0),
 marker BLOB NOT NULL CHECK(length(marker) = 116),
 complete INTEGER NOT NULL CHECK(complete IN (0, 1)),
 copied_bytes INTEGER NOT NULL CHECK(copied_bytes >= 0),
 UNIQUE(mesh_id, target_id, generation, sequence)
) STRICT;
CREATE TABLE shards (
 pack_id INTEGER NOT NULL REFERENCES packs(id),
 shard_identity BLOB NOT NULL CHECK(length(shard_identity) = 46),
 stored_length INTEGER NOT NULL CHECK(stored_length BETWEEN 1 AND 67108864),
 digest BLOB NOT NULL CHECK(length(digest) = 32),
 PRIMARY KEY(pack_id, shard_identity)
) STRICT;
CREATE INDEX shards_exact ON shards(shard_identity, stored_length, digest, pack_id);
PRAGMA user_version = 1;";

pub(super) struct Repository {
    connection: Connection,
}

pub(super) struct ReservedPack {
    pub id: i64,
    pub complete: bool,
}

#[derive(Clone, Copy)]
pub(super) enum CandidateMatch {
    Exact(ShardIdentity),
    Content(ShardIdentity),
}

pub(super) struct CopiedPack {
    pub id: i64,
    pub marker: TargetMarker,
    pub sequence: u64,
}

pub(super) struct ShardCandidate {
    pub shard: ShardIdentity,
    pub pack: CopiedPack,
}

impl Repository {
    pub(super) fn create(file: &Path, scope: [u8; 32], maximum: u64) -> Result<Self, Error> {
        let mut connection = connect(file)?;
        let transaction = connection.transaction()?;
        transaction.execute_batch(SCHEMA)?;
        transaction.execute(
            "INSERT INTO inventory_state VALUES (1, ?1, ?2, ?3, 0)",
            params![
                scope.as_slice(),
                blake3::hash(SCHEMA.as_bytes()).as_bytes().as_slice(),
                sql(maximum)?
            ],
        )?;
        transaction.commit()?;
        Ok(Self { connection })
    }

    pub(super) fn open(file: &Path, scope: [u8; 32]) -> Result<Self, Error> {
        let connection = connect(file)?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let (stored, schema): (Vec<u8>, Vec<u8>) = connection.query_row(
            "SELECT CASE WHEN length(scope) = 32 THEN scope END, CASE WHEN length(schema_digest) = 32 THEN schema_digest END FROM inventory_state WHERE singleton = 1", [], |row| Ok((row.get(0)?, row.get(1)?)))?;
        if version != 1
            || stored.as_slice() != scope
            || schema.as_slice() != blake3::hash(SCHEMA.as_bytes()).as_bytes()
        {
            return Err(Error::IdentityMismatch);
        }
        Ok(Self { connection })
    }

    pub(super) fn reserve(
        &mut self,
        marker: TargetMarker,
        sequence: u64,
    ) -> Result<ReservedPack, Error> {
        let transaction = self.connection.transaction()?;
        let mesh = marker.mesh_id().as_bytes();
        let target = marker.target_id().as_bytes();
        let identity = params![
            mesh.as_slice(),
            target.as_slice(),
            sql(marker.generation())?,
            sql(sequence)?
        ];
        let existing: Option<(i64, i64, Vec<u8>)> = transaction.query_row(
            "SELECT id, complete, CASE WHEN length(marker) = 116 THEN marker END FROM packs WHERE mesh_id = ?1 AND target_id = ?2 AND generation = ?3 AND sequence = ?4",
            identity, |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional()?;
        if let Some((id, complete, bytes)) = existing {
            if id <= 0 || !matches!(complete, 0 | 1) || bytes != marker.encode() {
                return Err(Error::IdentityMismatch);
            }
            return Ok(ReservedPack {
                id,
                complete: complete == 1,
            });
        }
        transaction.execute("INSERT INTO packs(mesh_id, target_id, generation, sequence, marker, complete, copied_bytes) VALUES (?1, ?2, ?3, ?4, ?5, 0, 0)",
            params![marker.mesh_id().as_bytes().as_slice(), marker.target_id().as_bytes().as_slice(), sql(marker.generation())?, sql(sequence)?, marker.encode().as_slice()])?;
        let id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(ReservedPack {
            id,
            complete: false,
        })
    }

    pub(super) fn reset_pending(&mut self, id: i64) -> Result<(), Error> {
        self.connection.execute("DELETE FROM shards WHERE pack_id = ?1 AND EXISTS(SELECT 1 FROM packs WHERE id = ?1 AND complete = 0)", [id])?;
        Ok(())
    }

    pub(super) fn remaining_bytes(&self) -> Result<u64, Error> {
        let remaining: i64 = self.connection.query_row(
            "SELECT maximum_bytes - copied_bytes FROM inventory_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(remaining).map_err(|_| Error::Corrupt)
    }

    pub(super) fn append(&mut self, id: i64, records: &[RecoveryShardRecord]) -> Result<(), Error> {
        let transaction = self.connection.transaction()?;
        for record in records {
            if record.retention == RecoveryShardRetention::Unlinked {
                continue;
            }
            transaction.execute(
                "INSERT INTO shards VALUES (?1, ?2, ?3, ?4)",
                params![
                    id,
                    encode_shard(record.shard).as_slice(),
                    sql(record.length)?,
                    record.digest.as_slice()
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn complete(&mut self, id: i64, copied: u64) -> Result<(), Error> {
        let transaction = self.connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE packs SET complete = 1, copied_bytes = ?2 WHERE id = ?1 AND complete = 0",
            params![id, sql(copied)?],
        )?;
        if changed != 1 {
            return Err(Error::Corrupt);
        }
        let changed = transaction.execute("UPDATE inventory_state SET copied_bytes = copied_bytes + ?1 WHERE singleton = 1 AND maximum_bytes - copied_bytes >= ?1", [sql(copied)?])?;
        if changed != 1 {
            return Err(Error::InvalidInput);
        }
        transaction.commit()?;
        Ok(())
    }

    pub(super) fn candidate(
        &self,
        selection: CandidateMatch,
        length: u64,
        digest: [u8; 32],
        after: Option<(ShardIdentity, i64)>,
    ) -> Result<Option<ShardCandidate>, Error> {
        let (first, last) = match selection {
            CandidateMatch::Exact(shard) => (encode_shard(shard), encode_shard(shard)),
            CandidateMatch::Content(shard) => (
                encode_shard(ShardIdentity {
                    generation: 1,
                    ..shard
                }),
                encode_shard(ShardIdentity {
                    generation: u32::MAX,
                    ..shard
                }),
            ),
        };
        let (after_shard, after_pack) =
            after.map_or((first, 0), |(shard, pack)| (encode_shard(shard), pack));
        let row: Option<(i64, i64, Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                CANDIDATE_QUERY,
                params![
                    first.as_slice(),
                    last.as_slice(),
                    sql(length)?,
                    digest.as_slice(),
                    after_shard.as_slice(),
                    after_pack
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        row.map(|(id, sequence, bytes, shard)| {
            Ok(ShardCandidate {
                shard: decode_shard(&shard).map_err(|_| Error::Corrupt)?,
                pack: CopiedPack {
                    id,
                    sequence: u64::try_from(sequence).map_err(|_| Error::Corrupt)?,
                    marker: TargetMarker::decode(&bytes).map_err(|_| Error::Corrupt)?,
                },
            })
        })
        .transpose()
    }

    pub(super) fn summary(&self) -> Result<RecoveryInventorySummary, Error> {
        let pending: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM packs WHERE complete = 0)",
            [],
            |row| row.get(0),
        )?;
        if pending {
            return Err(Error::Incomplete);
        }
        let (packs, shards, bytes): (i64, i64, i64) = self.connection.query_row(
            "SELECT (SELECT count(*) FROM packs), (SELECT count(*) FROM shards), copied_bytes FROM inventory_state WHERE singleton = 1", [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        Ok(RecoveryInventorySummary {
            packs: u64::try_from(packs).map_err(|_| Error::Corrupt)?,
            retained_shards: u64::try_from(shards).map_err(|_| Error::Corrupt)?,
            copied_bytes: u64::try_from(bytes).map_err(|_| Error::Corrupt)?,
        })
    }

    pub(super) fn visit_packs(
        &self,
        mut visit: impl FnMut(CopiedPack) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut statement = self.connection.prepare("SELECT id, sequence, CASE WHEN length(marker) = 116 THEN marker END FROM packs WHERE complete = 1 ORDER BY mesh_id, target_id, generation, sequence")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let sequence = u64::try_from(row.get::<_, i64>(1)?).map_err(|_| Error::Corrupt)?;
            if sequence == 0 {
                return Err(Error::Corrupt);
            }
            visit(CopiedPack {
                id: row.get(0)?,
                sequence,
                marker: TargetMarker::decode(&row.get::<_, Vec<u8>>(2)?)
                    .map_err(|_| Error::Corrupt)?,
            })?;
        }
        Ok(())
    }
}

fn connect(file: &Path) -> Result<Connection, Error> {
    let connection = Connection::open_with_flags(
        file,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.execute_batch(
        "PRAGMA trusted_schema = OFF; PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL;",
    )?;
    // New databases default to DELETE. Opening a foreign scope must not change its journal mode.
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if journal != "delete" {
        return Err(Error::InvalidInput);
    }
    Ok(connection)
}

fn sql(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_range_uses_the_existing_shard_index_without_sorting()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let inventory = super::super::RecoveryInventory::create(
            &directory.path().join("inventory"),
            [1; 32],
            1024,
        )?;
        let repository = &inventory.repository;
        let first = ShardIdentity {
            manifest_digest: [2; 32],
            stripe_index: 3,
            shard_index: 4,
            generation: 1,
        };
        let last = ShardIdentity {
            generation: u32::MAX,
            ..first
        };
        let mut statement = repository
            .connection
            .prepare(&format!("EXPLAIN QUERY PLAN {CANDIDATE_QUERY}"))?;
        let details = statement
            .query_map(
                params![
                    encode_shard(first).as_slice(),
                    encode_shard(last).as_slice(),
                    100_i64,
                    [5_u8; 32].as_slice(),
                    encode_shard(first).as_slice(),
                    0_i64
                ],
                |row| row.get::<_, String>(3),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("SEARCH shards USING COVERING INDEX shards_exact")),
            "{details:?}"
        );
        assert!(
            details
                .iter()
                .all(|detail| !detail.contains("TEMP B-TREE") && !detail.contains("SCAN")),
            "{details:?}"
        );
        Ok(())
    }
}
