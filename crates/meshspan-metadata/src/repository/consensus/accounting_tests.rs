// SPDX-License-Identifier: GPL-2.0-only

//! Independent accounting oracles, durability boundaries and executed SQLite work.

use meshspan_consensus::{DurableMutation, LogEntry, LogPosition};
use meshspan_domain::{NodeId, OperationId, PartitionId, UnixMicros};
use rusqlite::{Connection, params};

use super::{
    ConsensusStoreError, StoreFailpoint, accounting, load_state, persist_mutation,
    persist_mutation_with_failpoint,
    tests::{entry, initialise_plan},
};
use crate::{MetadataStoreError, PartitionDatabase};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn log_accounting_matches_oracle_after_every_mutation_and_crash() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("accounting.sqlite3");
    let mut database =
        PartitionDatabase::open(&path, PartitionId::from_bytes([1; 16])?, UnixMicros::new(1))?;
    initialise_plan(&mut database, NodeId::from_bytes([2; 16])?, 1)?;
    let first = mutation(
        vec![entry(1, 1, 3, b"first")?, entry(1, 2, 4, b"second")?],
        None,
    );
    persist_mutation(&mut database, 1, &first, UnixMicros::new(2))?;
    assert_oracle(&database, (2, 43))?;
    let old = load_state(&database, 1)?;
    let accounting = accounting_row(database.connection())?;
    let replacement = mutation(
        vec![entry(1, 2, 5, b"replacement")?, entry(1, 3, 6, b"tail")?],
        Some(2),
    );
    assert!(matches!(
        persist_mutation_with_failpoint(
            &mut database,
            1,
            &replacement,
            UnixMicros::new(3),
            StoreFailpoint::BeforeCommit
        ),
        Err(ConsensusStoreError::InjectedFault)
    ));
    assert_eq!(accounting_row(database.connection())?, accounting);
    assert_eq!(load_state(&database, 1)?, old);
    assert_oracle(&database, (2, 43))?;
    drop(database);
    let mut database = PartitionDatabase::open_existing(&path, UnixMicros::new(4))?;
    assert_eq!(accounting_row(database.connection())?, accounting);
    persist_mutation(&mut database, 1, &replacement, UnixMicros::new(5))?;
    assert_oracle(&database, (3, 68))?;
    persist_mutation(&mut database, 1, &replacement, UnixMicros::new(6))?;
    assert_oracle(&database, (3, 68))?;
    let committed = load_state(&database, 1)?;
    let before_invalid = accounting_row(database.connection())?;
    let invalid = mutation(vec![entry(1, 4, 7, b"gap")?], Some(2));
    assert!(matches!(
        persist_mutation(&mut database, 1, &invalid, UnixMicros::new(7)),
        Err(ConsensusStoreError::InvalidMutation)
    ));
    assert_eq!(accounting_row(database.connection())?, before_invalid);
    assert_eq!(load_state(&database, 1)?, committed);
    persist_mutation(
        &mut database,
        1,
        &mutation(Vec::new(), Some(2)),
        UnixMicros::new(8),
    )?;
    assert_oracle(&database, (1, 21))?;
    drop(database);
    let database = PartitionDatabase::open_existing(&path, UnixMicros::new(9))?;
    assert_oracle(&database, (1, 21))
}

#[test]
fn accounting_migration_backfills_retained_history_once() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("migration.sqlite3");
    let mut connection = Connection::open(&path)?;
    crate::migration::migrate_partition_through(&mut connection, 122, 1)?;
    for (index, bytes) in [(1, 19), (2, 21)] {
        connection.execute("INSERT INTO consensus_log(log_index, term, entry_kind, entry_version, payload, payload_digest)
            VALUES (?1, 1, 1, 1, zeroblob(?2), zeroblob(32))", params![index, bytes])?;
    }
    crate::migration::migrate_partition(&mut connection, 2)?;
    assert_eq!(accounting_row(&connection)?, (2, 40, 0));
    crate::migration::migrate_partition(&mut connection, 3)?;
    assert_eq!(accounting_row(&connection)?, (2, 40, 0));
    drop(connection);
    let database =
        PartitionDatabase::open(&path, PartitionId::from_bytes([1; 16])?, UnixMicros::new(4))?;
    assert_oracle(&database, (2, 40))
}

#[test]
fn corrupt_accounting_fails_load_integrity_and_restart_without_repair() -> TestResult {
    for corrupt in [
        "UPDATE consensus_log_accounting SET entry_count = entry_count + 1",
        "UPDATE consensus_log_accounting SET payload_bytes = payload_bytes + 1",
        "DELETE FROM consensus_log_accounting",
        "PRAGMA ignore_check_constraints = ON; UPDATE consensus_log_accounting SET format_version = 2; PRAGMA ignore_check_constraints = OFF",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("corrupt.sqlite3");
        let mut database =
            PartitionDatabase::open(&path, PartitionId::from_bytes([1; 16])?, UnixMicros::new(1))?;
        initialise_plan(&mut database, NodeId::from_bytes([2; 16])?, 1)?;
        persist_mutation(
            &mut database,
            1,
            &mutation(vec![entry(1, 1, 3, b"kept")?], None),
            UnixMicros::new(2),
        )?;
        database.connection().execute_batch(corrupt)?;
        let before = raw_accounting(database.connection())?;
        assert!(matches!(
            load_state(&database, 1),
            Err(ConsensusStoreError::CorruptState)
        ));
        assert!(matches!(
            database.check_integrity(),
            Err(MetadataStoreError::IntegrityFailed)
        ));
        drop(database);
        assert!(matches!(
            PartitionDatabase::open_existing(&path, UnixMicros::new(3)),
            Err(MetadataStoreError::IntegrityFailed)
        ));
        let connection = Connection::open(&path)?;
        assert_eq!(raw_accounting(&connection)?, before);
        let bytes: i64 = connection.query_row(
            "SELECT sum(length(payload)) FROM consensus_log",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(bytes, 20);
    }
    Ok(())
}

#[test]
fn fixed_append_accounting_does_not_scan_retained_history() -> TestResult {
    let mut previous_work = None;
    for retained in [1_000_u64, 10_000, 100_000] {
        let directory = tempfile::tempdir()?;
        let mut database = PartitionDatabase::open(
            &directory.path().join("work.sqlite3"),
            PartitionId::from_bytes([1; 16])?,
            UnixMicros::new(1),
        )?;
        initialise_plan(&mut database, NodeId::from_bytes([2; 16])?, 1)?;
        let entries = (1..=retained)
            .map(sized_entry)
            .collect::<Result<Vec<_>, _>>()?;
        persist_mutation(
            &mut database,
            1,
            &mutation(entries, None),
            UnixMicros::new(2),
        )?;
        accounting::take_work();
        let changes = database.connection().total_changes();
        let append = DurableMutation {
            vote_state: None,
            ..mutation(vec![sized_entry(retained + 1)?], None)
        };
        persist_mutation(&mut database, 1, &append, UnixMicros::new(3))?;
        let append_work = accounting::take_work();
        assert_eq!(
            database.connection().total_changes() - changes,
            2,
            "one log row and one accounting row"
        );
        let vote = mutation(Vec::new(), None);
        let changes = database.connection().total_changes();
        persist_mutation(&mut database, 1, &vote, UnixMicros::new(4))?;
        let vote_work = accounting::take_work();
        assert_eq!(
            database.connection().total_changes() - changes,
            1,
            "vote-only updates no accounting rows"
        );
        for work in [append_work, vote_work] {
            assert_eq!(work.statements, 1);
            assert_eq!(work.fullscan_steps, 0, "retained={retained}, work={work:?}");
            assert!(
                work.vm_steps > 0 && work.vm_steps < 100,
                "retained={retained}, work={work:?}"
            );
        }
        let measured = (append_work, vote_work);
        if let Some(previous) = previous_work {
            assert_eq!(
                measured, previous,
                "accounting work depends on retained history"
            );
        }
        previous_work = Some(measured);
        assert_oracle(&database, (retained + 1, (retained + 1) * 80))?;
    }
    Ok(())
}

#[test]
fn suffix_accounting_uses_an_indexed_range() -> TestResult {
    let directory = tempfile::tempdir()?;
    let database = PartitionDatabase::open(
        &directory.path().join("plan.sqlite3"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let plans = database.connection().prepare(
        "EXPLAIN QUERY PLAN SELECT count(*), coalesce(sum(length(payload)), 0) FROM consensus_log WHERE log_index >= ?1")?
        .query_map([42], |row| row.get::<_, String>(3))?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(plans.len(), 1);
    assert!(
        plans[0].contains("SEARCH consensus_log USING INTEGER PRIMARY KEY"),
        "{plans:?}"
    );
    Ok(())
}

fn mutation(append: Vec<LogEntry>, truncate_from: Option<u64>) -> DurableMutation {
    DurableMutation {
        vote_state: Some((1, None)),
        truncate_from,
        append,
        membership_epoch: None,
        quorum_plan: None,
    }
}

fn sized_entry(index: u64) -> Result<LogEntry, ConsensusStoreError> {
    let mut operation = [1; 16];
    operation[8..].copy_from_slice(&index.to_be_bytes());
    Ok(LogEntry::new(
        LogPosition { term: 1, index },
        OperationId::from_bytes(operation).map_err(|_| ConsensusStoreError::InvalidMutation)?,
        1,
        vec![7; 64],
    )?)
}

fn assert_oracle(database: &PartitionDatabase, expected: (u64, u64)) -> TestResult {
    let actual: (i64, i64) = database.connection().query_row(
        "SELECT count(*), coalesce(sum(length(payload)), 0) FROM consensus_log",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let actual = (u64::try_from(actual.0)?, u64::try_from(actual.1)?);
    let recorded = accounting::read(database.connection())?;
    assert_eq!(actual, expected);
    assert_eq!((recorded.entry_count, recorded.payload_bytes), actual);
    database.check_integrity()?;
    Ok(())
}

fn accounting_row(connection: &Connection) -> Result<(i64, i64, i64), rusqlite::Error> {
    connection.query_row("SELECT entry_count, payload_bytes, revision FROM consensus_log_accounting WHERE singleton = 1", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
}

fn raw_accounting(connection: &Connection) -> Result<Vec<(i64, i64, i64, i64)>, rusqlite::Error> {
    connection.prepare("SELECT format_version, entry_count, payload_bytes, revision FROM consensus_log_accounting ORDER BY singleton")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?.collect()
}
