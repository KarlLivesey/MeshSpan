// SPDX-License-Identifier: GPL-2.0-only

//! Exact retained-log resource accounting, changed in the log writer's transaction.

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{ConsensusStoreError, MAXIMUM_RECOVERED_LOG_BYTES, MAXIMUM_RECOVERED_LOG_ENTRIES};

const READ_QUERY: &str = "SELECT entry_count, payload_bytes, revision, format_version
    FROM consensus_log_accounting WHERE singleton = 1";
const SUFFIX_QUERY: &str = "SELECT count(*), coalesce(sum(length(payload)), 0)
    FROM consensus_log WHERE log_index >= ?1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Accounting {
    pub(super) entry_count: u64,
    pub(super) payload_bytes: u64,
    revision: i64,
}

pub(super) fn read(connection: &Connection) -> Result<Accounting, ConsensusStoreError> {
    let mut statement = connection.prepare(READ_QUERY)?;
    let row = statement
        .query_row([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .optional()?;
    #[cfg(test)]
    observe(&statement);
    let (entries, bytes, revision, version) = row.ok_or(ConsensusStoreError::CorruptState)?;
    if version != 1 || revision < 0 {
        return Err(ConsensusStoreError::CorruptState);
    }
    let accounting = Accounting {
        entry_count: super::nonnegative_u64(entries)?,
        payload_bytes: super::nonnegative_u64(bytes)?,
        revision,
    };
    accounting.require_bounds()?;
    Ok(accounting)
}

/// Independent full verification belongs to admission and explicit integrity, never a mutation.
pub(crate) fn verify(connection: &Connection) -> Result<(), ConsensusStoreError> {
    // One statement holds one SQLite read snapshot while comparing both sides.
    let valid: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM consensus_log_accounting a
         CROSS JOIN (SELECT count(*) AS entries, coalesce(sum(length(payload)), 0) AS bytes
                     FROM consensus_log) actual
         WHERE a.singleton = 1 AND a.format_version = 1 AND a.revision >= 0
           AND a.entry_count = actual.entries AND a.payload_bytes = actual.bytes
           AND a.entry_count BETWEEN 0 AND ?1 AND a.payload_bytes BETWEEN 0 AND ?2)",
        params![
            i64::try_from(MAXIMUM_RECOVERED_LOG_ENTRIES)
                .map_err(|_| ConsensusStoreError::RecoveryBoundExceeded)?,
            super::to_i64(MAXIMUM_RECOVERED_LOG_BYTES)?
        ],
        |row| row.get(0),
    )?;
    if !valid {
        return Err(ConsensusStoreError::CorruptState);
    }
    Ok(())
}

/// Removes only the named suffix; the caller commits the new accounting with this deletion.
pub(super) fn delete_suffix(
    transaction: &Transaction<'_>,
    prior: Accounting,
    from: u64,
) -> Result<Accounting, ConsensusStoreError> {
    let mut statement = transaction.prepare(SUFFIX_QUERY)?;
    let (entries, bytes): (i64, i64) =
        statement.query_row([super::to_i64(from)?], |row| Ok((row.get(0)?, row.get(1)?)))?;
    #[cfg(test)]
    observe(&statement);
    let removed_entries = super::nonnegative_u64(entries)?;
    let next = Accounting {
        entry_count: prior
            .entry_count
            .checked_sub(removed_entries)
            .ok_or(ConsensusStoreError::CorruptState)?,
        payload_bytes: prior
            .payload_bytes
            .checked_sub(super::nonnegative_u64(bytes)?)
            .ok_or(ConsensusStoreError::CorruptState)?,
        ..prior
    };
    let deleted = transaction.execute(
        "DELETE FROM consensus_log WHERE log_index >= ?1",
        [super::to_i64(from)?],
    )?;
    if u64::try_from(deleted).ok() != Some(removed_entries) {
        return Err(ConsensusStoreError::CorruptState);
    }
    Ok(next)
}

pub(super) fn store(
    transaction: &Transaction<'_>,
    prior: Accounting,
    next: Accounting,
) -> Result<(), ConsensusStoreError> {
    next.require_bounds()?;
    if next == prior {
        return Ok(());
    }
    let revision = prior
        .revision
        .checked_add(1)
        .ok_or(ConsensusStoreError::RecoveryBoundExceeded)?;
    let updated = transaction.execute(
        "UPDATE consensus_log_accounting SET entry_count = ?1, payload_bytes = ?2, revision = ?3
         WHERE singleton = 1 AND entry_count = ?4 AND payload_bytes = ?5 AND revision = ?6
         AND format_version = 1",
        params![
            super::to_i64(next.entry_count)?,
            super::to_i64(next.payload_bytes)?,
            revision,
            super::to_i64(prior.entry_count)?,
            super::to_i64(prior.payload_bytes)?,
            prior.revision
        ],
    )?;
    if updated != 1 {
        return Err(ConsensusStoreError::CorruptState);
    }
    Ok(())
}

impl Accounting {
    pub(super) fn with_payload(self, payload_bytes: usize) -> Result<Self, ConsensusStoreError> {
        let next = Self {
            entry_count: self
                .entry_count
                .checked_add(1)
                .ok_or(ConsensusStoreError::RecoveryBoundExceeded)?,
            payload_bytes: self
                .payload_bytes
                .checked_add(
                    u64::try_from(payload_bytes)
                        .map_err(|_| ConsensusStoreError::RecoveryBoundExceeded)?,
                )
                .ok_or(ConsensusStoreError::RecoveryBoundExceeded)?,
            ..self
        };
        next.require_bounds()?;
        Ok(next)
    }

    fn require_bounds(self) -> Result<(), ConsensusStoreError> {
        if self.entry_count
            > u64::try_from(MAXIMUM_RECOVERED_LOG_ENTRIES)
                .map_err(|_| ConsensusStoreError::RecoveryBoundExceeded)?
            || self.payload_bytes > MAXIMUM_RECOVERED_LOG_BYTES
        {
            return Err(ConsensusStoreError::RecoveryBoundExceeded);
        }
        Ok(())
    }
}

// Instrument SQLite's executed accounting statements on the actual persistence path.
// Per-thread measurement keeps parallel fixtures independent and changes no production SQL.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct QueryWork {
    pub(super) fullscan_steps: i64,
    pub(super) vm_steps: i64,
    pub(super) statements: u64,
}

#[cfg(test)]
std::thread_local! {
    static QUERY_WORK: std::cell::Cell<QueryWork> = const {
        std::cell::Cell::new(QueryWork { fullscan_steps: 0, vm_steps: 0, statements: 0 })
    };
}

#[cfg(test)]
fn observe(statement: &rusqlite::Statement<'_>) {
    use rusqlite::StatementStatus;
    QUERY_WORK.with(|value| {
        let prior = value.get();
        value.set(QueryWork {
            fullscan_steps: prior.fullscan_steps
                + i64::from(statement.get_status(StatementStatus::FullscanStep)),
            vm_steps: prior.vm_steps + i64::from(statement.get_status(StatementStatus::VmStep)),
            statements: prior.statements + 1,
        });
    });
}

#[cfg(test)]
pub(super) fn take_work() -> QueryWork {
    QUERY_WORK.with(|value| value.replace(QueryWork::default()))
}
