// SPDX-License-Identifier: GPL-2.0-only

//! Transactional merged-range index for bounded resumable-upload pagination.

use std::ops::Range;

use meshspan_domain::StageId;
use rusqlite::{Connection, Transaction, params};

use crate::StageStoreError;

pub(crate) const MAXIMUM_RANGE_PAGE_ITEMS: u16 = 256;

pub(crate) struct IndexedRangePage {
    pub(crate) sequence: u64,
    pub(crate) ranges: Vec<Range<u64>>,
    pub(crate) next_after_start: Option<u64>,
}

pub(crate) fn merge(
    transaction: &Transaction<'_>,
    stage_id: StageId,
    new_range: Range<u64>,
) -> Result<(), StageStoreError> {
    if new_range.start >= new_range.end {
        return Err(StageStoreError::InvalidInput);
    }
    let identifier = stage_id.as_bytes();
    let bounds: (Option<i64>, Option<i64>) = transaction.query_row(
        "SELECT MIN(range_start), MAX(range_end)
         FROM stage_ranges
         WHERE stage_id = ?1 AND range_start <= ?2 AND range_end >= ?3",
        params![
            identifier.as_slice(),
            to_i64(new_range.end)?,
            to_i64(new_range.start)?
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let merged_start = bounds
        .0
        .map(from_i64)
        .transpose()?
        .map_or(new_range.start, |start| start.min(new_range.start));
    let merged_end = bounds
        .1
        .map(from_i64)
        .transpose()?
        .map_or(new_range.end, |end| end.max(new_range.end));
    transaction.execute(
        "DELETE FROM stage_ranges
         WHERE stage_id = ?1 AND range_start <= ?2 AND range_end >= ?3",
        params![
            identifier.as_slice(),
            to_i64(new_range.end)?,
            to_i64(new_range.start)?
        ],
    )?;
    transaction.execute(
        "INSERT INTO stage_ranges(stage_id, range_start, range_end) VALUES (?1, ?2, ?3)",
        params![
            identifier.as_slice(),
            to_i64(merged_start)?,
            to_i64(merged_end)?
        ],
    )?;
    Ok(())
}

pub(crate) fn page(
    connection: &Connection,
    stage_id: StageId,
    expected_sequence: Option<u64>,
    after_start: Option<u64>,
    limit: u16,
) -> Result<IndexedRangePage, StageStoreError> {
    if limit == 0 || limit > MAXIMUM_RANGE_PAGE_ITEMS {
        return Err(StageStoreError::InvalidInput);
    }
    let mut statement = connection.prepare(
        "SELECT stages.mutation_sequence, stage_ranges.range_start, stage_ranges.range_end
         FROM stages
         LEFT JOIN stage_ranges
           ON stage_ranges.stage_id = stages.stage_id
          AND (?2 IS NULL OR stage_ranges.range_start > ?2)
         WHERE stages.stage_id = ?1
           AND (?3 IS NULL OR stages.mutation_sequence = ?3)
         ORDER BY stage_ranges.range_start
         LIMIT ?4",
    )?;
    let mut rows = statement.query(params![
        stage_id.as_bytes().as_slice(),
        after_start.map(to_i64).transpose()?,
        expected_sequence.map(to_i64).transpose()?,
        i64::from(limit) + 1,
    ])?;
    let mut sequence = None;
    let mut ranges = Vec::with_capacity(usize::from(limit) + 1);
    while let Some(row) = rows.next()? {
        let row_sequence = from_i64(row.get(0)?)?;
        if sequence
            .replace(row_sequence)
            .is_some_and(|value| value != row_sequence)
        {
            return Err(StageStoreError::Corrupt);
        }
        let start: Option<i64> = row.get(1)?;
        let end: Option<i64> = row.get(2)?;
        match (start, end) {
            (Some(start), Some(end)) => ranges.push(from_i64(start)?..from_i64(end)?),
            (None, None) => {}
            _ => return Err(StageStoreError::Corrupt),
        }
    }
    let sequence = sequence.ok_or(StageStoreError::Stale)?;
    let has_more = ranges.len() > usize::from(limit);
    let next_after_start = if has_more {
        ranges.pop();
        Some(ranges.last().ok_or(StageStoreError::Corrupt)?.start)
    } else {
        None
    };
    verify_ranges(&ranges)?;
    Ok(IndexedRangePage {
        sequence,
        ranges,
        next_after_start,
    })
}

fn verify_ranges(ranges: &[Range<u64>]) -> Result<(), StageStoreError> {
    let valid = ranges.iter().all(|range| range.start < range.end)
        && ranges.windows(2).all(|pair| pair[0].end < pair[1].start);
    if valid {
        Ok(())
    } else {
        Err(StageStoreError::Corrupt)
    }
}

fn to_i64(value: u64) -> Result<i64, StageStoreError> {
    i64::try_from(value).map_err(|_| StageStoreError::InvalidInput)
}

fn from_i64(value: i64) -> Result<u64, StageStoreError> {
    u64::try_from(value).map_err(|_| StageStoreError::Corrupt)
}
