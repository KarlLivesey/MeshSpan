// SPDX-License-Identifier: GPL-2.0-only

//! Constant-size pager metadata reads, not table scans or a compaction operation.

use super::{PackStore, PackStoreError};
use meshspan_contracts::PackSpaceObservation;

impl PackStore {
    pub(crate) fn observe_space(&self) -> Result<PackSpaceObservation, PackStoreError> {
        observe_space(&self.connection)
    }
}

pub(super) fn observe_space(
    connection: &rusqlite::Connection,
) -> Result<PackSpaceObservation, PackStoreError> {
    let transaction = connection.unchecked_transaction()?;
    let page_size: i64 = transaction.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let pages: i64 = transaction.pragma_query_value(None, "page_count", |row| row.get(0))?;
    let free: i64 = transaction.pragma_query_value(None, "freelist_count", |row| row.get(0))?;
    let result = decode_space(page_size, pages, free)?;
    transaction.commit()?;
    Ok(result)
}

fn decode_space(
    page_size: i64,
    pages: i64,
    free: i64,
) -> Result<PackSpaceObservation, PackStoreError> {
    let page_size = u64::try_from(page_size).map_err(|_| PackStoreError::Corrupt)?;
    let pages = u64::try_from(pages).map_err(|_| PackStoreError::Corrupt)?;
    let free = u64::try_from(free).map_err(|_| PackStoreError::Corrupt)?;
    if !(512..=65_536).contains(&page_size)
        || !page_size.is_power_of_two()
        || pages == 0
        || free > pages
    {
        return Err(PackStoreError::Corrupt);
    }
    Ok(PackSpaceObservation {
        database_bytes: pages
            .checked_mul(page_size)
            .ok_or(PackStoreError::Corrupt)?,
        reusable_bytes: free.checked_mul(page_size).ok_or(PackStoreError::Corrupt)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_units_are_exact_and_invalid_metadata_is_not_zero() -> Result<(), PackStoreError> {
        assert_eq!(
            decode_space(4_096, 10, 3)?,
            PackSpaceObservation {
                database_bytes: 40_960,
                reusable_bytes: 12_288
            }
        );
        for values in [
            (0, 10, 3),
            (513, 10, 3),
            (4_096, 0, 0),
            (4_096, 10, 11),
            (4_096, -1, 0),
            (4_096, 10, -1),
            (65_536, i64::MAX, 0),
        ] {
            assert!(decode_space(values.0, values.1, values.2).is_err());
        }
        Ok(())
    }
}
