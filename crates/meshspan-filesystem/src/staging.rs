// SPDX-License-Identifier: GPL-2.0-only

//! Pure fenced random-write and completeness rules shared by every staging backend.

use std::collections::BTreeMap;
use std::ops::Range;

use meshspan_contracts::BoundedBytes;
use meshspan_domain::OperationId;
use thiserror::Error;

/// One bounded, independently idempotent stage range write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageWrite {
    /// Stable identity whose exact retries coalesce.
    pub operation_id: OperationId,
    /// Current stage generation; stale writers cannot alter a resumed stage.
    pub stage_fence: u64,
    /// Logical byte offset at which this part begins.
    pub offset: u64,
    /// Complete range bytes beneath the stage's configured bound.
    pub bytes: BoundedBytes,
    /// BLAKE3 digest independently checked before mutation.
    pub digest: [u8; 32],
}

/// Observable result of one accepted range write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StageWriteOutcome {
    /// New bytes were applied in the stage's durable ordering.
    Applied,
    /// The exact operation/range/content had already been applied.
    Replayed,
}

/// Complete range coverage and logical extent at one checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    /// Monotonic mutation sequence within this stage fence.
    pub sequence: u64,
    /// Highest byte offset written, exclusive.
    pub logical_extent: u64,
    /// Sorted, non-overlapping and adjacency-merged initialised ranges.
    pub initialised_ranges: Vec<Range<u64>>,
}

/// Bounded in-memory reference implementation of the staging semantic kernel.
///
/// Production staging persists the same transitions through a replaceable backend; this type is
/// the deterministic behaviour oracle and never implies that large files belong in memory.
pub struct StageOverlay {
    fence: u64,
    maximum_bytes: usize,
    bytes: Vec<u8>,
    ranges: Vec<Range<u64>>,
    operations: BTreeMap<OperationId, AppliedWrite>,
    sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AppliedWrite {
    offset: u64,
    length: u64,
    digest: [u8; 32],
}

impl StageOverlay {
    /// Creates one empty fenced overlay beneath an explicit logical byte limit.
    ///
    /// # Errors
    ///
    /// Rejects a zero fence or zero maximum byte count.
    pub fn new(fence: u64, maximum_bytes: usize) -> Result<Self, StageWriteError> {
        if fence == 0 || maximum_bytes == 0 {
            return Err(StageWriteError::InvalidInput);
        }
        Ok(Self {
            fence,
            maximum_bytes,
            bytes: Vec::new(),
            ranges: Vec::new(),
            operations: BTreeMap::new(),
            sequence: 0,
        })
    }

    /// Applies an exact range or resolves its idempotent replay.
    ///
    /// Later accepted overlapping writes replace earlier stage bytes in mutation order. The stage
    /// remains private, so no intermediate combination is user-visible.
    ///
    /// # Errors
    ///
    /// Rejects stale fences, empty/excessive/overflowing ranges, digest mismatch and operation-ID
    /// reuse with different range or content.
    pub fn write(&mut self, write: &StageWrite) -> Result<StageWriteOutcome, StageWriteError> {
        let applied = validate_write(write, self.fence, self.maximum_bytes)?;
        if let Some(existing) = self.operations.get(&write.operation_id) {
            return if *existing == applied {
                Ok(StageWriteOutcome::Replayed)
            } else {
                Err(StageWriteError::OperationConflict)
            };
        }
        let end = usize::try_from(
            write
                .offset
                .checked_add(applied.length)
                .ok_or(StageWriteError::InvalidInput)?,
        )
        .map_err(|_| StageWriteError::InvalidInput)?;
        if self.bytes.len() < end {
            self.bytes.resize(end, 0);
        }
        let start = usize::try_from(write.offset).map_err(|_| StageWriteError::InvalidInput)?;
        self.bytes[start..end].copy_from_slice(write.bytes.as_slice());
        insert_range(
            &mut self.ranges,
            write.offset..u64::try_from(end).map_err(|_| StageWriteError::InvalidInput)?,
        );
        self.operations.insert(write.operation_id, applied);
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(StageWriteError::InvalidInput)?;
        Ok(StageWriteOutcome::Applied)
    }

    /// Captures the exact private progress that a durable backend must persist before success.
    #[must_use]
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            sequence: self.sequence,
            logical_extent: u64::try_from(self.bytes.len()).unwrap_or(u64::MAX),
            initialised_ranges: self.ranges.clone(),
        }
    }

    /// Produces exact complete commit bytes without publishing or mutating the stage.
    ///
    /// # Errors
    ///
    /// Rejects excessive final length and missing ranges unless sparse completion was explicit.
    pub fn complete_bytes(
        &self,
        final_length: u64,
        sparse: bool,
    ) -> Result<BoundedBytes, StageWriteError> {
        let length = usize::try_from(final_length).map_err(|_| StageWriteError::InvalidInput)?;
        if length > self.maximum_bytes {
            return Err(StageWriteError::InvalidInput);
        }
        if !sparse && !covers(&self.ranges, final_length) {
            return Err(StageWriteError::Incomplete);
        }
        let mut complete = self.bytes.get(..length).map_or_else(
            || {
                let mut expanded = self.bytes.clone();
                expanded.resize(length, 0);
                expanded
            },
            <[u8]>::to_vec,
        );
        complete.truncate(length);
        BoundedBytes::copy_from(&complete, self.maximum_bytes)
            .map_err(|_| StageWriteError::InvalidInput)
    }
}

/// Stable rejection categories for private staged range mutations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StageWriteError {
    /// Fence, range, length, digest or configured bound is invalid.
    #[error("staged write input is invalid")]
    InvalidInput,
    /// The caller's stage generation is no longer current.
    #[error("staged write fence is stale")]
    StaleFence,
    /// An operation identity already belongs to different range/content.
    #[error("staged write operation conflicts with an earlier input")]
    OperationConflict,
    /// Commit would expose one or more uninitialised ranges.
    #[error("staged write is incomplete")]
    Incomplete,
}

fn validate_write(
    write: &StageWrite,
    expected_fence: u64,
    maximum_bytes: usize,
) -> Result<AppliedWrite, StageWriteError> {
    if write.stage_fence != expected_fence {
        return Err(StageWriteError::StaleFence);
    }
    if write.bytes.is_empty() || blake3::hash(write.bytes.as_slice()).as_bytes() != &write.digest {
        return Err(StageWriteError::InvalidInput);
    }
    let length = u64::try_from(write.bytes.len()).map_err(|_| StageWriteError::InvalidInput)?;
    let end = write
        .offset
        .checked_add(length)
        .ok_or(StageWriteError::InvalidInput)?;
    if end > u64::try_from(maximum_bytes).map_err(|_| StageWriteError::InvalidInput)? {
        return Err(StageWriteError::InvalidInput);
    }
    Ok(AppliedWrite {
        offset: write.offset,
        length,
        digest: write.digest,
    })
}

pub(crate) fn insert_range(ranges: &mut Vec<Range<u64>>, mut inserted: Range<u64>) {
    let mut merged = Vec::with_capacity(ranges.len().saturating_add(1));
    let mut placed = false;
    for range in ranges.drain(..) {
        if range.end < inserted.start {
            merged.push(range);
        } else if inserted.end < range.start {
            if !placed {
                merged.push(inserted.clone());
                placed = true;
            }
            merged.push(range);
        } else {
            inserted.start = inserted.start.min(range.start);
            inserted.end = inserted.end.max(range.end);
        }
    }
    if !placed {
        merged.push(inserted);
    }
    *ranges = merged;
}

pub(crate) fn covers(ranges: &[Range<u64>], final_length: u64) -> bool {
    final_length == 0
        || ranges
            .first()
            .is_some_and(|range| range.start == 0 && range.end >= final_length)
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::BoundedBytes;
    use meshspan_domain::OperationId;

    use super::{StageOverlay, StageWrite, StageWriteError, StageWriteOutcome};

    #[test]
    fn random_overlap_replay_and_sparse_completion_are_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut stage = StageOverlay::new(3, 64)?;
        let suffix = write(1, 3, 5, b"world")?;
        assert_eq!(stage.write(&suffix)?, StageWriteOutcome::Applied);
        assert_eq!(stage.write(&suffix)?, StageWriteOutcome::Replayed);
        assert_eq!(
            stage.complete_bytes(10, false),
            Err(StageWriteError::Incomplete)
        );
        let prefix = write(2, 3, 0, b"hello")?;
        stage.write(&prefix)?;
        assert_eq!(stage.complete_bytes(10, false)?.as_slice(), b"helloworld");
        let overwrite = write(3, 3, 3, b"p!!")?;
        stage.write(&overwrite)?;
        assert_eq!(stage.complete_bytes(10, false)?.as_slice(), b"help!!orld");
        assert_eq!(stage.checkpoint().initialised_ranges, vec![0..10]);

        let sparse = StageOverlay::new(4, 64)?;
        assert!(sparse.complete_bytes(0, false)?.is_empty());
        assert_eq!(sparse.complete_bytes(4, true)?.as_slice(), [0; 4]);
        Ok(())
    }

    #[test]
    fn stale_forged_excessive_and_conflicting_writes_change_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut stage = StageOverlay::new(7, 8)?;
        assert_eq!(
            stage.write(&write(1, 6, 0, b"a")?),
            Err(StageWriteError::StaleFence)
        );
        let mut forged = write(2, 7, 0, b"a")?;
        forged.digest[0] ^= 1;
        assert_eq!(stage.write(&forged), Err(StageWriteError::InvalidInput));
        assert_eq!(
            stage.write(&write(3, 7, 8, b"x")?),
            Err(StageWriteError::InvalidInput)
        );
        stage.write(&write(4, 7, 0, b"ok")?)?;
        assert_eq!(
            stage.write(&write(4, 7, 0, b"no")?),
            Err(StageWriteError::OperationConflict)
        );
        assert_eq!(stage.complete_bytes(2, false)?.as_slice(), b"ok");
        Ok(())
    }

    fn write(
        operation: u8,
        fence: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<StageWrite, Box<dyn std::error::Error>> {
        let bounded = BoundedBytes::copy_from(bytes, 64)?;
        Ok(StageWrite {
            operation_id: OperationId::from_bytes([operation; 16])?,
            stage_fence: fence,
            offset,
            digest: blake3::hash(bytes).into(),
            bytes: bounded,
        })
    }
}
