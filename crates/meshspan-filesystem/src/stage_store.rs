// SPDX-License-Identifier: GPL-2.0-only

//! WAL/FULL-sync stage journal plus immutable capability-scoped range parts.

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::Path;

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use meshspan_contracts::BoundedBytes;
use meshspan_domain::{OperationId, StageId, UnixMicros};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;

use crate::staging::{covers, insert_range};
use crate::{Checkpoint, StageWrite, StageWriteOutcome};

const MAXIMUM_SQLITE_INTEGER: u64 = 9_223_372_036_854_775_807;
type BaseLoader<'a> = dyn FnMut(&mut dyn Write) -> Result<(), StageStoreError> + 'a;
const MIGRATIONS: [Migration; 5] = [
    Migration {
        version: 1,
        sql: include_str!("../schema/stage/001_initial.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("../schema/stage/002_lease_operations.sql"),
    },
    Migration {
        version: 3,
        sql: include_str!("../schema/stage/003_truncation_operations.sql"),
    },
    Migration {
        version: 4,
        sql: include_str!("../schema/stage/004_abort_operations.sql"),
    },
    Migration {
        version: 5,
        sql: include_str!("../schema/stage/005_range_index.sql"),
    },
];
const SCHEMA_VERSION: u32 = 5;
const STAGE_DIRECTORY: &str = "stages";
const DATABASE_FILE: &str = "filesystem-stages.sqlite3";
const COPY_BUFFER_BYTES: usize = 64 * 1_024;
const COPY_BUFFER_BYTES_U64: u64 = 65_536;
/// Maximum plaintext bytes returned by one private-stage range read.
pub const MAXIMUM_STAGE_READ_BYTES: usize = 8 * 1_024 * 1_024;

#[derive(Clone, Copy)]
struct Migration {
    version: u32,
    sql: &'static str,
}

/// Durable identity, bounds and expiry for one private write stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageRegistration {
    /// Stable stage identity.
    pub stage_id: StageId,
    /// Positive writer generation.
    pub stage_fence: u64,
    /// Maximum logical bytes admitted for this stage.
    pub maximum_bytes: u64,
    /// Stage creation instant.
    pub created_at: UnixMicros,
    /// Exclusive inactivity/authority expiry.
    pub expires_at: UnixMicros,
}

/// Exact fenced checkpoint selected for one streaming completion attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageCompletionRequest {
    /// Idempotency identity of the later publication operation.
    pub operation_id: OperationId,
    /// Stage to complete.
    pub stage_id: StageId,
    /// Exact writer generation.
    pub stage_fence: u64,
    /// Exact checkpoint sequence; later writes make this request stale.
    pub expected_sequence: u64,
    /// Exact final logical length.
    pub final_length: u64,
    /// Whether uninitialised ranges are explicit logical zeroes.
    pub sparse: bool,
    /// Authoritative time used for expiry validation.
    pub observed_at: UnixMicros,
}

/// Independently verified content identity produced by streaming stage completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletedStage {
    /// Exact number of streamed logical bytes.
    pub logical_length: u64,
    /// BLAKE3 digest of the complete logical byte stream.
    pub content_digest: [u8; 32],
}

/// Exact live checkpoint range selected for a bounded read-your-writes view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageRangeReadRequest {
    /// Private stage derived from the opened handle.
    pub stage_id: StageId,
    /// Exact current handle/stage fence.
    pub stage_fence: u64,
    /// Exact checkpoint sequence selected before provider IO.
    pub expected_sequence: u64,
    /// First logical byte requested.
    pub offset: u64,
    /// Maximum requested bytes; the result is shorter at logical EOF.
    pub length: u64,
    /// Authoritative read instant used for lease expiry.
    pub observed_at: UnixMicros,
}

/// One bounded immutable page over exact initialised range coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageRangePage {
    /// Exact checkpoint represented by every range in this traversal.
    pub checkpoint_sequence: u64,
    /// Sorted, merged, non-adjacent coverage.
    pub ranges: Vec<Range<u64>>,
    /// Start of the last returned range, used only with the pinned checkpoint.
    pub next_after_start: Option<u64>,
}

/// One bounded range-index query pinned after its first page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageRangePageRequest {
    /// Selected private stage.
    pub stage_id: StageId,
    /// First page omits this; continuations require the returned exact sequence.
    pub expected_sequence: Option<u64>,
    /// Exclusive range-start continuation from the preceding page.
    pub after_start: Option<u64>,
    /// Positive page bound no larger than 256.
    pub limit: u16,
}

/// Exact idempotent private-stage lease transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageLeaseRequest {
    /// Stable operation identity shared with the handle lease transition.
    pub operation_id: OperationId,
    /// Private stage derived from the writable handle identity.
    pub stage_id: StageId,
    /// Current positive fence.
    pub expected_fence: u64,
    /// Whether ownership transfer advances the fence by one.
    pub takeover: bool,
    /// New exclusive lease deadline, never earlier than the current deadline.
    pub lease_expires_at: UnixMicros,
    /// Authoritative attempt instant.
    pub observed_at: UnixMicros,
}

/// Observable durable stage-lease result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageLeaseReceipt {
    /// Whether this transition was newly applied or exactly replayed.
    pub outcome: StageWriteOutcome,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Updated stage.
    pub stage_id: StageId,
    /// Exact request digest.
    pub request_digest: [u8; 32],
    /// Fence after renewal/takeover.
    pub stage_fence: u64,
    /// New exclusive lease deadline.
    pub lease_expires_at: UnixMicros,
    /// Digest binding the complete durable result.
    pub result_digest: [u8; 32],
}

/// Exact idempotent abandonment of one private write stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageAbortRequest {
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Private stage being abandoned.
    pub stage_id: StageId,
    /// Exact current writer generation.
    pub stage_fence: u64,
    /// Authoritative abandonment instant.
    pub observed_at: UnixMicros,
}

/// Durable proof that a private stage can no longer accept writes or publish content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageAbortReceipt {
    /// Whether the abort was newly applied or exactly replayed.
    pub outcome: StageWriteOutcome,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Abandoned stage.
    pub stage_id: StageId,
    /// Digest binding the exact abort request.
    pub request_digest: [u8; 32],
    /// Fence retired by the abort.
    pub stage_fence: u64,
    /// Authoritative abandonment instant.
    pub aborted_at: UnixMicros,
    /// Digest binding the complete durable result.
    pub result_digest: [u8; 32],
}

/// Durable stage journal and immutable part storage beneath one daemon state directory.
pub struct DurableStageStore {
    connection: Connection,
    stages: Dir,
}

impl DurableStageStore {
    /// Opens or creates the stage database and capability-scoped private part directory.
    ///
    /// # Errors
    ///
    /// Rejects migration drift, newer schemas, integrity failure and filesystem/SQLite errors.
    pub fn open(state_directory: &Path, opened_at: UnixMicros) -> Result<Self, StageStoreError> {
        fs::create_dir_all(state_directory)?;
        let root = Dir::open_ambient_dir(state_directory, ambient_authority())?;
        match root.create_dir(STAGE_DIRECTORY) {
            Ok(()) => sync_directory(&root)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let stages = root.open_dir(STAGE_DIRECTORY)?;
        let mut connection = Connection::open(state_directory.join(DATABASE_FILE))?;
        configure(&connection)?;
        migrate(&mut connection, opened_at)?;
        verify_database(&connection)?;
        Ok(Self { connection, stages })
    }

    /// Registers one new stage or resolves an exact idempotent replay.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds/time, conflicting identity reuse and persistence failure.
    pub fn register(&mut self, stage: StageRegistration) -> Result<(), StageStoreError> {
        validate_registration(stage)?;
        let identifier = stage.stage_id.as_bytes();
        let expected = (
            to_i64(stage.stage_fence)?,
            to_i64(stage.maximum_bytes)?,
            stage.created_at.get(),
            stage.expires_at.get(),
        );
        let existing: Option<(i64, i64, i64, i64)> = self
            .connection
            .query_row(
                "SELECT stage_fence, maximum_bytes, created_at, expires_at
                 FROM stages WHERE stage_id = ?1",
                [identifier.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        if let Some(existing) = existing {
            return if existing == expected {
                create_stage_directory(&self.stages, stage.stage_id)
            } else {
                Err(StageStoreError::OperationConflict)
            };
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO stages(
                stage_id, stage_fence, maximum_bytes, state, mutation_sequence,
                logical_extent, created_at, expires_at
             ) VALUES (?1, ?2, ?3, 1, 0, 0, ?4, ?5)",
            params![
                identifier.as_slice(),
                expected.0,
                expected.1,
                expected.2,
                expected.3
            ],
        )?;
        transaction.commit()?;
        create_stage_directory(&self.stages, stage.stage_id)
    }

    pub(crate) fn initialise_truncation(
        &mut self,
        stage_id: StageId,
        operation_id: OperationId,
        stage_fence: u64,
        observed_at: UnixMicros,
    ) -> Result<StageWriteOutcome, StageStoreError> {
        type Stored = (Vec<u8>, i64, i64, i64, Vec<u8>, Vec<u8>);
        if stage_fence == 0 {
            return Err(StageStoreError::InvalidInput);
        }
        let request_digest =
            truncation_request_digest(operation_id, stage_id, stage_fence, observed_at);
        let stored: Option<Stored> = self
            .connection
            .query_row(
                "SELECT stage_id, stage_fence, mutation_sequence, applied_at,
                        request_digest, receipt_digest
                 FROM stage_truncation_operations WHERE operation_id = ?1",
                [operation_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        if let Some(stored) = stored {
            let sequence = from_i64(stored.2)?;
            let stored_request: [u8; 32] = stored
                .4
                .as_slice()
                .try_into()
                .map_err(|_| StageStoreError::Corrupt)?;
            let stored_receipt: [u8; 32] = stored
                .5
                .as_slice()
                .try_into()
                .map_err(|_| StageStoreError::Corrupt)?;
            let expected_receipt = truncation_receipt_digest(request_digest, sequence);
            let fields_match = stored.0.as_slice() == stage_id.as_bytes()
                && from_i64(stored.1)? == stage_fence
                && stored.3 == observed_at.get()
                && sequence == 1;
            return match (
                fields_match,
                stored_request == request_digest,
                stored_receipt == expected_receipt,
            ) {
                (true, true, true) => Ok(StageWriteOutcome::Replayed),
                (true, _, _) | (false, true, _) => Err(StageStoreError::Corrupt),
                (false, false, _) => Err(StageStoreError::OperationConflict),
            };
        }
        reject_stage_operation_collision(&self.connection, operation_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE stages SET mutation_sequence = 1, logical_extent = 0
             WHERE stage_id = ?1 AND state = 1 AND stage_fence = ?2
               AND mutation_sequence = 0 AND expires_at > ?3",
            params![
                stage_id.as_bytes().as_slice(),
                to_i64(stage_fence)?,
                observed_at.get()
            ],
        )?;
        if changed != 1 {
            return Err(StageStoreError::Stale);
        }
        let receipt_digest = truncation_receipt_digest(request_digest, 1);
        transaction.execute(
            "INSERT INTO stage_truncation_operations(
                operation_id, stage_id, stage_fence, mutation_sequence, applied_at,
                request_digest, receipt_digest
             ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6)",
            params![
                operation_id.as_bytes().as_slice(),
                stage_id.as_bytes().as_slice(),
                to_i64(stage_fence)?,
                observed_at.get(),
                request_digest.as_slice(),
                receipt_digest.as_slice()
            ],
        )?;
        transaction.commit()?;
        Ok(StageWriteOutcome::Applied)
    }

    /// Durably installs one immutable part before journalling its ordered acceptance.
    ///
    /// # Errors
    ///
    /// Rejects stale/expired stages, malformed writes, conflicting replay, corrupt parts and IO.
    pub fn write(
        &mut self,
        stage_id: StageId,
        write: &StageWrite,
        observed_at: UnixMicros,
    ) -> Result<StageWriteOutcome, StageStoreError> {
        let stage = load_stage(&self.connection, stage_id)?;
        validate_live_write(stage, write, observed_at)?;
        if let Some(existing) = load_write(&self.connection, write.operation_id)? {
            if existing.stage_id != stage_id || !existing.matches(write)? {
                return Err(StageStoreError::OperationConflict);
            }
            verify_part(&self.stages, &existing, write.bytes.as_slice())?;
            return Ok(StageWriteOutcome::Replayed);
        }
        let part_name = install_part(&self.stages, stage_id, write)?;
        self.record_write(stage_id, stage, write, observed_at, &part_name)
    }

    /// Returns the exact ordered range coverage persisted in the stage journal.
    ///
    /// # Errors
    ///
    /// Rejects absent/corrupt stage state or SQLite failure.
    pub fn checkpoint(&self, stage_id: StageId) -> Result<Checkpoint, StageStoreError> {
        let stage = load_stage(&self.connection, stage_id)?;
        let writes = load_stage_writes(&self.connection, stage_id)?;
        let ranges = ranges(&writes)?;
        Ok(Checkpoint {
            sequence: stage.sequence,
            logical_extent: stage.logical_extent,
            initialised_ranges: ranges,
        })
    }

    /// Returns one bounded exact range page without scanning the write journal.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds, absent stages, stale continuation checkpoints and corrupt indexes.
    pub fn range_page(
        &self,
        request: StageRangePageRequest,
    ) -> Result<StageRangePage, StageStoreError> {
        let page = crate::stage_range_index::page(
            &self.connection,
            request.stage_id,
            request.expected_sequence,
            request.after_start,
            request.limit,
        )?;
        Ok(StageRangePage {
            checkpoint_sequence: page.sequence,
            ranges: page.ranges,
            next_after_start: page.next_after_start,
        })
    }

    /// Extends a private-stage lease or advances its fence during explicit handle takeover.
    ///
    /// # Errors
    ///
    /// Rejects stale/expired stages, shrinking leases, fence overflow, operation conflicts,
    /// corrupt receipts and persistence failure.
    pub fn renew_lease(
        &mut self,
        request: StageLeaseRequest,
    ) -> Result<StageLeaseReceipt, StageStoreError> {
        validate_lease_request(request)?;
        let request_digest = lease_request_digest(request);
        if let Some(receipt) = load_lease_receipt(&self.connection, request.operation_id)? {
            return matching_lease_replay(receipt, request, request_digest);
        }
        reject_stage_operation_collision(&self.connection, request.operation_id)?;
        let stage = load_stage(&self.connection, request.stage_id)?;
        let resulting_fence = if request.takeover {
            request
                .expected_fence
                .checked_add(1)
                .ok_or(StageStoreError::InvalidInput)?
        } else {
            request.expected_fence
        };
        if stage.state != 1
            || stage.fence != request.expected_fence
            || stage.expires_at <= request.observed_at
            || request.lease_expires_at < stage.expires_at
        {
            return Err(StageStoreError::Stale);
        }
        let result_digest = lease_result_digest(
            request.operation_id,
            request.stage_id,
            request_digest,
            resulting_fence,
            request.lease_expires_at,
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE stages SET stage_fence = ?1, expires_at = ?2
             WHERE stage_id = ?3 AND state = 1 AND stage_fence = ?4
               AND expires_at > ?5 AND expires_at <= ?2",
            params![
                to_i64(resulting_fence)?,
                request.lease_expires_at.get(),
                request.stage_id.as_bytes().as_slice(),
                to_i64(request.expected_fence)?,
                request.observed_at.get(),
            ],
        )?;
        if updated != 1 {
            return Err(StageStoreError::Stale);
        }
        transaction.execute(
            "INSERT INTO stage_lease_operations(
                operation_id, stage_id, request_digest, expected_fence, resulting_fence,
                lease_expires_at, committed_at, receipt_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                request.operation_id.as_bytes().as_slice(),
                request.stage_id.as_bytes().as_slice(),
                request_digest.as_slice(),
                to_i64(request.expected_fence)?,
                to_i64(resulting_fence)?,
                request.lease_expires_at.get(),
                request.observed_at.get(),
                result_digest.as_slice(),
            ],
        )?;
        transaction.commit()?;
        Ok(StageLeaseReceipt {
            outcome: StageWriteOutcome::Applied,
            operation_id: request.operation_id,
            stage_id: request.stage_id,
            request_digest,
            stage_fence: resulting_fence,
            lease_expires_at: request.lease_expires_at,
            result_digest,
        })
    }

    /// Permanently fences one unpublished stage without making any staged bytes visible.
    ///
    /// Exact retries return the original receipt. The immutable part files remain unreachable and
    /// are reclaimed separately, so a crash cannot turn a partially removed stage back into a
    /// writable one.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale, expired or conflicting requests and persistence failure.
    pub fn abort(
        &mut self,
        request: StageAbortRequest,
    ) -> Result<StageAbortReceipt, StageStoreError> {
        validate_abort_request(request)?;
        let request_digest = abort_request_digest(request);
        if let Some(receipt) = load_abort_receipt(&self.connection, request.operation_id)? {
            return matching_abort_replay(receipt, request, request_digest);
        }
        reject_stage_operation_collision(&self.connection, request.operation_id)?;
        let stage = load_stage(&self.connection, request.stage_id)?;
        if stage.state != 1
            || stage.fence != request.stage_fence
            || stage.expires_at <= request.observed_at
        {
            return Err(StageStoreError::Stale);
        }
        let result_digest = abort_result_digest(request, request_digest);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE stages SET state = 3
             WHERE stage_id = ?1 AND state = 1 AND stage_fence = ?2 AND expires_at > ?3",
            params![
                request.stage_id.as_bytes().as_slice(),
                to_i64(request.stage_fence)?,
                request.observed_at.get(),
            ],
        )?;
        if updated != 1 {
            return Err(StageStoreError::Stale);
        }
        transaction.execute(
            "INSERT INTO stage_abort_operations(
                operation_id, stage_id, request_digest, stage_fence, aborted_at, receipt_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request.operation_id.as_bytes().as_slice(),
                request.stage_id.as_bytes().as_slice(),
                request_digest.as_slice(),
                to_i64(request.stage_fence)?,
                request.observed_at.get(),
                result_digest.as_slice(),
            ],
        )?;
        transaction.commit()?;
        Ok(StageAbortReceipt {
            outcome: StageWriteOutcome::Applied,
            operation_id: request.operation_id,
            stage_id: request.stage_id,
            request_digest,
            stage_fence: request.stage_fence,
            aborted_at: request.observed_at,
            result_digest,
        })
    }

    /// Checks whether a lease transition can proceed without changing durable state.
    ///
    /// The later renewal repeats all checks transactionally. Exact completed retries are valid.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale, expired, shrinking, conflicting or corrupt transitions.
    pub fn preflight_lease(&self, request: StageLeaseRequest) -> Result<(), StageStoreError> {
        validate_lease_request(request)?;
        let request_digest = lease_request_digest(request);
        if let Some(receipt) = load_lease_receipt(&self.connection, request.operation_id)? {
            matching_lease_replay(receipt, request, request_digest)?;
            return Ok(());
        }
        reject_stage_operation_collision(&self.connection, request.operation_id)?;
        let stage = load_stage(&self.connection, request.stage_id)?;
        if request.takeover && request.expected_fence == u64::MAX {
            return Err(StageStoreError::InvalidInput);
        }
        if stage.state != 1
            || stage.fence != request.expected_fence
            || stage.expires_at <= request.observed_at
            || request.lease_expires_at < stage.expires_at
        {
            Err(StageStoreError::Stale)
        } else {
            Ok(())
        }
    }

    /// Reconstructs exact ordered acknowledged bytes for publication without changing stage state.
    ///
    /// # Errors
    ///
    /// Rejects holes unless sparse was explicit, configured excess and every missing/corrupt part.
    pub fn complete_bytes(
        &self,
        stage_id: StageId,
        final_length: u64,
        sparse: bool,
    ) -> Result<BoundedBytes, StageStoreError> {
        let stage = load_stage(&self.connection, stage_id)?;
        if final_length > stage.maximum_bytes {
            return Err(StageStoreError::InvalidInput);
        }
        let writes = load_stage_writes(&self.connection, stage_id)?;
        if !sparse && !covers(&ranges(&writes)?, final_length) {
            return Err(StageStoreError::Incomplete);
        }
        let length = usize::try_from(final_length).map_err(|_| StageStoreError::InvalidInput)?;
        let mut complete = vec![0_u8; length];
        for write in writes {
            apply_part(&self.stages, stage_id, &write, &mut complete)?;
        }
        BoundedBytes::copy_from(&complete, length).map_err(|_| StageStoreError::InvalidInput)
    }

    /// Streams one exact fenced checkpoint through a bounded buffer without allocating file size.
    ///
    /// A private sparse completion image is assembled in journal order, synced, rewound and
    /// independently hashed while it is copied to `destination`. It is never a published file and
    /// is removed after success. A failed destination leaves no metadata publication; its private
    /// temporary image is discarded on exact retry.
    ///
    /// # Errors
    ///
    /// Rejects stale fence/sequence/time, holes without explicit sparse intent, corrupt/missing
    /// parts, range excess and every source/destination filesystem error.
    pub fn stream_complete(
        &mut self,
        request: StageCompletionRequest,
        destination: &mut impl Write,
    ) -> Result<CompletedStage, StageStoreError> {
        self.stream_complete_inner(request, 0, None, destination)
    }

    /// Streams a checkpoint over an exact immutable base-version prefix.
    ///
    /// The base callback must write exactly `min(base_length, final_length)` verified bytes.
    /// Private stage ranges then overwrite that prefix in durable mutation order. Extending past
    /// the base still requires complete staged coverage unless sparse completion was explicit.
    ///
    /// # Errors
    ///
    /// Rejects stale/incomplete stages, a short/excess base stream, corrupt parts and every IO or
    /// callback failure.
    pub fn stream_complete_with_base(
        &mut self,
        request: StageCompletionRequest,
        base_length: u64,
        mut load_base: impl FnMut(&mut dyn Write) -> Result<(), StageStoreError>,
        destination: &mut impl Write,
    ) -> Result<CompletedStage, StageStoreError> {
        self.stream_complete_inner(request, base_length, Some(&mut load_base), destination)
    }

    /// Reads one bounded range from an exact live checkpoint over an immutable base version.
    ///
    /// The base callback receives only the intersecting immutable range. Every staged part is
    /// independently length/digest verified before its overlapping bytes are applied in journal
    /// order. Memory is bounded by [`MAXIMUM_STAGE_READ_BYTES`], never logical file size.
    ///
    /// # Errors
    ///
    /// Rejects stale fences/checkpoints, expired stages, excessive or overflowing ranges, short
    /// base streams, corrupt parts and callback failure.
    pub fn read_range_with_base(
        &self,
        request: StageRangeReadRequest,
        base_length: u64,
        mut load_base: impl FnMut(u64, u64, &mut dyn Write) -> Result<(), StageStoreError>,
    ) -> Result<BoundedBytes, StageStoreError> {
        validate_range_read(request)?;
        let stage = load_stage(&self.connection, request.stage_id)?;
        if stage.state != 1
            || stage.fence != request.stage_fence
            || stage.sequence != request.expected_sequence
            || request.observed_at >= stage.expires_at
        {
            return Err(StageStoreError::Stale);
        }
        let logical_length = base_length.max(stage.logical_extent);
        let available = logical_length.saturating_sub(request.offset);
        let result_length = request.length.min(available);
        let result_size =
            usize::try_from(result_length).map_err(|_| StageStoreError::InvalidInput)?;
        let mut result = vec![0_u8; result_size];
        let base_available = base_length.saturating_sub(request.offset);
        let base_read_length = result_length.min(base_available);
        if base_read_length != 0 {
            let mut destination = std::io::Cursor::new(result.as_mut_slice());
            let mut exact = ExactPrefixWriter::new(&mut destination, base_read_length);
            load_base(request.offset, base_read_length, &mut exact)?;
            exact.finish()?;
        }
        let writes = load_stage_writes(&self.connection, request.stage_id)?;
        for write in &writes {
            apply_part_to_range(&self.stages, write, request.offset, &mut result)?;
        }
        BoundedBytes::copy_from(&result, MAXIMUM_STAGE_READ_BYTES)
            .map_err(|_| StageStoreError::InvalidInput)
    }

    fn stream_complete_inner(
        &mut self,
        request: StageCompletionRequest,
        base_length: u64,
        load_base: Option<&mut BaseLoader<'_>>,
        destination: &mut impl Write,
    ) -> Result<CompletedStage, StageStoreError> {
        let stage = load_stage(&self.connection, request.stage_id)?;
        validate_completion(stage, request)?;
        let writes = load_stage_writes(&self.connection, request.stage_id)?;
        let base_prefix = base_length.min(request.final_length);
        let mut initialised = ranges(&writes)?;
        if base_prefix != 0 {
            insert_range(&mut initialised, 0..base_prefix);
        }
        if !request.sparse && !covers(&initialised, request.final_length) {
            return Err(StageStoreError::Incomplete);
        }
        let directory = self.stages.open_dir(request.stage_id.to_string())?;
        let pending_name = format!("{}.completion.pending", request.operation_id);
        remove_private_file(&directory, &pending_name)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        let mut image = directory.open_with(&pending_name, &options)?;
        image.set_len(request.final_length)?;
        if let Some(load_base) = load_base {
            image.seek(SeekFrom::Start(0))?;
            let mut prefix = ExactPrefixWriter::new(&mut image, base_prefix);
            load_base(&mut prefix)?;
            prefix.finish()?;
        } else if base_prefix != 0 {
            return Err(StageStoreError::InvalidInput);
        }
        for write in &writes {
            apply_part_to_image(&directory, write, request.final_length, &mut image)?;
        }
        image.sync_all()?;
        image.seek(SeekFrom::Start(0))?;
        let content_digest = copy_complete_image(&mut image, request.final_length, destination)?;
        drop(image);
        directory.remove_file(&pending_name)?;
        sync_directory(&directory)?;
        Ok(CompletedStage {
            logical_length: request.final_length,
            content_digest,
        })
    }

    fn record_write(
        &mut self,
        stage_id: StageId,
        stage: StoredStage,
        write: &StageWrite,
        observed_at: UnixMicros,
        part_name: &str,
    ) -> Result<StageWriteOutcome, StageStoreError> {
        let length = u64::try_from(write.bytes.len()).map_err(|_| StageStoreError::InvalidInput)?;
        let extent = write
            .offset
            .checked_add(length)
            .ok_or(StageStoreError::InvalidInput)?;
        let sequence = stage
            .sequence
            .checked_add(1)
            .ok_or(StageStoreError::InvalidInput)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO stage_writes(
                operation_id, stage_id, mutation_sequence, stage_fence, byte_offset,
                byte_length, content_digest, part_name, applied_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                write.operation_id.as_bytes().as_slice(),
                stage_id.as_bytes().as_slice(),
                to_i64(sequence)?,
                to_i64(write.stage_fence)?,
                to_i64(write.offset)?,
                to_i64(length)?,
                write.digest.as_slice(),
                part_name,
                observed_at.get()
            ],
        )?;
        let updated = transaction.execute(
            "UPDATE stages
             SET mutation_sequence = ?1, logical_extent = MAX(logical_extent, ?2)
             WHERE stage_id = ?3 AND state = 1 AND mutation_sequence = ?4",
            params![
                to_i64(sequence)?,
                to_i64(extent)?,
                stage_id.as_bytes().as_slice(),
                to_i64(stage.sequence)?
            ],
        )?;
        if updated != 1 {
            return Err(StageStoreError::Unavailable);
        }
        crate::stage_range_index::merge(&transaction, stage_id, write.offset..extent)?;
        transaction.commit()?;
        Ok(StageWriteOutcome::Applied)
    }
}

#[derive(Clone, Copy)]
struct StoredStage {
    fence: u64,
    maximum_bytes: u64,
    state: u8,
    sequence: u64,
    logical_extent: u64,
    expires_at: UnixMicros,
}

#[derive(Clone)]
struct StoredWrite {
    operation_id: OperationId,
    stage_id: StageId,
    fence: u64,
    offset: u64,
    length: u64,
    digest: [u8; 32],
    part_name: String,
}

struct ExactPrefixWriter<'a, W> {
    destination: &'a mut W,
    remaining: u64,
}

impl<'a, W: Write> ExactPrefixWriter<'a, W> {
    const fn new(destination: &'a mut W, length: u64) -> Self {
        Self {
            destination,
            remaining: length,
        }
    }

    fn finish(self) -> Result<(), StageStoreError> {
        if self.remaining == 0 {
            Ok(())
        } else {
            Err(StageStoreError::Corrupt)
        }
    }
}

impl<W: Write> Write for ExactPrefixWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let length = u64::try_from(bytes.len())
            .map_err(|_| std::io::Error::other("base write length exceeds u64"))?;
        if length > self.remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "base source exceeded requested prefix",
            ));
        }
        let written = self.destination.write(bytes)?;
        self.remaining = self
            .remaining
            .checked_sub(u64::try_from(written).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("base write counter underflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.destination.flush()
    }
}

impl StoredWrite {
    fn matches(&self, write: &StageWrite) -> Result<bool, StageStoreError> {
        Ok(self.fence == write.stage_fence
            && self.offset == write.offset
            && self.length
                == u64::try_from(write.bytes.len()).map_err(|_| StageStoreError::InvalidInput)?
            && self.digest == write.digest)
    }

    fn end(&self) -> Result<u64, StageStoreError> {
        self.offset
            .checked_add(self.length)
            .ok_or(StageStoreError::Corrupt)
    }
}

/// Stable durable-stage failure categories.
#[derive(Debug, Error)]
pub enum StageStoreError {
    /// Input, bounds or time relation is invalid.
    #[error("durable stage input is invalid")]
    InvalidInput,
    /// Stage or operation identity already belongs to different canonical input.
    #[error("durable stage operation conflicts with existing input")]
    OperationConflict,
    /// Stage fence or lifetime no longer authorises mutation.
    #[error("durable stage authority is stale")]
    Stale,
    /// Requested non-sparse completion contains uninitialised ranges.
    #[error("durable stage is incomplete")]
    Incomplete,
    /// Journal or immutable part bytes violate an internal invariant.
    #[error("durable stage state is corrupt")]
    Corrupt,
    /// A concurrent/local persistence transition prevented this operation.
    #[error("durable stage state is unavailable")]
    Unavailable,
    /// Capability-scoped filesystem IO failed.
    #[error("durable stage filesystem operation failed")]
    Io(#[from] std::io::Error),
    /// SQLite persistence failed.
    #[error("durable stage database operation failed")]
    Sqlite(#[from] rusqlite::Error),
}

fn validate_lease_request(request: StageLeaseRequest) -> Result<(), StageStoreError> {
    if request.expected_fence == 0 || request.lease_expires_at <= request.observed_at {
        Err(StageStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_abort_request(request: StageAbortRequest) -> Result<(), StageStoreError> {
    if request.stage_fence == 0 {
        Err(StageStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_range_read(request: StageRangeReadRequest) -> Result<(), StageStoreError> {
    let maximum =
        u64::try_from(MAXIMUM_STAGE_READ_BYTES).map_err(|_| StageStoreError::InvalidInput)?;
    if request.stage_fence == 0
        || request.length > maximum
        || request.offset.checked_add(request.length).is_none()
    {
        Err(StageStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn reject_stage_operation_collision(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<(), StageStoreError> {
    let collision: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM stage_writes WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM stage_lease_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM stage_truncation_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM stage_abort_operations WHERE operation_id = ?1)",
        [operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision == 0 {
        Ok(())
    } else {
        Err(StageStoreError::OperationConflict)
    }
}

fn load_abort_receipt(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<StageAbortReceipt>, StageStoreError> {
    type Stored = (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>);
    let stored: Option<Stored> = connection
        .query_row(
            "SELECT stage_id, request_digest, stage_fence, aborted_at, receipt_digest
             FROM stage_abort_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    stored
        .as_ref()
        .map(|stored| decode_abort_receipt(operation_id, stored))
        .transpose()
}

fn decode_abort_receipt(
    operation_id: OperationId,
    stored: &(Vec<u8>, Vec<u8>, i64, i64, Vec<u8>),
) -> Result<StageAbortReceipt, StageStoreError> {
    let stage_id = stage_identifier(&stored.0)?;
    let request_digest = copy_digest(&stored.1)?;
    let stage_fence = from_i64(stored.2)?;
    let aborted_at = UnixMicros::new(stored.3);
    let result_digest = copy_digest(&stored.4)?;
    let request = StageAbortRequest {
        operation_id,
        stage_id,
        stage_fence,
        observed_at: aborted_at,
    };
    if result_digest != abort_result_digest(request, request_digest) {
        return Err(StageStoreError::Corrupt);
    }
    Ok(StageAbortReceipt {
        outcome: StageWriteOutcome::Replayed,
        operation_id,
        stage_id,
        request_digest,
        stage_fence,
        aborted_at,
        result_digest,
    })
}

fn matching_abort_replay(
    receipt: StageAbortReceipt,
    request: StageAbortRequest,
    request_digest: [u8; 32],
) -> Result<StageAbortReceipt, StageStoreError> {
    if receipt.stage_id == request.stage_id && receipt.request_digest == request_digest {
        Ok(receipt)
    } else {
        Err(StageStoreError::OperationConflict)
    }
}

fn abort_request_digest(request: StageAbortRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.stage-abort-request.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.stage_id.as_bytes());
    digest.update(&request.stage_fence.to_be_bytes());
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn abort_result_digest(request: StageAbortRequest, request_digest: [u8; 32]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.stage-abort-result.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.stage_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&request.stage_fence.to_be_bytes());
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn truncation_request_digest(
    operation_id: OperationId,
    stage_id: StageId,
    stage_fence: u64,
    observed_at: UnixMicros,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.stage.initial-truncation.request.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&stage_id.as_bytes());
    digest.update(&stage_fence.to_be_bytes());
    digest.update(&observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn truncation_receipt_digest(request_digest: [u8; 32], sequence: u64) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.stage.initial-truncation.receipt.v1\0");
    digest.update(&request_digest);
    digest.update(&sequence.to_be_bytes());
    digest.finalize().into()
}

fn load_lease_receipt(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<StageLeaseReceipt>, StageStoreError> {
    type Stored = (Vec<u8>, Vec<u8>, i64, i64, Vec<u8>);
    let stored: Option<Stored> = connection
        .query_row(
            "SELECT stage_id, request_digest, resulting_fence, lease_expires_at,
                    receipt_digest
             FROM stage_lease_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    stored
        .as_ref()
        .map(|stored| decode_lease_receipt(operation_id, stored))
        .transpose()
}

fn decode_lease_receipt(
    operation_id: OperationId,
    stored: &(Vec<u8>, Vec<u8>, i64, i64, Vec<u8>),
) -> Result<StageLeaseReceipt, StageStoreError> {
    let stage_id = stage_identifier(&stored.0)?;
    let request_digest = copy_digest(&stored.1)?;
    let stage_fence = from_i64(stored.2)?;
    let lease_expires_at = UnixMicros::new(stored.3);
    let result_digest = copy_digest(&stored.4)?;
    let expected = lease_result_digest(
        operation_id,
        stage_id,
        request_digest,
        stage_fence,
        lease_expires_at,
    );
    if stage_fence == 0 || result_digest != expected {
        return Err(StageStoreError::Corrupt);
    }
    Ok(StageLeaseReceipt {
        outcome: StageWriteOutcome::Replayed,
        operation_id,
        stage_id,
        request_digest,
        stage_fence,
        lease_expires_at,
        result_digest,
    })
}

fn matching_lease_replay(
    receipt: StageLeaseReceipt,
    request: StageLeaseRequest,
    request_digest: [u8; 32],
) -> Result<StageLeaseReceipt, StageStoreError> {
    if receipt.stage_id == request.stage_id && receipt.request_digest == request_digest {
        Ok(receipt)
    } else {
        Err(StageStoreError::OperationConflict)
    }
}

fn stage_identifier(bytes: &[u8]) -> Result<StageId, StageStoreError> {
    let exact: [u8; 16] = bytes.try_into().map_err(|_| StageStoreError::Corrupt)?;
    StageId::from_bytes(exact).map_err(|_| StageStoreError::Corrupt)
}

fn copy_digest(bytes: &[u8]) -> Result<[u8; 32], StageStoreError> {
    bytes.try_into().map_err(|_| StageStoreError::Corrupt)
}

fn lease_request_digest(request: StageLeaseRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.stage-lease-request.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.stage_id.as_bytes());
    digest.update(&request.expected_fence.to_be_bytes());
    digest.update(&[u8::from(request.takeover)]);
    digest.update(&request.lease_expires_at.get().to_be_bytes());
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn lease_result_digest(
    operation_id: OperationId,
    stage_id: StageId,
    request_digest: [u8; 32],
    stage_fence: u64,
    lease_expires_at: UnixMicros,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.stage-lease-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&stage_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&stage_fence.to_be_bytes());
    digest.update(&lease_expires_at.get().to_be_bytes());
    digest.finalize().into()
}

fn validate_registration(stage: StageRegistration) -> Result<(), StageStoreError> {
    if stage.stage_fence == 0
        || stage.maximum_bytes == 0
        || stage.maximum_bytes > MAXIMUM_SQLITE_INTEGER
        || stage.expires_at <= stage.created_at
    {
        Err(StageStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_live_write(
    stage: StoredStage,
    write: &StageWrite,
    observed_at: UnixMicros,
) -> Result<(), StageStoreError> {
    if stage.state != 1 || stage.fence != write.stage_fence || observed_at >= stage.expires_at {
        return Err(StageStoreError::Stale);
    }
    if write.bytes.is_empty() || blake3::hash(write.bytes.as_slice()).as_bytes() != &write.digest {
        return Err(StageStoreError::InvalidInput);
    }
    let length = u64::try_from(write.bytes.len()).map_err(|_| StageStoreError::InvalidInput)?;
    let end = write
        .offset
        .checked_add(length)
        .ok_or(StageStoreError::InvalidInput)?;
    if end > stage.maximum_bytes {
        Err(StageStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_completion(
    stage: StoredStage,
    request: StageCompletionRequest,
) -> Result<(), StageStoreError> {
    if request.final_length > stage.maximum_bytes {
        return Err(StageStoreError::InvalidInput);
    }
    if stage.state != 1
        || stage.fence != request.stage_fence
        || stage.sequence != request.expected_sequence
        || request.observed_at >= stage.expires_at
    {
        Err(StageStoreError::Stale)
    } else {
        Ok(())
    }
}

fn load_stage(connection: &Connection, stage_id: StageId) -> Result<StoredStage, StageStoreError> {
    let identifier = stage_id.as_bytes();
    let values: (i64, i64, u8, i64, i64, i64) = connection
        .query_row(
            "SELECT stage_fence, maximum_bytes, state, mutation_sequence,
                    logical_extent, expires_at
             FROM stages WHERE stage_id = ?1",
            [identifier.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?
        .ok_or(StageStoreError::Stale)?;
    Ok(StoredStage {
        fence: from_i64(values.0)?,
        maximum_bytes: from_i64(values.1)?,
        state: values.2,
        sequence: from_i64(values.3)?,
        logical_extent: from_i64(values.4)?,
        expires_at: UnixMicros::new(values.5),
    })
}

fn load_write(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<Option<StoredWrite>, StageStoreError> {
    let identifier = operation_id.as_bytes();
    connection
        .query_row(
            "SELECT stage_id, stage_fence, byte_offset,
                    byte_length, content_digest, part_name
             FROM stage_writes WHERE operation_id = ?1",
            [identifier.as_slice()],
            |row| decode_write_row(operation_id, row),
        )
        .optional()
        .map_err(Into::into)
}

fn load_stage_writes(
    connection: &Connection,
    stage_id: StageId,
) -> Result<Vec<StoredWrite>, StageStoreError> {
    let identifier = stage_id.as_bytes();
    let mut statement = connection.prepare(
        "SELECT operation_id, stage_fence, byte_offset,
                byte_length, content_digest, part_name
         FROM stage_writes WHERE stage_id = ?1 ORDER BY mutation_sequence, operation_id",
    )?;
    let rows = statement.query_map([identifier.as_slice()], |row| {
        let operation_id = decode_operation_id(row, 0)?;
        decode_write_columns(operation_id, stage_id, row, 1)
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn decode_write_row(
    operation_id: OperationId,
    row: &rusqlite::Row<'_>,
) -> Result<StoredWrite, rusqlite::Error> {
    let stage: Vec<u8> = row.get(0)?;
    let stage_id = StageId::from_bytes(
        stage
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    decode_write_columns(operation_id, stage_id, row, 1)
}

fn decode_write_columns(
    operation_id: OperationId,
    stage_id: StageId,
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> Result<StoredWrite, rusqlite::Error> {
    let digest: Vec<u8> = row.get(offset + 3)?;
    let stored = StoredWrite {
        operation_id,
        stage_id,
        fence: from_sql_i64(row.get(offset)?)?,
        offset: from_sql_i64(row.get(offset + 1)?)?,
        length: from_sql_i64(row.get(offset + 2)?)?,
        digest: digest
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        part_name: row.get(offset + 4)?,
    };
    if stored.part_name == format!("{}.part", stored.operation_id) {
        Ok(stored)
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

fn decode_operation_id(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> Result<OperationId, rusqlite::Error> {
    let identifier: Vec<u8> = row.get(offset)?;
    OperationId::from_bytes(
        identifier
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn ranges(writes: &[StoredWrite]) -> Result<Vec<Range<u64>>, StageStoreError> {
    let mut ranges = Vec::new();
    for write in writes {
        insert_range(&mut ranges, write.offset..write.end()?);
    }
    Ok(ranges)
}

fn install_part(
    root: &Dir,
    stage_id: StageId,
    write: &StageWrite,
) -> Result<String, StageStoreError> {
    let directory = root.open_dir(stage_id.to_string())?;
    let final_name = format!("{}.part", write.operation_id);
    if let Ok(mut existing) = directory.open(&final_name) {
        verify_open_file(&mut existing, write.bytes.as_slice(), write.digest)?;
        return Ok(final_name);
    }
    let pending_name = format!("{}.pending", write.operation_id);
    match directory.remove_file(&pending_name) {
        Ok(()) => sync_directory(&directory)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut pending = directory.open_with(&pending_name, &options)?;
    pending.write_all(write.bytes.as_slice())?;
    pending.sync_all()?;
    directory.rename(&pending_name, &directory, &final_name)?;
    sync_directory(&directory)?;
    Ok(final_name)
}

fn verify_part(root: &Dir, stored: &StoredWrite, expected: &[u8]) -> Result<(), StageStoreError> {
    let directory = root.open_dir(stored.stage_id.to_string())?;
    let mut file = directory.open(&stored.part_name)?;
    verify_open_file(&mut file, expected, stored.digest)
}

fn verify_open_file(
    file: &mut cap_std::fs::File,
    expected: &[u8],
    digest: [u8; 32],
) -> Result<(), StageStoreError> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes != expected || blake3::hash(&bytes).as_bytes() != &digest {
        Err(StageStoreError::Corrupt)
    } else {
        Ok(())
    }
}

fn apply_part(
    root: &Dir,
    stage_id: StageId,
    stored: &StoredWrite,
    complete: &mut [u8],
) -> Result<(), StageStoreError> {
    let directory = root.open_dir(stage_id.to_string())?;
    let mut file = directory.open(&stored.part_name)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() != usize::try_from(stored.length).map_err(|_| StageStoreError::Corrupt)?
        || blake3::hash(&bytes).as_bytes() != &stored.digest
    {
        return Err(StageStoreError::Corrupt);
    }
    let start = usize::try_from(stored.offset).map_err(|_| StageStoreError::Corrupt)?;
    if start < complete.len() {
        let copied = bytes.len().min(complete.len() - start);
        complete[start..start + copied].copy_from_slice(&bytes[..copied]);
    }
    Ok(())
}

fn apply_part_to_range(
    root: &Dir,
    stored: &StoredWrite,
    range_offset: u64,
    result: &mut [u8],
) -> Result<(), StageStoreError> {
    let directory = root.open_dir(stored.stage_id.to_string())?;
    let mut file = directory.open(&stored.part_name)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() != usize::try_from(stored.length).map_err(|_| StageStoreError::Corrupt)?
        || blake3::hash(&bytes).as_bytes() != &stored.digest
    {
        return Err(StageStoreError::Corrupt);
    }
    let result_length = u64::try_from(result.len()).map_err(|_| StageStoreError::Corrupt)?;
    let range_end = range_offset
        .checked_add(result_length)
        .ok_or(StageStoreError::Corrupt)?;
    let write_end = stored.end()?;
    let overlap_start = range_offset.max(stored.offset);
    let overlap_end = range_end.min(write_end);
    if overlap_start >= overlap_end {
        return Ok(());
    }
    let source_start =
        usize::try_from(overlap_start - stored.offset).map_err(|_| StageStoreError::Corrupt)?;
    let destination_start =
        usize::try_from(overlap_start - range_offset).map_err(|_| StageStoreError::Corrupt)?;
    let length =
        usize::try_from(overlap_end - overlap_start).map_err(|_| StageStoreError::Corrupt)?;
    result[destination_start..destination_start + length]
        .copy_from_slice(&bytes[source_start..source_start + length]);
    Ok(())
}

fn apply_part_to_image(
    directory: &Dir,
    stored: &StoredWrite,
    final_length: u64,
    image: &mut cap_std::fs::File,
) -> Result<(), StageStoreError> {
    let mut source = directory.open(&stored.part_name)?;
    image.seek(SeekFrom::Start(stored.offset.min(final_length)))?;
    let mut digest = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        let read_u64 = u64::try_from(read).map_err(|_| StageStoreError::Corrupt)?;
        let chunk_start = stored
            .offset
            .checked_add(total)
            .ok_or(StageStoreError::Corrupt)?;
        if chunk_start < final_length {
            let writable = usize::try_from((final_length - chunk_start).min(read_u64))
                .map_err(|_| StageStoreError::Corrupt)?;
            image.write_all(&buffer[..writable])?;
        }
        total = total
            .checked_add(read_u64)
            .ok_or(StageStoreError::Corrupt)?;
    }
    if total == stored.length && digest.finalize().as_bytes() == &stored.digest {
        Ok(())
    } else {
        Err(StageStoreError::Corrupt)
    }
}

fn copy_complete_image(
    image: &mut cap_std::fs::File,
    logical_length: u64,
    destination: &mut impl Write,
) -> Result<[u8; 32], StageStoreError> {
    let mut remaining = logical_length;
    let mut digest = blake3::Hasher::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    while remaining != 0 {
        let requested = usize::try_from(remaining.min(COPY_BUFFER_BYTES_U64))
            .map_err(|_| StageStoreError::Corrupt)?;
        let read = image.read(&mut buffer[..requested])?;
        if read == 0 {
            return Err(StageStoreError::Corrupt);
        }
        digest.update(&buffer[..read]);
        destination.write_all(&buffer[..read])?;
        remaining -= u64::try_from(read).map_err(|_| StageStoreError::Corrupt)?;
    }
    Ok(digest.finalize().into())
}

fn remove_private_file(directory: &Dir, name: &str) -> Result<(), StageStoreError> {
    match directory.remove_file(name) {
        Ok(()) => sync_directory(directory).map_err(Into::into),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn create_stage_directory(root: &Dir, stage_id: StageId) -> Result<(), StageStoreError> {
    match root.create_dir(stage_id.to_string()) {
        Ok(()) => sync_directory(root).map_err(Into::into),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn configure(connection: &Connection) -> Result<(), StageStoreError> {
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )?;
    Ok(())
}

fn migrate(connection: &mut Connection, applied_at: UnixMicros) -> Result<(), StageStoreError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'schema_migrations' LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let current: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current > SCHEMA_VERSION || (current == 0 && exists) || (current != 0 && !exists) {
        return Err(StageStoreError::Corrupt);
    }
    for migration in MIGRATIONS {
        let digest: [u8; 32] = blake3::hash(migration.sql.as_bytes()).into();
        if migration.version <= current {
            let stored: Vec<u8> = connection.query_row(
                "SELECT migration_digest FROM schema_migrations WHERE version = ?1",
                [migration.version],
                |row| row.get(0),
            )?;
            if stored.as_slice() != digest {
                return Err(StageStoreError::Corrupt);
            }
            continue;
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, migration_digest, applied_at)
             VALUES (?1, ?2, ?3)",
            params![migration.version, digest.as_slice(), applied_at.get()],
        )?;
        transaction.pragma_update(None, "user_version", migration.version)?;
        transaction.commit()?;
    }
    Ok(())
}

fn verify_database(connection: &Connection) -> Result<(), StageStoreError> {
    let quick: String = connection.pragma_query_value(None, "quick_check", |row| row.get(0))?;
    let foreign_key_violation = connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some();
    if quick == "ok" && !foreign_key_violation {
        Ok(())
    } else {
        Err(StageStoreError::Corrupt)
    }
}

fn sync_directory(directory: &Dir) -> Result<(), std::io::Error> {
    directory.open(".")?.into_std().sync_all()
}

fn to_i64(value: u64) -> Result<i64, StageStoreError> {
    i64::try_from(value).map_err(|_| StageStoreError::InvalidInput)
}

fn from_i64(value: i64) -> Result<u64, StageStoreError> {
    u64::try_from(value).map_err(|_| StageStoreError::Corrupt)
}

fn from_sql_i64(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use meshspan_contracts::BoundedBytes;
    use meshspan_domain::{OperationId, StageId, UnixMicros};
    use rusqlite::{Connection, params};
    use tempfile::tempdir;

    use super::{
        CompletedStage, DATABASE_FILE, DurableStageStore, MAXIMUM_STAGE_READ_BYTES, MIGRATIONS,
        SCHEMA_VERSION, STAGE_DIRECTORY, StageAbortRequest, StageCompletionRequest,
        StageLeaseRequest, StageRangePageRequest, StageRangeReadRequest, StageRegistration,
        StageStoreError, configure, install_part,
    };
    use crate::{StageWrite, StageWriteOutcome};

    #[test]
    fn version_one_stage_database_migrates_to_current_schema()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let connection = Connection::open(directory.path().join(DATABASE_FILE))?;
        configure(&connection)?;
        connection.execute_batch(MIGRATIONS[0].sql)?;
        let digest: [u8; 32] = blake3::hash(MIGRATIONS[0].sql.as_bytes()).into();
        connection.execute(
            "INSERT INTO schema_migrations(version, migration_digest, applied_at)
             VALUES (1, ?1, 1)",
            params![digest.as_slice()],
        )?;
        connection.pragma_update(None, "user_version", 1)?;
        drop(connection);

        let store = DurableStageStore::open(directory.path(), UnixMicros::new(2))?;
        let version: u32 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        assert_eq!(version, SCHEMA_VERSION);
        let lease_table: i64 = store.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type = 'table' AND name = 'stage_lease_operations'
             )",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(lease_table, 1);
        let truncation_table: i64 = store.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type = 'table' AND name = 'stage_truncation_operations'
             )",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(truncation_table, 1);
        Ok(())
    }

    #[test]
    fn range_index_migration_backfills_legacy_write_coverage()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([91; 16])?;
        let connection = Connection::open(directory.path().join(DATABASE_FILE))?;
        configure(&connection)?;
        for migration in &MIGRATIONS[..4] {
            connection.execute_batch(migration.sql)?;
            let digest: [u8; 32] = blake3::hash(migration.sql.as_bytes()).into();
            connection.execute(
                "INSERT INTO schema_migrations(version, migration_digest, applied_at)
                 VALUES (?1, ?2, 1)",
                params![migration.version, digest.as_slice()],
            )?;
            connection.pragma_update(None, "user_version", migration.version)?;
        }
        connection.execute(
            "INSERT INTO stages(
                stage_id, stage_fence, maximum_bytes, state, mutation_sequence,
                logical_extent, created_at, expires_at
             ) VALUES (?1, 1, 100, 1, 4, 6, 1, 100)",
            [stage_id.as_bytes().as_slice()],
        )?;
        for (sequence, offset) in [(1_i64, 0_i64), (2, 2), (3, 1), (4, 5)] {
            let operation = OperationId::from_bytes([u8::try_from(sequence)?; 16])?;
            connection.execute(
                "INSERT INTO stage_writes(
                    operation_id, stage_id, mutation_sequence, stage_fence, byte_offset,
                    byte_length, content_digest, part_name, applied_at
                 ) VALUES (?1, ?2, ?3, 1, ?4, 1, ?5, ?6, 2)",
                params![
                    operation.as_bytes().as_slice(),
                    stage_id.as_bytes().as_slice(),
                    sequence,
                    offset,
                    [0_u8; 32].as_slice(),
                    format!("{operation}.part")
                ],
            )?;
        }
        drop(connection);

        let store = DurableStageStore::open(directory.path(), UnixMicros::new(2))?;
        let page = store.range_page(StageRangePageRequest {
            stage_id,
            expected_sequence: Some(4),
            after_start: None,
            limit: 8,
        })?;
        assert_eq!(page.ranges, vec![0..3, 5..6]);
        assert_eq!(page.next_after_start, None);
        Ok(())
    }

    #[test]
    fn abort_is_durable_idempotent_and_permanently_fences_private_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([101; 16])?;
        let operation_id = OperationId::from_bytes([102; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration(stage_id, 7, 100))?;
        store.write(stage_id, &write(103, 7, 0, b"private")?, UnixMicros::new(2))?;
        let request = StageAbortRequest {
            operation_id,
            stage_id,
            stage_fence: 7,
            observed_at: UnixMicros::new(3),
        };
        let applied = store.abort(request)?;
        assert_eq!(applied.outcome, StageWriteOutcome::Applied);
        assert_eq!(store.abort(request)?.outcome, StageWriteOutcome::Replayed);
        assert!(matches!(
            store.write(stage_id, &write(104, 7, 7, b"hidden")?, UnixMicros::new(4)),
            Err(StageStoreError::Stale)
        ));
        assert!(matches!(
            store.stream_complete(
                StageCompletionRequest {
                    operation_id: OperationId::from_bytes([105; 16])?,
                    stage_id,
                    stage_fence: 7,
                    expected_sequence: 1,
                    final_length: 7,
                    sparse: false,
                    observed_at: UnixMicros::new(4),
                },
                &mut Vec::new(),
            ),
            Err(StageStoreError::Stale)
        ));
        drop(store);

        let mut reopened = DurableStageStore::open(directory.path(), UnixMicros::new(5))?;
        assert_eq!(
            reopened.abort(request)?.outcome,
            StageWriteOutcome::Replayed
        );
        let conflict = StageAbortRequest {
            stage_id: StageId::from_bytes([106; 16])?,
            ..request
        };
        assert!(matches!(
            reopened.abort(conflict),
            Err(StageStoreError::OperationConflict)
        ));
        Ok(())
    }

    #[test]
    fn initial_truncation_is_one_replayable_empty_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([3; 16])?;
        let operation_id = OperationId::from_bytes([4; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration(stage_id, 1, 100))?;
        assert_eq!(
            store.initialise_truncation(stage_id, operation_id, 1, UnixMicros::new(2))?,
            StageWriteOutcome::Applied
        );
        assert_eq!(store.checkpoint(stage_id)?.sequence, 1);
        drop(store);

        let mut reopened = DurableStageStore::open(directory.path(), UnixMicros::new(3))?;
        assert_eq!(
            reopened.initialise_truncation(stage_id, operation_id, 1, UnixMicros::new(2))?,
            StageWriteOutcome::Replayed
        );
        assert!(matches!(
            reopened.initialise_truncation(stage_id, operation_id, 1, UnixMicros::new(3)),
            Err(StageStoreError::OperationConflict)
        ));
        reopened.connection.execute(
            "UPDATE stage_truncation_operations SET receipt_digest = zeroblob(32)
             WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
        )?;
        assert!(matches!(
            reopened.initialise_truncation(stage_id, operation_id, 1, UnixMicros::new(2)),
            Err(StageStoreError::Corrupt)
        ));
        Ok(())
    }

    #[test]
    fn lease_takeover_fences_old_writes_and_replays_after_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([90; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration(stage_id, 1, 100))?;
        let takeover = StageLeaseRequest {
            operation_id: OperationId::from_bytes([91; 16])?,
            stage_id,
            expected_fence: 1,
            takeover: true,
            lease_expires_at: UnixMicros::new(200),
            observed_at: UnixMicros::new(20),
        };
        let applied = store.renew_lease(takeover)?;
        assert_eq!(applied.outcome, StageWriteOutcome::Applied);
        assert_eq!(applied.stage_fence, 2);
        assert!(matches!(
            store.write(stage_id, &write(92, 1, 0, b"old")?, UnixMicros::new(30)),
            Err(StageStoreError::Stale)
        ));
        assert_eq!(
            store.write(stage_id, &write(93, 2, 0, b"new")?, UnixMicros::new(30))?,
            StageWriteOutcome::Applied
        );
        drop(store);

        let mut reopened = DurableStageStore::open(directory.path(), UnixMicros::new(2))?;
        let replayed = reopened.renew_lease(takeover)?;
        assert_eq!(replayed.outcome, StageWriteOutcome::Replayed);
        assert_eq!(replayed.result_digest, applied.result_digest);
        let mut changed = takeover;
        changed.lease_expires_at = UnixMicros::new(201);
        assert!(matches!(
            reopened.renew_lease(changed),
            Err(StageStoreError::OperationConflict)
        ));
        Ok(())
    }

    #[test]
    fn lease_cannot_shrink_or_reuse_a_write_operation() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([94; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration(stage_id, 1, 100))?;
        let staged = write(95, 1, 0, b"data")?;
        store.write(stage_id, &staged, UnixMicros::new(10))?;
        let request = StageLeaseRequest {
            operation_id: staged.operation_id,
            stage_id,
            expected_fence: 1,
            takeover: false,
            lease_expires_at: UnixMicros::new(99),
            observed_at: UnixMicros::new(20),
        };
        assert!(matches!(
            store.renew_lease(request),
            Err(StageStoreError::OperationConflict)
        ));
        let distinct = StageLeaseRequest {
            operation_id: OperationId::from_bytes([96; 16])?,
            ..request
        };
        assert!(matches!(
            store.renew_lease(distinct),
            Err(StageStoreError::Stale)
        ));
        Ok(())
    }

    #[test]
    fn completion_overlays_verified_base_and_requires_new_extension_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([97; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration(stage_id, 1, 100))?;
        store.write(stage_id, &write(98, 1, 5, b"X")?, UnixMicros::new(10))?;
        let request = StageCompletionRequest {
            operation_id: OperationId::from_bytes([99; 16])?,
            stage_id,
            stage_fence: 1,
            expected_sequence: 1,
            final_length: 10,
            sparse: false,
            observed_at: UnixMicros::new(20),
        };
        let mut output = Vec::new();
        store.stream_complete_with_base(
            request,
            10,
            |destination| destination.write_all(b"abcdefghij").map_err(Into::into),
            &mut output,
        )?;
        assert_eq!(output, b"abcdeXghij");

        let mut extended = request;
        extended.operation_id = OperationId::from_bytes([100; 16])?;
        extended.final_length = 12;
        let result = store.stream_complete_with_base(
            extended,
            10,
            |destination| destination.write_all(b"abcdefghij").map_err(Into::into),
            &mut Vec::new(),
        );
        assert!(matches!(result, Err(StageStoreError::Incomplete)));
        store.write(stage_id, &write(101, 1, 10, b"KL")?, UnixMicros::new(21))?;
        extended.expected_sequence = 2;
        let mut extended_output = Vec::new();
        store.stream_complete_with_base(
            extended,
            10,
            |destination| destination.write_all(b"abcdefghij").map_err(Into::into),
            &mut extended_output,
        )?;
        assert_eq!(extended_output, b"abcdeXghijKL");
        Ok(())
    }

    #[test]
    fn restart_replays_parts_and_reconstructs_acknowledged_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([1; 16])?;
        let registration = registration(stage_id, 3, 100);
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration)?;
        let suffix = write(2, 3, 5, b"world")?;
        assert_eq!(
            store.write(stage_id, &suffix, UnixMicros::new(2))?,
            StageWriteOutcome::Applied
        );
        store.write(stage_id, &write(3, 3, 0, b"hello")?, UnixMicros::new(3))?;
        drop(store);

        let mut reopened = DurableStageStore::open(directory.path(), UnixMicros::new(4))?;
        reopened.register(registration)?;
        assert_eq!(
            reopened.write(stage_id, &suffix, UnixMicros::new(5))?,
            StageWriteOutcome::Replayed
        );
        assert_eq!(
            reopened.complete_bytes(stage_id, 10, false)?.as_slice(),
            b"helloworld"
        );
        assert_eq!(
            reopened.checkpoint(stage_id)?.initialised_ranges,
            vec![0..10]
        );
        Ok(())
    }

    #[test]
    fn holes_expiry_and_corrupt_parts_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([4; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration(stage_id, 5, 10))?;
        store.write(stage_id, &write(6, 5, 4, b"part")?, UnixMicros::new(2))?;
        assert!(matches!(
            store.complete_bytes(stage_id, 8, false),
            Err(StageStoreError::Incomplete)
        ));
        assert_eq!(
            store.complete_bytes(stage_id, 8, true)?.as_slice(),
            b"\0\0\0\0part"
        );
        assert!(matches!(
            store.write(stage_id, &write(7, 5, 0, b"late")?, UnixMicros::new(10)),
            Err(StageStoreError::Stale)
        ));
        std::fs::write(
            directory
                .path()
                .join("stages")
                .join(stage_id.to_string())
                .join(format!("{}.part", OperationId::from_bytes([6; 16])?)),
            b"evil",
        )?;
        assert!(matches!(
            store.complete_bytes(stage_id, 8, true),
            Err(StageStoreError::Corrupt)
        ));
        Ok(())
    }

    #[test]
    fn crash_after_part_sync_before_journal_recovers_exactly_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([8; 16])?;
        let registration = registration(stage_id, 9, 100);
        let staged_write = write(10, 9, 0, b"durable")?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration)?;

        std::fs::remove_dir(directory.path().join("stages").join(stage_id.to_string()))?;
        drop(store);

        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(2))?;
        store.register(registration)?;

        install_part(&store.stages, stage_id, &staged_write)?;
        drop(store);

        let mut reopened = DurableStageStore::open(directory.path(), UnixMicros::new(3))?;
        reopened.register(registration)?;
        assert_eq!(
            reopened.write(stage_id, &staged_write, UnixMicros::new(4))?,
            StageWriteOutcome::Applied
        );
        assert_eq!(
            reopened.write(stage_id, &staged_write, UnixMicros::new(5))?,
            StageWriteOutcome::Replayed
        );
        assert_eq!(
            reopened.complete_bytes(stage_id, 7, false)?.as_slice(),
            b"durable"
        );
        Ok(())
    }

    #[test]
    fn streaming_completion_is_fenced_exact_and_retryable_after_sink_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([11; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration(stage_id, 12, 100))?;
        store.write(stage_id, &write(13, 12, 5, b"world")?, UnixMicros::new(2))?;
        store.write(stage_id, &write(14, 12, 0, b"hello")?, UnixMicros::new(3))?;
        let request = StageCompletionRequest {
            operation_id: OperationId::from_bytes([15; 16])?,
            stage_id,
            stage_fence: 12,
            expected_sequence: 2,
            final_length: 10,
            sparse: false,
            observed_at: UnixMicros::new(4),
        };
        let mut failing = FailingWriter;
        assert!(matches!(
            store.stream_complete(request, &mut failing),
            Err(StageStoreError::Io(_))
        ));
        let mut completed = Vec::new();
        assert_eq!(
            store.stream_complete(request, &mut completed)?,
            CompletedStage {
                logical_length: 10,
                content_digest: blake3::hash(b"helloworld").into(),
            }
        );
        assert_eq!(completed, b"helloworld");
        let stale = StageCompletionRequest {
            expected_sequence: 1,
            ..request
        };
        assert!(matches!(
            store.stream_complete(stale, &mut Vec::new()),
            Err(StageStoreError::Stale)
        ));
        Ok(())
    }

    #[test]
    fn sparse_completion_streams_large_logical_extent_in_bounded_chunks()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([16; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(StageRegistration {
            stage_id,
            stage_fence: 17,
            maximum_bytes: 2 * 1_024 * 1_024,
            created_at: UnixMicros::new(1),
            expires_at: UnixMicros::new(100),
        })?;
        store.write(
            stage_id,
            &write(18, 17, 1_048_575, b"x")?,
            UnixMicros::new(2),
        )?;
        let mut counter = CountingWriter::default();
        let completed = store.stream_complete(
            StageCompletionRequest {
                operation_id: OperationId::from_bytes([19; 16])?,
                stage_id,
                stage_fence: 17,
                expected_sequence: 1,
                final_length: 1_048_576,
                sparse: true,
                observed_at: UnixMicros::new(3),
            },
            &mut counter,
        )?;
        assert_eq!(completed.logical_length, 1_048_576);
        assert_eq!(counter.written, 1_048_576);
        assert!(counter.maximum_write <= 64 * 1_024);
        Ok(())
    }

    #[test]
    fn streaming_completion_accepts_an_empty_checkpoint() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([20; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration(stage_id, 21, 100))?;
        let mut completed_bytes = Vec::new();
        let completed = store.stream_complete(
            StageCompletionRequest {
                operation_id: OperationId::from_bytes([22; 16])?,
                stage_id,
                stage_fence: 21,
                expected_sequence: 0,
                final_length: 0,
                sparse: false,
                observed_at: UnixMicros::new(2),
            },
            &mut completed_bytes,
        )?;
        assert_eq!(completed.logical_length, 0);
        assert_eq!(completed.content_digest, *blake3::hash(&[]).as_bytes());
        assert!(completed_bytes.is_empty());
        Ok(())
    }

    #[test]
    fn bounded_range_read_overlays_one_checkpoint_and_returns_short_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let stage_id = StageId::from_bytes([91; 16])?;
        let mut store = DurableStageStore::open(directory.path(), UnixMicros::new(1))?;
        store.register(registration(stage_id, 1, 100))?;
        store.write(stage_id, &write(92, 1, 2, b"ZZ")?, UnixMicros::new(2))?;
        let base = b"initial";

        let result = store.read_range_with_base(
            StageRangeReadRequest {
                stage_id,
                stage_fence: 1,
                expected_sequence: 1,
                offset: 1,
                length: 5,
                observed_at: UnixMicros::new(3),
            },
            7,
            |offset, length, destination| write_base_range(base, offset, length, destination),
        )?;
        assert_eq!(result.as_slice(), b"nZZia");

        let eof = store.read_range_with_base(
            StageRangeReadRequest {
                stage_id,
                stage_fence: 1,
                expected_sequence: 1,
                offset: 6,
                length: 10,
                observed_at: UnixMicros::new(3),
            },
            7,
            |offset, length, destination| write_base_range(base, offset, length, destination),
        )?;
        assert_eq!(eof.as_slice(), b"l");

        store.write(stage_id, &write(93, 1, 10, b"X")?, UnixMicros::new(4))?;
        let extension = store.read_range_with_base(
            StageRangeReadRequest {
                stage_id,
                stage_fence: 1,
                expected_sequence: 2,
                offset: 7,
                length: 4,
                observed_at: UnixMicros::new(5),
            },
            7,
            |offset, length, destination| write_base_range(base, offset, length, destination),
        )?;
        assert_eq!(extension.as_slice(), &[0, 0, 0, b'X']);
        let excessive = u64::try_from(MAXIMUM_STAGE_READ_BYTES)?.saturating_add(1);
        assert!(matches!(
            store.read_range_with_base(
                StageRangeReadRequest {
                    stage_id,
                    stage_fence: 1,
                    expected_sequence: 2,
                    offset: 0,
                    length: excessive,
                    observed_at: UnixMicros::new(5),
                },
                7,
                |_, _, _| Ok(()),
            ),
            Err(StageStoreError::InvalidInput)
        ));
        std::fs::write(
            directory
                .path()
                .join(STAGE_DIRECTORY)
                .join(stage_id.to_string())
                .join(format!("{}.part", OperationId::from_bytes([92; 16])?)),
            b"forged",
        )?;
        assert!(matches!(
            store.read_range_with_base(
                StageRangeReadRequest {
                    stage_id,
                    stage_fence: 1,
                    expected_sequence: 2,
                    offset: 0,
                    length: 4,
                    observed_at: UnixMicros::new(5),
                },
                7,
                |offset, length, destination| {
                    write_base_range(base, offset, length, destination)
                },
            ),
            Err(StageStoreError::Corrupt)
        ));
        Ok(())
    }

    fn write_base_range(
        base: &[u8],
        offset: u64,
        length: u64,
        destination: &mut dyn Write,
    ) -> Result<(), StageStoreError> {
        let start = usize::try_from(offset).map_err(|_| StageStoreError::InvalidInput)?;
        let end = usize::try_from(offset + length).map_err(|_| StageStoreError::InvalidInput)?;
        destination.write_all(&base[start..end])?;
        Ok(())
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected destination failure",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct CountingWriter {
        written: usize,
        maximum_write: usize,
    }

    impl Write for CountingWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.written = self.written.saturating_add(buffer.len());
            self.maximum_write = self.maximum_write.max(buffer.len());
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn registration(stage_id: StageId, fence: u64, expiry: i64) -> StageRegistration {
        StageRegistration {
            stage_id,
            stage_fence: fence,
            maximum_bytes: 64,
            created_at: UnixMicros::new(1),
            expires_at: UnixMicros::new(expiry),
        }
    }

    fn write(
        operation: u8,
        fence: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<StageWrite, Box<dyn std::error::Error>> {
        Ok(StageWrite {
            operation_id: OperationId::from_bytes([operation; 16])?,
            stage_fence: fence,
            offset,
            bytes: BoundedBytes::copy_from(bytes, 64)?,
            digest: blake3::hash(bytes).into(),
        })
    }
}
