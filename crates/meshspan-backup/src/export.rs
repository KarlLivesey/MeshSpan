// SPDX-License-Identifier: GPL-2.0-only

//! Bounded export of an exact encrypted object without possessing its recovery key.

use std::io::{self, Write};

use meshspan_contracts::{BackupReadReceipt, BackupReadRequest};
use sha2::{Digest, Sha256};

const FRAME_BYTES: usize = 64 * 1024;

/// Counts and hashes provider bytes independently, withholding the final frame until verified.
///
/// The caller must obtain `request` from current authorised catalogue evidence and recheck
/// authority before calling `finish`. Failed verification never emits the declared complete
/// byte length, including when a provider lies in its receipt. `flush` deliberately
/// does not release the withheld frame. This is encrypted-byte verification, not restore proof.
pub struct VerifiedBackupExport<W> {
    sink: W,
    evidence: BackupExportEvidence,
    received: u64,
    hash: Sha256,
    pending: Vec<u8>,
    failed: bool,
    published: bool,
}

/// Exact transfer identity bound by the caller to an authorised encrypted container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupExportEvidence {
    /// Unique read operation.
    pub operation_id: meshspan_domain::OperationId,
    /// Complete encrypted-container length.
    pub byte_length: u64,
    /// SHA-256 of the complete encrypted container.
    pub digest: [u8; 32],
}

impl<W: Write> VerifiedBackupExport<W> {
    /// Binds an export to validated provider-read evidence and a streaming sink.
    ///
    /// # Errors
    /// Rejects invalid object identity, deadline, version or missing revision.
    pub fn new(
        sink: W,
        request: &BackupReadRequest,
        now: meshspan_domain::UnixMicros,
    ) -> Result<Self, meshspan_contracts::ContractError> {
        meshspan_contracts::validate_backup_read_request(request, now)?;
        Self::from_evidence(
            sink,
            BackupExportEvidence {
                operation_id: request.context.operation_id,
                byte_length: request.object.byte_length,
                digest: request.object.digest,
            },
        )
    }

    /// Binds an authorised export without imposing any provider location.
    ///
    /// # Errors
    /// Rejects empty or missing encrypted-byte evidence.
    pub fn from_evidence(
        sink: W,
        evidence: BackupExportEvidence,
    ) -> Result<Self, meshspan_contracts::ContractError> {
        if evidence.byte_length == 0 || evidence.digest == [0; 32] {
            return Err(meshspan_contracts::ContractError::InvalidInput);
        }
        Ok(Self {
            sink,
            evidence,
            received: 0,
            hash: Sha256::new(),
            pending: Vec::with_capacity(FRAME_BYTES),
            failed: false,
            published: false,
        })
    }

    /// Releases the final frame only after independent byte verification and an exact receipt.
    ///
    /// # Errors
    /// Rejects short/corrupt bytes, substituted receipts and sink failures.
    pub fn finish(mut self, receipt: BackupReadReceipt) -> io::Result<W> {
        let digest: [u8; 32] = self.hash.finalize().into();
        if self.failed
            || self.received != self.evidence.byte_length
            || digest != self.evidence.digest
            || receipt.operation_id != self.evidence.operation_id
            || receipt.byte_length != self.received
            || receipt.digest != digest
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encrypted backup export verification failed",
            ));
        }
        self.sink.write_all(&self.pending)?;
        self.sink.flush()?;
        Ok(self.sink)
    }
    /// Whether another identical catalogue-bound copy may safely replace this source.
    /// No sink write may have been attempted and no sink validation may have failed.
    #[must_use]
    pub const fn can_restart(&self) -> bool {
        !self.published && !self.failed
    }

    /// Discards an unpublished prefix before another copy of the same exact bytes is tried.
    ///
    /// # Errors
    /// Refuses once any sink write was attempted or any write failed.
    pub fn restart(&mut self) -> io::Result<()> {
        if !self.can_restart() {
            return Err(invalid_length());
        }
        self.received = 0;
        self.hash = Sha256::new();
        self.pending.clear();
        Ok(())
    }

    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let offered = u64::try_from(bytes.len()).map_err(|_| invalid_length())?;
        if offered > self.evidence.byte_length.saturating_sub(self.received) {
            return Err(invalid_length());
        }
        if self.pending.len() == FRAME_BYTES {
            self.published = true;
            self.sink.write_all(&self.pending)?;
            self.pending.clear();
        }
        let count = bytes.len().min(FRAME_BYTES - self.pending.len());
        let accepted = bytes.get(..count).ok_or_else(invalid_length)?;
        self.pending.extend_from_slice(accepted);
        self.hash.update(accepted);
        self.received = self
            .received
            .checked_add(u64::try_from(count).map_err(|_| invalid_length())?)
            .ok_or_else(invalid_length)?;
        Ok(count)
    }
}

impl<W: Write> Write for VerifiedBackupExport<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(invalid_length());
        }
        let result = self.write_frame(bytes);
        self.failed |= result.is_err();
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn invalid_length() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "encrypted backup export length is invalid",
    )
}
