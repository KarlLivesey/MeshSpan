// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, resumable and independently verified snapshot staging.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use meshspan_protocol::v1::{LogPosition, SnapshotBegin, SnapshotChunk, SnapshotFinish};
use sha2::{Digest, Sha256};

use crate::TransportError;

const DIGEST_BYTES: usize = 32;
const IDENTIFIER_BYTES: usize = 16;
const HASH_BUFFER_BYTES: usize = 64 * 1_024;

/// A closed snapshot whose exact staged bytes match the independently validated manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSnapshot {
    /// Caller-owned staging file containing the exact verified bytes.
    pub staging_path: PathBuf,
    /// Stable snapshot identity.
    pub snapshot_id: [u8; IDENTIFIER_BYTES],
    /// Last applied log position contained in the image.
    pub included_position: LogPosition,
    /// State-machine revision contained in the image.
    pub state_revision: u64,
    /// Snapshot image format.
    pub format_version: u32,
    /// Membership epoch represented by the image.
    pub membership_epoch: u64,
    /// Exact staged image length.
    pub total_bytes: u64,
    /// SHA-256 of the complete staged image.
    pub digest: [u8; DIGEST_BYTES],
}

/// Mutable receiver for one sequential snapshot transfer.
pub struct SnapshotStager {
    file: File,
    staging_path: PathBuf,
    snapshot_id: [u8; IDENTIFIER_BYTES],
    included_position: LogPosition,
    state_revision: u64,
    format_version: u32,
    membership_epoch: u64,
    total_bytes: u64,
    expected_digest: [u8; DIGEST_BYTES],
    received_bytes: u64,
    digest: Sha256,
    maximum_chunk_bytes: usize,
}

impl SnapshotStager {
    /// Creates a new staging file for one validated manifest.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities, positions, bounds and an existing destination.
    pub fn begin(
        staging_path: &Path,
        begin: &SnapshotBegin,
        maximum_snapshot_bytes: u64,
        maximum_chunk_bytes: usize,
    ) -> Result<Self, TransportError> {
        let manifest = StagingManifest::parse(begin, maximum_snapshot_bytes)?;
        if maximum_chunk_bytes == 0 {
            return Err(TransportError::InvalidConfiguration);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(staging_path)
            .map_err(TransportError::Io)?;
        Ok(Self::from_parts(
            file,
            staging_path,
            manifest,
            maximum_chunk_bytes,
            0,
            Sha256::new(),
        ))
    }

    /// Resumes a prior staged prefix after rehashing every existing byte.
    ///
    /// # Errors
    ///
    /// Rejects a missing/non-file stage, an oversized prefix or malformed manifest.
    pub fn resume(
        staging_path: &Path,
        begin: &SnapshotBegin,
        maximum_snapshot_bytes: u64,
        maximum_chunk_bytes: usize,
    ) -> Result<Self, TransportError> {
        let manifest = StagingManifest::parse(begin, maximum_snapshot_bytes)?;
        if maximum_chunk_bytes == 0 {
            return Err(TransportError::InvalidConfiguration);
        }
        let metadata = std::fs::symlink_metadata(staging_path).map_err(TransportError::Io)?;
        if !metadata.file_type().is_file() || metadata.len() > manifest.total_bytes {
            return Err(TransportError::SnapshotRejected);
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(staging_path)
            .map_err(TransportError::Io)?;
        let (received_bytes, digest) = hash_prefix(&mut file, manifest.total_bytes)?;
        file.seek(SeekFrom::End(0)).map_err(TransportError::Io)?;
        Ok(Self::from_parts(
            file,
            staging_path,
            manifest,
            maximum_chunk_bytes,
            received_bytes,
            digest,
        ))
    }

    /// Returns the next exact offset the sender may write.
    #[must_use]
    pub const fn received_bytes(&self) -> u64 {
        self.received_bytes
    }

    /// Verifies and durably appends one exact next chunk.
    ///
    /// # Errors
    ///
    /// Rejects wrong identity/offset, empty or excessive chunks, overflow and digest mismatch.
    pub fn append_chunk(&mut self, chunk: &SnapshotChunk) -> Result<(), TransportError> {
        if chunk.snapshot_id.as_slice() != self.snapshot_id
            || chunk.offset != self.received_bytes
            || chunk.bytes.is_empty()
            || chunk.bytes.len() > self.maximum_chunk_bytes
            || chunk.chunk_digest.len() != DIGEST_BYTES
            || Sha256::digest(&chunk.bytes).as_slice() != chunk.chunk_digest
        {
            return Err(TransportError::SnapshotRejected);
        }
        let next_received = self
            .received_bytes
            .checked_add(
                u64::try_from(chunk.bytes.len()).map_err(|_| TransportError::SnapshotRejected)?,
            )
            .ok_or(TransportError::SnapshotRejected)?;
        if next_received > self.total_bytes {
            return Err(TransportError::SnapshotRejected);
        }
        self.file
            .write_all(&chunk.bytes)
            .map_err(TransportError::Io)?;
        self.file.sync_data().map_err(TransportError::Io)?;
        self.digest.update(&chunk.bytes);
        self.received_bytes = next_received;
        Ok(())
    }

    /// Closes and yields a verified image only when finish and begin agree with all received bytes.
    ///
    /// # Errors
    ///
    /// Rejects incomplete, substituted or corrupt image bytes.
    pub fn finish(self, finish: &SnapshotFinish) -> Result<VerifiedSnapshot, TransportError> {
        if finish.snapshot_id.as_slice() != self.snapshot_id
            || finish.total_bytes != self.total_bytes
            || finish.digest.as_slice() != self.expected_digest
            || self.received_bytes != self.total_bytes
        {
            return Err(TransportError::SnapshotRejected);
        }
        let actual_digest: [u8; DIGEST_BYTES] = self.digest.finalize().into();
        if actual_digest != self.expected_digest {
            return Err(TransportError::SnapshotRejected);
        }
        self.file.sync_all().map_err(TransportError::Io)?;
        Ok(VerifiedSnapshot {
            staging_path: self.staging_path,
            snapshot_id: self.snapshot_id,
            included_position: self.included_position,
            state_revision: self.state_revision,
            format_version: self.format_version,
            membership_epoch: self.membership_epoch,
            total_bytes: self.total_bytes,
            digest: actual_digest,
        })
    }

    fn from_parts(
        file: File,
        staging_path: &Path,
        manifest: StagingManifest,
        maximum_chunk_bytes: usize,
        received_bytes: u64,
        digest: Sha256,
    ) -> Self {
        Self {
            file,
            staging_path: staging_path.to_path_buf(),
            snapshot_id: manifest.snapshot_id,
            included_position: manifest.included_position,
            state_revision: manifest.state_revision,
            format_version: manifest.format_version,
            membership_epoch: manifest.membership_epoch,
            total_bytes: manifest.total_bytes,
            expected_digest: manifest.digest,
            received_bytes,
            digest,
            maximum_chunk_bytes,
        }
    }
}

#[derive(Clone, Copy)]
struct StagingManifest {
    snapshot_id: [u8; IDENTIFIER_BYTES],
    included_position: LogPosition,
    state_revision: u64,
    format_version: u32,
    membership_epoch: u64,
    total_bytes: u64,
    digest: [u8; DIGEST_BYTES],
}

impl StagingManifest {
    fn parse(begin: &SnapshotBegin, maximum_snapshot_bytes: u64) -> Result<Self, TransportError> {
        let snapshot_id = exact_bytes(&begin.snapshot_id)?;
        let digest = exact_bytes(&begin.digest)?;
        let included_position = begin
            .included_position
            .ok_or(TransportError::SnapshotRejected)?;
        if included_position.term == 0
            || included_position.index == 0
            || begin.state_revision == 0
            || begin.format_version == 0
            || begin.membership_epoch == 0
            || begin.total_bytes == 0
            || begin.total_bytes > maximum_snapshot_bytes
        {
            return Err(TransportError::SnapshotRejected);
        }
        Ok(Self {
            snapshot_id,
            included_position,
            state_revision: begin.state_revision,
            format_version: begin.format_version,
            membership_epoch: begin.membership_epoch,
            total_bytes: begin.total_bytes,
            digest,
        })
    }
}

fn exact_bytes<const SIZE: usize>(bytes: &[u8]) -> Result<[u8; SIZE], TransportError> {
    bytes
        .try_into()
        .map_err(|_| TransportError::SnapshotRejected)
}

fn hash_prefix(file: &mut File, maximum_bytes: u64) -> Result<(u64, Sha256), TransportError> {
    file.seek(SeekFrom::Start(0)).map_err(TransportError::Io)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES].into_boxed_slice();
    let mut length = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(TransportError::Io)?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(read).map_err(|_| TransportError::SnapshotRejected)?)
            .ok_or(TransportError::SnapshotRejected)?;
        if length > maximum_bytes {
            return Err(TransportError::SnapshotRejected);
        }
        digest.update(&buffer[..read]);
    }
    Ok((length, digest))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn snapshot_transfer_resumes_and_verifies_exact_bytes() -> Result<(), Box<dyn std::error::Error>>
    {
        let file_path = staging_path();
        let bytes = b"authoritative snapshot bytes";
        let begin = begin(bytes);
        let first = &bytes[..10];
        let second = &bytes[10..];
        let mut stager = SnapshotStager::begin(&file_path, &begin, 1_024, 16)?;
        stager.append_chunk(&chunk(0, first))?;
        drop(stager);

        let mut resumed = SnapshotStager::resume(&file_path, &begin, 1_024, 32)?;
        assert_eq!(resumed.received_bytes(), 10);
        resumed.append_chunk(&chunk(10, second))?;
        let verified = resumed.finish(&finish(bytes))?;
        assert_eq!(verified.total_bytes, u64::try_from(bytes.len())?);
        assert_eq!(std::fs::read(&file_path)?, bytes);
        std::fs::remove_file(file_path)?;
        Ok(())
    }

    #[test]
    fn corrupt_reordered_and_excessive_chunks_do_not_advance_stage()
    -> Result<(), Box<dyn std::error::Error>> {
        let file_path = staging_path();
        let bytes = b"bounded snapshot";
        let begin = begin(bytes);
        let mut stager = SnapshotStager::begin(&file_path, &begin, 1_024, 8)?;
        let mut corrupt = chunk(0, &bytes[..8]);
        corrupt.chunk_digest = vec![9; DIGEST_BYTES];
        assert!(matches!(
            stager.append_chunk(&corrupt),
            Err(TransportError::SnapshotRejected)
        ));
        assert!(matches!(
            stager.append_chunk(&chunk(1, &bytes[..8])),
            Err(TransportError::SnapshotRejected)
        ));
        assert!(matches!(
            stager.append_chunk(&chunk(0, &bytes[..9])),
            Err(TransportError::SnapshotRejected)
        ));
        assert_eq!(stager.received_bytes(), 0);
        drop(stager);
        assert!(std::fs::read(&file_path)?.is_empty());
        std::fs::remove_file(file_path)?;
        Ok(())
    }

    fn begin(bytes: &[u8]) -> SnapshotBegin {
        SnapshotBegin {
            snapshot_id: vec![1; IDENTIFIER_BYTES],
            included_position: Some(LogPosition { term: 3, index: 9 }),
            state_revision: 8,
            total_bytes: u64::try_from(bytes.len()).unwrap_or(0),
            digest: Sha256::digest(bytes).to_vec(),
            format_version: 1,
            membership_epoch: 4,
        }
    }

    fn chunk(offset: u64, bytes: &[u8]) -> SnapshotChunk {
        SnapshotChunk {
            snapshot_id: vec![1; IDENTIFIER_BYTES],
            offset,
            bytes: bytes.to_vec(),
            chunk_digest: Sha256::digest(bytes).to_vec(),
        }
    }

    fn finish(bytes: &[u8]) -> SnapshotFinish {
        SnapshotFinish {
            snapshot_id: vec![1; IDENTIFIER_BYTES],
            total_bytes: u64::try_from(bytes.len()).unwrap_or(0),
            digest: Sha256::digest(bytes).to_vec(),
        }
    }

    fn staging_path() -> PathBuf {
        let suffix = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "meshspan-snapshot-{}-{suffix}.stage",
            std::process::id()
        ))
    }
}
