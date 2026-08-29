// SPDX-License-Identifier: GPL-2.0-only

//! Opaque continuation for one stable relationship-grant authority page.

use meshspan_domain::{FederationGrantId, FederationRelationshipId, Revision};
use thiserror::Error;

const DOMAIN: &[u8] = b"meshspan.federation.grant-cursor";
const FORMAT_VERSION: u8 = 1;
const CHECKSUM_BYTES: usize = 32;

/// Invalid or unsupported opaque grant continuation.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FederationGrantCursorError {
    /// The continuation is truncated, excessive, corrupt or semantically inconsistent.
    #[error("federation grant cursor is invalid")]
    Invalid,
    /// The continuation uses a format this implementation does not understand.
    #[error("federation grant cursor format is unsupported")]
    UnsupportedVersion,
}

/// Stable continuation bound to one relationship, revision window and last emitted grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationGrantCursor {
    relationship_id: FederationRelationshipId,
    after_revision: Revision,
    snapshot_revision: Revision,
    record_revision: Revision,
    grant_id: FederationGrantId,
}

impl FederationGrantCursor {
    pub(super) fn new(
        relationship_id: FederationRelationshipId,
        after_revision: Revision,
        snapshot_revision: Revision,
        record_revision: Revision,
        grant_id: FederationGrantId,
    ) -> Result<Self, FederationGrantCursorError> {
        let cursor = Self {
            relationship_id,
            after_revision,
            snapshot_revision,
            record_revision,
            grant_id,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    /// Encodes the opaque continuation with deterministic corruption detection.
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DOMAIN.len().saturating_add(98));
        bytes.extend_from_slice(DOMAIN);
        bytes.push(0);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&self.relationship_id.as_bytes());
        bytes.extend_from_slice(&self.after_revision.get().to_be_bytes());
        bytes.extend_from_slice(&self.snapshot_revision.get().to_be_bytes());
        bytes.extend_from_slice(&self.record_revision.get().to_be_bytes());
        bytes.extend_from_slice(&self.grant_id.as_bytes());
        let checksum = blake3::hash(&bytes);
        bytes.extend_from_slice(checksum.as_bytes());
        bytes
    }

    /// Decodes an opaque continuation without trusting its fields or checksum.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, corruption, trailing bytes and impossible revision windows.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, FederationGrantCursorError> {
        let payload_length = bytes
            .len()
            .checked_sub(CHECKSUM_BYTES)
            .ok_or(FederationGrantCursorError::Invalid)?;
        let (payload, checksum) = bytes.split_at(payload_length);
        if blake3::hash(payload).as_bytes() != checksum {
            return Err(FederationGrantCursorError::Invalid);
        }
        let mut decoder = Decoder::new(payload);
        decoder.expect(DOMAIN)?;
        if decoder.byte()? != 0 {
            return Err(FederationGrantCursorError::Invalid);
        }
        if decoder.byte()? != FORMAT_VERSION {
            return Err(FederationGrantCursorError::UnsupportedVersion);
        }
        let relationship_id = FederationRelationshipId::from_bytes(decoder.array()?)
            .map_err(|_| FederationGrantCursorError::Invalid)?;
        let after_revision = Revision::new(decoder.unsigned()?);
        let snapshot_revision = Revision::new(decoder.unsigned()?);
        let record_revision = Revision::new(decoder.unsigned()?);
        let grant_id = FederationGrantId::from_bytes(decoder.array()?)
            .map_err(|_| FederationGrantCursorError::Invalid)?;
        decoder.finish()?;
        Self::new(
            relationship_id,
            after_revision,
            snapshot_revision,
            record_revision,
            grant_id,
        )
    }

    /// Returns the relationship whose page produced this continuation.
    #[must_use]
    pub const fn relationship_id(self) -> FederationRelationshipId {
        self.relationship_id
    }

    /// Returns the caller's exclusive revision floor bound into this continuation.
    #[must_use]
    pub const fn after_revision(self) -> Revision {
        self.after_revision
    }

    /// Returns the exact stable metadata snapshot bound into this continuation.
    #[must_use]
    pub const fn snapshot_revision(self) -> Revision {
        self.snapshot_revision
    }

    /// Returns the last grant revision emitted by the preceding page.
    #[must_use]
    pub const fn record_revision(self) -> Revision {
        self.record_revision
    }

    /// Returns the last stable grant identity emitted by the preceding page.
    #[must_use]
    pub const fn grant_id(self) -> FederationGrantId {
        self.grant_id
    }

    fn validate(self) -> Result<(), FederationGrantCursorError> {
        if self.snapshot_revision.get() == 0
            || self.record_revision <= self.after_revision
            || self.record_revision > self.snapshot_revision
        {
            Err(FederationGrantCursorError::Invalid)
        } else {
            Ok(())
        }
    }
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), FederationGrantCursorError> {
        if self.bytes(expected.len())? == expected {
            Ok(())
        } else {
            Err(FederationGrantCursorError::Invalid)
        }
    }

    fn byte(&mut self) -> Result<u8, FederationGrantCursorError> {
        Ok(self.array::<1>()?[0])
    }

    fn unsigned(&mut self) -> Result<u64, FederationGrantCursorError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], FederationGrantCursorError> {
        self.bytes(LENGTH)?
            .try_into()
            .map_err(|_| FederationGrantCursorError::Invalid)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], FederationGrantCursorError> {
        if self.remaining.len() < length {
            return Err(FederationGrantCursorError::Invalid);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn finish(self) -> Result<(), FederationGrantCursorError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(FederationGrantCursorError::Invalid)
        }
    }
}
