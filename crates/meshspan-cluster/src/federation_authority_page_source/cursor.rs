// SPDX-License-Identifier: GPL-2.0-only

//! Opaque continuation for a relationship snapshot followed by its complete grant stream.

use meshspan_domain::{FederationRelationshipId, Revision};
use meshspan_metadata::FederationGrantCursor;
use sha2::{Digest, Sha256};
use thiserror::Error;

const DOMAIN: &[u8] = b"meshspan.federation.authority-cursor";
const FORMAT_VERSION: u8 = 1;
const CHECKSUM_BYTES: usize = 32;
const MAXIMUM_INNER_CURSOR_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(super) enum FederationAuthorityCursorError {
    #[error("federation authority cursor is invalid")]
    Invalid,
    #[error("federation authority cursor format is unsupported")]
    UnsupportedVersion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FederationAuthorityCursor {
    relationship_id: FederationRelationshipId,
    after_revision: Revision,
    snapshot_revision: Revision,
    grant_cursor: Option<FederationGrantCursor>,
}

impl FederationAuthorityCursor {
    pub(super) fn new(
        relationship_id: FederationRelationshipId,
        after_revision: Revision,
        snapshot_revision: Revision,
        grant_cursor: Option<FederationGrantCursor>,
    ) -> Result<Self, FederationAuthorityCursorError> {
        let cursor = Self {
            relationship_id,
            after_revision,
            snapshot_revision,
            grant_cursor,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    pub(super) fn canonical_bytes(self) -> Result<Vec<u8>, FederationAuthorityCursorError> {
        let inner = self
            .grant_cursor
            .map(FederationGrantCursor::canonical_bytes)
            .unwrap_or_default();
        let mut bytes = Vec::with_capacity(DOMAIN.len().saturating_add(76 + inner.len()));
        bytes.extend_from_slice(DOMAIN);
        bytes.push(0);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&self.relationship_id.as_bytes());
        bytes.extend_from_slice(&self.after_revision.get().to_be_bytes());
        bytes.extend_from_slice(&self.snapshot_revision.get().to_be_bytes());
        let inner_length =
            u16::try_from(inner.len()).map_err(|_| FederationAuthorityCursorError::Invalid)?;
        bytes.extend_from_slice(&inner_length.to_be_bytes());
        bytes.extend_from_slice(&inner);
        let checksum = Sha256::digest(&bytes);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    pub(super) fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, FederationAuthorityCursorError> {
        let payload_length = bytes
            .len()
            .checked_sub(CHECKSUM_BYTES)
            .ok_or(FederationAuthorityCursorError::Invalid)?;
        let (payload, checksum) = bytes.split_at(payload_length);
        if Sha256::digest(payload).as_slice() != checksum {
            return Err(FederationAuthorityCursorError::Invalid);
        }
        let mut decoder = Decoder::new(payload);
        decoder.expect(DOMAIN)?;
        if decoder.byte()? != 0 {
            return Err(FederationAuthorityCursorError::Invalid);
        }
        if decoder.byte()? != FORMAT_VERSION {
            return Err(FederationAuthorityCursorError::UnsupportedVersion);
        }
        let relationship_id = FederationRelationshipId::from_bytes(decoder.array()?)
            .map_err(|_| FederationAuthorityCursorError::Invalid)?;
        let after_revision = Revision::new(decoder.unsigned()?);
        let snapshot_revision = Revision::new(decoder.unsigned()?);
        let inner_length = usize::from(decoder.short()?);
        if inner_length > MAXIMUM_INNER_CURSOR_BYTES {
            return Err(FederationAuthorityCursorError::Invalid);
        }
        let grant_cursor = if inner_length == 0 {
            None
        } else {
            Some(
                FederationGrantCursor::from_canonical_bytes(decoder.bytes(inner_length)?)
                    .map_err(|_| FederationAuthorityCursorError::Invalid)?,
            )
        };
        decoder.finish()?;
        Self::new(
            relationship_id,
            after_revision,
            snapshot_revision,
            grant_cursor,
        )
    }

    pub(super) const fn relationship_id(self) -> FederationRelationshipId {
        self.relationship_id
    }

    pub(super) const fn after_revision(self) -> Revision {
        self.after_revision
    }

    pub(super) const fn snapshot_revision(self) -> Revision {
        self.snapshot_revision
    }

    pub(super) const fn grant_cursor(self) -> Option<FederationGrantCursor> {
        self.grant_cursor
    }

    fn validate(self) -> Result<(), FederationAuthorityCursorError> {
        if self.snapshot_revision.get() == 0 || self.after_revision >= self.snapshot_revision {
            return Err(FederationAuthorityCursorError::Invalid);
        }
        if self.grant_cursor.is_some_and(|cursor| {
            cursor.relationship_id() != self.relationship_id
                || cursor.after_revision() != self.after_revision
                || cursor.snapshot_revision() != self.snapshot_revision
        }) {
            Err(FederationAuthorityCursorError::Invalid)
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

    fn expect(&mut self, expected: &[u8]) -> Result<(), FederationAuthorityCursorError> {
        if self.bytes(expected.len())? == expected {
            Ok(())
        } else {
            Err(FederationAuthorityCursorError::Invalid)
        }
    }

    fn byte(&mut self) -> Result<u8, FederationAuthorityCursorError> {
        Ok(self.array::<1>()?[0])
    }

    fn short(&mut self) -> Result<u16, FederationAuthorityCursorError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn unsigned(&mut self) -> Result<u64, FederationAuthorityCursorError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn array<const LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; LENGTH], FederationAuthorityCursorError> {
        self.bytes(LENGTH)?
            .try_into()
            .map_err(|_| FederationAuthorityCursorError::Invalid)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], FederationAuthorityCursorError> {
        if self.remaining.len() < length {
            return Err(FederationAuthorityCursorError::Invalid);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn finish(self) -> Result<(), FederationAuthorityCursorError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(FederationAuthorityCursorError::Invalid)
        }
    }
}
