// SPDX-License-Identifier: GPL-2.0-only

//! Canonical content-addressed bodies referenced by federated history pages.

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, ObjectId, ObjectRevisionId, OperationId,
    PrincipalId, UnixMicros, VolumeId,
};

use super::super::digest::object_revision as object_revision_digest;
use super::super::repository::ObjectRevisionInsert;
use super::super::transfer::TransferredFileVersion;
use super::NamespaceHistoryRecordError;
use crate::{DirectoryNodeDigest, DirectoryNodeRecord, ManifestPublication};

const DOMAIN: &[u8] = b"meshspan.filesystem.history-object\0";
const FORMAT_VERSION: u8 = 1;
const MAXIMUM_RECORD_BYTES: usize = 2 * 1_024 * 1_024;
const MAXIMUM_DIRECTORY_NODE_BYTES: usize = 300 * 1_024;
const MAXIMUM_SQLITE_INTEGER: u64 = i64::MAX as u64;

/// Immutable filesystem record kind carried behind one content identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceHistoryImmutableKind {
    /// Content-addressed directory trie node.
    DirectoryNode,
    /// Immutable content manifest root.
    Manifest,
    /// Immutable logical file version.
    FileVersion,
    /// Immutable namespace object revision.
    ObjectRevision,
}

/// One independently validated immutable object body for bounded data transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryImmutableRecord {
    kind: NamespaceHistoryImmutableKind,
    canonical_bytes: Vec<u8>,
    digest: [u8; 32],
}

impl NamespaceHistoryImmutableRecord {
    /// Revalidates untrusted bytes and requires the exact identity signed into a branch page.
    ///
    /// # Errors
    ///
    /// Rejects content substitution even when the substituted body is independently well formed.
    pub fn from_expected_digest(
        expected_digest: [u8; 32],
        canonical_bytes: Vec<u8>,
    ) -> Result<Self, NamespaceHistoryRecordError> {
        let record = Self::from_canonical_bytes(canonical_bytes)?;
        if record.digest == expected_digest {
            Ok(record)
        } else {
            Err(NamespaceHistoryRecordError::Invalid)
        }
    }

    /// Revalidates untrusted canonical bytes and derives their stable transfer identity.
    ///
    /// # Errors
    ///
    /// Rejects excessive, truncated, trailing, non-canonical or inconsistent object records.
    pub fn from_canonical_bytes(
        canonical_bytes: Vec<u8>,
    ) -> Result<Self, NamespaceHistoryRecordError> {
        let decoded = decode(&canonical_bytes)?;
        Ok(Self::new(decoded.kind(), canonical_bytes))
    }

    /// Typed object category used for bounded routing and receiver accounting.
    #[must_use]
    pub const fn kind(&self) -> NamespaceHistoryImmutableKind {
        self.kind
    }

    /// Exact domain-separated bytes transferred over a bounded data stream.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// BLAKE3 identity referenced from a signed branch page.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the validated manifest carried by this record, or `None` for another object kind.
    ///
    /// # Errors
    ///
    /// Rejects any in-memory record whose canonical bytes no longer decode exactly.
    pub fn as_manifest(&self) -> Result<Option<ManifestPublication>, NamespaceHistoryRecordError> {
        match self.decoded()? {
            Decoded::Manifest(manifest) => Ok(Some(manifest)),
            Decoded::DirectoryNode(_) | Decoded::FileVersion(_) | Decoded::ObjectRevision(_) => {
                Ok(None)
            }
        }
    }

    pub(in crate::publication) fn directory(
        record: &DirectoryNodeRecord,
    ) -> Result<Self, NamespaceHistoryRecordError> {
        let mut bytes = header(NamespaceHistoryImmutableKind::DirectoryNode);
        bytes.extend_from_slice(&record.digest().as_bytes());
        variable(&mut bytes, &record.encode())?;
        checked_record(NamespaceHistoryImmutableKind::DirectoryNode, bytes)
    }

    pub(in crate::publication) fn manifest(
        record: ManifestPublication,
    ) -> Result<Self, NamespaceHistoryRecordError> {
        validate_manifest(record)?;
        let mut bytes = header(NamespaceHistoryImmutableKind::Manifest);
        identifier(&mut bytes, record.manifest_id.as_bytes());
        bytes.extend_from_slice(&record.format_version.to_be_bytes());
        bytes.extend_from_slice(&record.logical_length.to_be_bytes());
        bytes.extend_from_slice(&record.content_digest);
        bytes.extend_from_slice(&record.root_digest);
        checked_record(NamespaceHistoryImmutableKind::Manifest, bytes)
    }

    pub(in crate::publication) fn file_version(
        record: TransferredFileVersion,
    ) -> Result<Self, NamespaceHistoryRecordError> {
        validate_file_version(record)?;
        let mut bytes = header(NamespaceHistoryImmutableKind::FileVersion);
        identifier(&mut bytes, record.version_id.as_bytes());
        identifier(&mut bytes, record.branch_id.as_bytes());
        identifier(&mut bytes, record.volume_id.as_bytes());
        identifier(&mut bytes, record.object_id.as_bytes());
        optional_identifier(&mut bytes, record.parent_version_id);
        identifier(&mut bytes, record.manifest_id.as_bytes());
        bytes.extend_from_slice(&record.logical_length.to_be_bytes());
        bytes.extend_from_slice(&record.content_digest);
        identifier(&mut bytes, record.created_by.as_bytes());
        bytes.extend_from_slice(&record.created_at.get().to_be_bytes());
        identifier(&mut bytes, record.operation_id.as_bytes());
        checked_record(NamespaceHistoryImmutableKind::FileVersion, bytes)
    }

    pub(in crate::publication) fn object_revision(
        record: ObjectRevisionInsert,
    ) -> Result<Self, NamespaceHistoryRecordError> {
        validate_revision_shape(record)?;
        let mut bytes = header(NamespaceHistoryImmutableKind::ObjectRevision);
        identifier(&mut bytes, record.revision_id.as_bytes());
        identifier(&mut bytes, record.volume_id.as_bytes());
        identifier(&mut bytes, record.object_id.as_bytes());
        bytes.push(record.kind);
        optional_identifier(&mut bytes, record.prior_revision_id);
        optional_digest(
            &mut bytes,
            record.directory_root.map(DirectoryNodeDigest::as_bytes),
        );
        optional_identifier(&mut bytes, record.file_version_id);
        identifier(&mut bytes, record.created_by.as_bytes());
        bytes.extend_from_slice(&record.created_at.get().to_be_bytes());
        bytes.extend_from_slice(&object_revision_digest(&record));
        checked_record(NamespaceHistoryImmutableKind::ObjectRevision, bytes)
    }

    fn new(kind: NamespaceHistoryImmutableKind, canonical_bytes: Vec<u8>) -> Self {
        Self {
            kind,
            digest: blake3::hash(&canonical_bytes).into(),
            canonical_bytes,
        }
    }

    pub(in crate::publication) fn decoded(&self) -> Result<Decoded, NamespaceHistoryRecordError> {
        decode(&self.canonical_bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::publication) enum Decoded {
    DirectoryNode(DirectoryNodeRecord),
    Manifest(ManifestPublication),
    FileVersion(TransferredFileVersion),
    ObjectRevision(ObjectRevisionInsert),
}

impl Decoded {
    const fn kind(&self) -> NamespaceHistoryImmutableKind {
        match self {
            Self::DirectoryNode(_) => NamespaceHistoryImmutableKind::DirectoryNode,
            Self::Manifest(_) => NamespaceHistoryImmutableKind::Manifest,
            Self::FileVersion(_) => NamespaceHistoryImmutableKind::FileVersion,
            Self::ObjectRevision(_) => NamespaceHistoryImmutableKind::ObjectRevision,
        }
    }
}

fn decode(bytes: &[u8]) -> Result<Decoded, NamespaceHistoryRecordError> {
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        return Err(NamespaceHistoryRecordError::BoundsExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    decoder.expect(DOMAIN)?;
    if decoder.byte()? != FORMAT_VERSION {
        return Err(NamespaceHistoryRecordError::Invalid);
    }
    let record = match decoder.byte()? {
        1 => decode_directory(&mut decoder).map(Decoded::DirectoryNode),
        2 => decode_manifest(&mut decoder).map(Decoded::Manifest),
        3 => decode_file_version(&mut decoder).map(Decoded::FileVersion),
        4 => decode_object_revision(&mut decoder).map(Decoded::ObjectRevision),
        _ => Err(NamespaceHistoryRecordError::Invalid),
    }?;
    decoder.finish()?;
    Ok(record)
}

fn decode_directory(
    decoder: &mut Decoder<'_>,
) -> Result<DirectoryNodeRecord, NamespaceHistoryRecordError> {
    let digest = DirectoryNodeDigest::from_bytes(decoder.digest()?);
    DirectoryNodeRecord::decode(digest, decoder.variable(MAXIMUM_DIRECTORY_NODE_BYTES)?)
        .map_err(|_| NamespaceHistoryRecordError::Invalid)
}

fn decode_manifest(
    decoder: &mut Decoder<'_>,
) -> Result<ManifestPublication, NamespaceHistoryRecordError> {
    let record = ManifestPublication {
        manifest_id: decoder.identifier(ContentManifestId::from_bytes)?,
        format_version: decoder.short()?,
        logical_length: decoder.unsigned()?,
        content_digest: decoder.digest()?,
        root_digest: decoder.digest()?,
    };
    validate_manifest(record)?;
    Ok(record)
}

fn decode_file_version(
    decoder: &mut Decoder<'_>,
) -> Result<TransferredFileVersion, NamespaceHistoryRecordError> {
    let record = TransferredFileVersion {
        version_id: decoder.identifier(FileVersionId::from_bytes)?,
        branch_id: decoder.identifier(BranchId::from_bytes)?,
        volume_id: decoder.identifier(VolumeId::from_bytes)?,
        object_id: decoder.identifier(ObjectId::from_bytes)?,
        parent_version_id: decoder.optional_identifier(FileVersionId::from_bytes)?,
        manifest_id: decoder.identifier(ContentManifestId::from_bytes)?,
        logical_length: decoder.unsigned()?,
        content_digest: decoder.digest()?,
        created_by: decoder.identifier(PrincipalId::from_bytes)?,
        created_at: UnixMicros::new(decoder.signed()?),
        operation_id: decoder.identifier(OperationId::from_bytes)?,
    };
    validate_file_version(record)?;
    Ok(record)
}

fn decode_object_revision(
    decoder: &mut Decoder<'_>,
) -> Result<ObjectRevisionInsert, NamespaceHistoryRecordError> {
    let record = ObjectRevisionInsert {
        revision_id: decoder.identifier(ObjectRevisionId::from_bytes)?,
        volume_id: decoder.identifier(VolumeId::from_bytes)?,
        object_id: decoder.identifier(ObjectId::from_bytes)?,
        kind: decoder.byte()?,
        prior_revision_id: decoder.optional_identifier(ObjectRevisionId::from_bytes)?,
        directory_root: decoder
            .optional_digest()?
            .map(DirectoryNodeDigest::from_bytes),
        file_version_id: decoder.optional_identifier(FileVersionId::from_bytes)?,
        created_by: decoder.identifier(PrincipalId::from_bytes)?,
        created_at: UnixMicros::new(decoder.signed()?),
    };
    let expected_digest = decoder.digest()?;
    validate_revision_shape(record)?;
    if object_revision_digest(&record) == expected_digest {
        Ok(record)
    } else {
        Err(NamespaceHistoryRecordError::Invalid)
    }
}

fn validate_revision_shape(
    record: ObjectRevisionInsert,
) -> Result<(), NamespaceHistoryRecordError> {
    let valid = match record.kind {
        1 => record.directory_root.is_some() && record.file_version_id.is_none(),
        2 => record.directory_root.is_none() && record.file_version_id.is_some(),
        _ => false,
    };
    if valid && record.prior_revision_id != Some(record.revision_id) {
        Ok(())
    } else {
        Err(NamespaceHistoryRecordError::Invalid)
    }
}

fn validate_manifest(record: ManifestPublication) -> Result<(), NamespaceHistoryRecordError> {
    if record.format_version == 0 || record.logical_length > MAXIMUM_SQLITE_INTEGER {
        Err(NamespaceHistoryRecordError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_file_version(
    record: TransferredFileVersion,
) -> Result<(), NamespaceHistoryRecordError> {
    if record.logical_length > MAXIMUM_SQLITE_INTEGER
        || record.parent_version_id == Some(record.version_id)
    {
        Err(NamespaceHistoryRecordError::Invalid)
    } else {
        Ok(())
    }
}

fn checked_record(
    kind: NamespaceHistoryImmutableKind,
    bytes: Vec<u8>,
) -> Result<NamespaceHistoryImmutableRecord, NamespaceHistoryRecordError> {
    if bytes.len() > MAXIMUM_RECORD_BYTES {
        Err(NamespaceHistoryRecordError::BoundsExceeded)
    } else {
        Ok(NamespaceHistoryImmutableRecord::new(kind, bytes))
    }
}

fn header(kind: NamespaceHistoryImmutableKind) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(DOMAIN);
    bytes.push(FORMAT_VERSION);
    bytes.push(match kind {
        NamespaceHistoryImmutableKind::DirectoryNode => 1,
        NamespaceHistoryImmutableKind::Manifest => 2,
        NamespaceHistoryImmutableKind::FileVersion => 3,
        NamespaceHistoryImmutableKind::ObjectRevision => 4,
    });
    bytes
}

fn variable(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), NamespaceHistoryRecordError> {
    let length =
        u32::try_from(value.len()).map_err(|_| NamespaceHistoryRecordError::BoundsExceeded)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn identifier(bytes: &mut Vec<u8>, value: [u8; 16]) {
    bytes.extend_from_slice(&value);
}

fn optional_identifier<T>(bytes: &mut Vec<u8>, value: Option<T>)
where
    T: Copy + IntoIdentifier,
{
    match value {
        Some(value) => {
            bytes.push(1);
            identifier(bytes, value.identifier());
        }
        None => bytes.push(0),
    }
}

trait IntoIdentifier {
    fn identifier(self) -> [u8; 16];
}

impl IntoIdentifier for FileVersionId {
    fn identifier(self) -> [u8; 16] {
        self.as_bytes()
    }
}

impl IntoIdentifier for ObjectRevisionId {
    fn identifier(self) -> [u8; 16] {
        self.as_bytes()
    }
}

fn optional_digest(bytes: &mut Vec<u8>, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value);
        }
        None => bytes.push(0),
    }
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    fn expect(&mut self, expected: &[u8]) -> Result<(), NamespaceHistoryRecordError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(NamespaceHistoryRecordError::Invalid)
        }
    }
    fn byte(&mut self) -> Result<u8, NamespaceHistoryRecordError> {
        Ok(self.take(1)?[0])
    }
    fn short(&mut self) -> Result<u16, NamespaceHistoryRecordError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn unsigned(&mut self) -> Result<u64, NamespaceHistoryRecordError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn signed(&mut self) -> Result<i64, NamespaceHistoryRecordError> {
        Ok(i64::from_be_bytes(self.array()?))
    }
    fn digest(&mut self) -> Result<[u8; 32], NamespaceHistoryRecordError> {
        self.array()
    }
    fn identifier<T, E>(
        &mut self,
        constructor: impl FnOnce([u8; 16]) -> Result<T, E>,
    ) -> Result<T, NamespaceHistoryRecordError> {
        constructor(self.array()?).map_err(|_| NamespaceHistoryRecordError::Invalid)
    }
    fn optional_identifier<T, E>(
        &mut self,
        constructor: impl FnOnce([u8; 16]) -> Result<T, E>,
    ) -> Result<Option<T>, NamespaceHistoryRecordError> {
        match self.byte()? {
            0 => Ok(None),
            1 => self.identifier(constructor).map(Some),
            _ => Err(NamespaceHistoryRecordError::Invalid),
        }
    }
    fn optional_digest(&mut self) -> Result<Option<[u8; 32]>, NamespaceHistoryRecordError> {
        match self.byte()? {
            0 => Ok(None),
            1 => self.digest().map(Some),
            _ => Err(NamespaceHistoryRecordError::Invalid),
        }
    }
    fn variable(&mut self, maximum: usize) -> Result<&'a [u8], NamespaceHistoryRecordError> {
        let length = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| NamespaceHistoryRecordError::BoundsExceeded)?;
        if length > maximum {
            return Err(NamespaceHistoryRecordError::BoundsExceeded);
        }
        self.take(length)
    }
    fn array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], NamespaceHistoryRecordError> {
        self.take(LENGTH)?
            .try_into()
            .map_err(|_| NamespaceHistoryRecordError::Invalid)
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], NamespaceHistoryRecordError> {
        if length > self.remaining.len() {
            return Err(NamespaceHistoryRecordError::Invalid);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }
    fn finish(self) -> Result<(), NamespaceHistoryRecordError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(NamespaceHistoryRecordError::Invalid)
        }
    }
}
