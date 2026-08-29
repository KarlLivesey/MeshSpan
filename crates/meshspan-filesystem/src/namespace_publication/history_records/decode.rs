// SPDX-License-Identifier: GPL-2.0-only

//! Bounded decoder and semantic verifier for canonical mutation commit records.

use meshspan_domain::{
    BranchId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId,
    PrincipalId, UnixMicros, VolumeId,
};

use super::super::repository::{StoredCommit, stored_commit_digest};
use super::super::transfer::TransferredMutationCommit;
use super::{
    COMMIT_DOMAIN, COMMIT_FORMAT_VERSION, MAXIMUM_COMMIT_RECORD_BYTES, NamespaceHistoryRecordError,
};
use crate::{
    BranchMutation, BranchMutationIntent, BranchRenameIntent, DirectoryRevisionTransition,
    NamespaceLimits, NamespacePath, ReconciliationCommit, ReconciliationCommitPayload,
};

const MAXIMUM_PATH_COMPONENTS: usize = 1_024;
const MAXIMUM_TRANSITIONS: usize = 1_024;
const MAXIMUM_COMPONENT_BYTES: usize = 16 * 1_024;

pub(super) fn decode_commit(
    bytes: &[u8],
) -> Result<TransferredMutationCommit, NamespaceHistoryRecordError> {
    if bytes.len() > MAXIMUM_COMMIT_RECORD_BYTES {
        return Err(NamespaceHistoryRecordError::BoundsExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    decoder.expect(COMMIT_DOMAIN)?;
    if decoder.byte()? != COMMIT_FORMAT_VERSION {
        return Err(NamespaceHistoryRecordError::Invalid);
    }
    let commit_id = decoder.identifier(NamespaceCommitId::from_bytes)?;
    let branch_id = decoder.identifier(BranchId::from_bytes)?;
    let volume_id = decoder.identifier(VolumeId::from_bytes)?;
    let root_object_id = decoder.identifier(ObjectId::from_bytes)?;
    let root_object_revision_id = decoder.identifier(ObjectRevisionId::from_bytes)?;
    let parents = decode_parents(&mut decoder)?;
    let operation_id = decoder.identifier(OperationId::from_bytes)?;
    let request_digest = decoder.digest()?;
    if decoder.byte()? != 1 {
        return Err(NamespaceHistoryRecordError::Invalid);
    }
    let intent_digest = decoder.digest()?;
    let created_by = decoder.identifier(PrincipalId::from_bytes)?;
    let created_at = UnixMicros::new(decoder.signed()?);
    let commit_digest = decoder.digest()?;
    let intent = decode_intent(&mut decoder)?;
    decoder.finish()?;
    let commit = ReconciliationCommit {
        commit_id,
        branch_id,
        volume_id,
        root_object_id,
        root_object_revision_id,
        parents,
        operation_id,
        request_digest,
        payload: ReconciliationCommitPayload::Mutation { intent_digest },
    };
    validate_record(&commit, &intent, created_by, created_at, commit_digest)?;
    Ok(TransferredMutationCommit {
        commit,
        created_by,
        created_at,
        commit_digest,
        intent,
    })
}

fn validate_record(
    commit: &ReconciliationCommit,
    intent: &BranchMutationIntent,
    created_by: PrincipalId,
    created_at: UnixMicros,
    commit_digest: [u8; 32],
) -> Result<(), NamespaceHistoryRecordError> {
    let ReconciliationCommitPayload::Mutation { intent_digest } = commit.payload else {
        return Err(NamespaceHistoryRecordError::Invalid);
    };
    let stored = StoredCommit {
        commit_id: commit.commit_id,
        branch_id: commit.branch_id,
        volume_id: commit.volume_id,
        root_object_id: commit.root_object_id,
        root_object_revision_id: commit.root_object_revision_id,
        parent_id: commit.parents.first().copied(),
        created_by,
        operation_id: commit.operation_id,
        created_at,
    };
    if intent.commit_id != commit.commit_id
        || intent.digest() != intent_digest
        || stored_commit_digest(&stored, commit.request_digest) != commit_digest
    {
        Err(NamespaceHistoryRecordError::Invalid)
    } else {
        Ok(())
    }
}

fn decode_intent(
    decoder: &mut Decoder<'_>,
) -> Result<BranchMutationIntent, NamespaceHistoryRecordError> {
    let commit_id = decoder.identifier(NamespaceCommitId::from_bytes)?;
    let path = decode_path(decoder)?;
    let ancestors = decode_transitions(decoder)?;
    let object_id = decoder.identifier(ObjectId::from_bytes)?;
    let object_revision_id = decoder.identifier(ObjectRevisionId::from_bytes)?;
    let prior_object_revision_id = decoder.optional_identifier(ObjectRevisionId::from_bytes)?;
    let entry_generation = decoder.unsigned()?;
    if entry_generation == 0 {
        return Err(NamespaceHistoryRecordError::Invalid);
    }
    let mutation = decode_mutation(decoder)?;
    let rename = match decoder.byte()? {
        0 => None,
        1 => Some(decode_rename(decoder)?),
        _ => return Err(NamespaceHistoryRecordError::Invalid),
    };
    Ok(BranchMutationIntent {
        commit_id,
        path,
        ancestors,
        object_id,
        object_revision_id,
        prior_object_revision_id,
        entry_generation,
        mutation,
        rename,
    })
}

fn decode_rename(
    decoder: &mut Decoder<'_>,
) -> Result<BranchRenameIntent, NamespaceHistoryRecordError> {
    let source_path = decode_path(decoder)?;
    let source_ancestors = decode_transitions(decoder)?;
    let source_entry_generation = decoder.unsigned()?;
    if source_entry_generation == 0 {
        return Err(NamespaceHistoryRecordError::Invalid);
    }
    Ok(BranchRenameIntent {
        source_path,
        source_ancestors,
        source_entry_generation,
        intermediate_root_object_revision_id: decoder.identifier(ObjectRevisionId::from_bytes)?,
    })
}

fn decode_path(decoder: &mut Decoder<'_>) -> Result<NamespacePath, NamespaceHistoryRecordError> {
    let count = decoder.bounded_count(MAXIMUM_PATH_COMPONENTS)?;
    if count == 0 {
        return Err(NamespaceHistoryRecordError::Invalid);
    }
    let mut components = Vec::with_capacity(count);
    for _ in 0..count {
        let bytes = decoder.variable(MAXIMUM_COMPONENT_BYTES)?;
        let value = std::str::from_utf8(bytes).map_err(|_| NamespaceHistoryRecordError::Invalid)?;
        components.push(value.to_owned());
    }
    NamespacePath::from_components(
        components.iter().map(String::as_str),
        NamespaceLimits::INTERNAL,
    )
    .map_err(|_| NamespaceHistoryRecordError::Invalid)
}

fn decode_transitions(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<DirectoryRevisionTransition>, NamespaceHistoryRecordError> {
    let count = decoder.bounded_count(MAXIMUM_TRANSITIONS)?;
    let mut transitions = Vec::with_capacity(count);
    for _ in 0..count {
        transitions.push(
            DirectoryRevisionTransition::new(
                decoder.identifier(ObjectId::from_bytes)?,
                decoder.identifier(ObjectRevisionId::from_bytes)?,
                decoder.identifier(ObjectRevisionId::from_bytes)?,
            )
            .map_err(|_| NamespaceHistoryRecordError::Invalid)?,
        );
    }
    Ok(transitions)
}

fn decode_mutation(
    decoder: &mut Decoder<'_>,
) -> Result<BranchMutation, NamespaceHistoryRecordError> {
    match decoder.byte()? {
        1 => Ok(BranchMutation::File {
            version_id: decoder.identifier(FileVersionId::from_bytes)?,
        }),
        2 => Ok(BranchMutation::CreateDirectory),
        3 => Ok(BranchMutation::DeleteFile {
            version_id: decoder.identifier(FileVersionId::from_bytes)?,
        }),
        4 => Ok(BranchMutation::DeleteDirectory),
        _ => Err(NamespaceHistoryRecordError::Invalid),
    }
}

fn decode_parents(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<NamespaceCommitId>, NamespaceHistoryRecordError> {
    let count = decoder.bounded_count(1)?;
    (0..count)
        .map(|_| decoder.identifier(NamespaceCommitId::from_bytes))
        .collect()
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

    fn bounded_count(&mut self, maximum: usize) -> Result<usize, NamespaceHistoryRecordError> {
        let count = usize::from(u16::from_be_bytes(self.array()?));
        if count <= maximum {
            Ok(count)
        } else {
            Err(NamespaceHistoryRecordError::BoundsExceeded)
        }
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
