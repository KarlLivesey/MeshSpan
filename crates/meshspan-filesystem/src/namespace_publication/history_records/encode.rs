// SPDX-License-Identifier: GPL-2.0-only

//! Canonical encoder for one immutable mutation commit and replay intent.

use meshspan_domain::ObjectRevisionId;

use super::super::transfer::TransferredMutationCommit;
use super::{COMMIT_DOMAIN, COMMIT_FORMAT_VERSION, NamespaceHistoryRecordError};
use crate::{
    BranchMutation, BranchMutationIntent, BranchRenameIntent, DirectoryRevisionTransition,
    NamespacePath, ReconciliationCommitPayload,
};

pub(super) fn encode_commit(
    record: &TransferredMutationCommit,
) -> Result<Vec<u8>, NamespaceHistoryRecordError> {
    let ReconciliationCommitPayload::Mutation { intent_digest } = record.commit.payload else {
        return Err(NamespaceHistoryRecordError::Invalid);
    };
    if record.commit.commit_id != record.intent.commit_id
        || record.intent.digest() != intent_digest
        || record.commit.parents.len() > 1
    {
        return Err(NamespaceHistoryRecordError::Invalid);
    }
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(COMMIT_DOMAIN);
    bytes.push(COMMIT_FORMAT_VERSION);
    identifier(&mut bytes, record.commit.commit_id.as_bytes());
    identifier(&mut bytes, record.commit.branch_id.as_bytes());
    identifier(&mut bytes, record.commit.volume_id.as_bytes());
    identifier(&mut bytes, record.commit.root_object_id.as_bytes());
    identifier(&mut bytes, record.commit.root_object_revision_id.as_bytes());
    identifiers(&mut bytes, &record.commit.parents)?;
    identifier(&mut bytes, record.commit.operation_id.as_bytes());
    digest(&mut bytes, record.commit.request_digest);
    bytes.push(1);
    digest(&mut bytes, intent_digest);
    identifier(&mut bytes, record.created_by.as_bytes());
    bytes.extend_from_slice(&record.created_at.get().to_be_bytes());
    digest(&mut bytes, record.commit_digest);
    encode_intent(&mut bytes, &record.intent)?;
    Ok(bytes)
}

fn encode_intent(
    bytes: &mut Vec<u8>,
    intent: &BranchMutationIntent,
) -> Result<(), NamespaceHistoryRecordError> {
    identifier(bytes, intent.commit_id.as_bytes());
    path(bytes, &intent.path)?;
    transitions(bytes, &intent.ancestors)?;
    identifier(bytes, intent.object_id.as_bytes());
    identifier(bytes, intent.object_revision_id.as_bytes());
    optional_identifier(bytes, intent.prior_object_revision_id);
    bytes.extend_from_slice(&intent.entry_generation.to_be_bytes());
    mutation(bytes, intent.mutation);
    match &intent.rename {
        Some(rename) => {
            bytes.push(1);
            rename_intent(bytes, rename)?;
        }
        None => bytes.push(0),
    }
    Ok(())
}

fn rename_intent(
    bytes: &mut Vec<u8>,
    rename: &BranchRenameIntent,
) -> Result<(), NamespaceHistoryRecordError> {
    path(bytes, &rename.source_path)?;
    transitions(bytes, &rename.source_ancestors)?;
    bytes.extend_from_slice(&rename.source_entry_generation.to_be_bytes());
    identifier(
        bytes,
        rename.intermediate_root_object_revision_id.as_bytes(),
    );
    Ok(())
}

fn path(bytes: &mut Vec<u8>, path: &NamespacePath) -> Result<(), NamespaceHistoryRecordError> {
    count(bytes, path.components().len())?;
    for component in path.components() {
        variable(bytes, component.display().as_bytes())?;
    }
    Ok(())
}

fn transitions(
    bytes: &mut Vec<u8>,
    transitions: &[DirectoryRevisionTransition],
) -> Result<(), NamespaceHistoryRecordError> {
    count(bytes, transitions.len())?;
    for transition in transitions {
        identifier(bytes, transition.object_id().as_bytes());
        identifier(bytes, transition.expected_revision_id().as_bytes());
        identifier(bytes, transition.new_revision_id().as_bytes());
    }
    Ok(())
}

fn mutation(bytes: &mut Vec<u8>, mutation: BranchMutation) {
    match mutation {
        BranchMutation::File { version_id } => {
            bytes.push(1);
            identifier(bytes, version_id.as_bytes());
        }
        BranchMutation::CreateDirectory => bytes.push(2),
        BranchMutation::DeleteFile { version_id } => {
            bytes.push(3);
            identifier(bytes, version_id.as_bytes());
        }
        BranchMutation::DeleteDirectory => bytes.push(4),
    }
}

fn identifiers(
    bytes: &mut Vec<u8>,
    identifiers: &[meshspan_domain::NamespaceCommitId],
) -> Result<(), NamespaceHistoryRecordError> {
    count(bytes, identifiers.len())?;
    for value in identifiers {
        identifier(bytes, value.as_bytes());
    }
    Ok(())
}

fn optional_identifier(bytes: &mut Vec<u8>, value: Option<ObjectRevisionId>) {
    match value {
        Some(value) => {
            bytes.push(1);
            identifier(bytes, value.as_bytes());
        }
        None => bytes.push(0),
    }
}

fn count(bytes: &mut Vec<u8>, value: usize) -> Result<(), NamespaceHistoryRecordError> {
    let value = u16::try_from(value).map_err(|_| NamespaceHistoryRecordError::BoundsExceeded)?;
    bytes.extend_from_slice(&value.to_be_bytes());
    Ok(())
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

fn digest(bytes: &mut Vec<u8>, value: [u8; 32]) {
    bytes.extend_from_slice(&value);
}
