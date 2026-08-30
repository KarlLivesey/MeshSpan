// SPDX-License-Identifier: GPL-2.0-only

//! Cross-swarm federation envelope and message validation.

use std::collections::BTreeSet;

use crate::framing::{WireContractError, WireLimits};
use crate::v1::federation_envelope::Message;
use crate::v1::{
    FederatedBranchPage, FederatedBranchResult, FederatedContentLayoutPage,
    FederatedContentShardHeader, FederatedHistoryObjectHeader, FederatedStorageCapability,
    FederatedStorageInventoryPage, FederatedStorageReceipt, FederationAuthorityPage,
    FederationEnvelope, FederationHeader, FederationHello, FederationWelcome,
    FetchFederatedBranchPage, FetchFederatedContentLayout, FetchFederatedContentShard,
    FetchFederatedHistoryObject, FetchFederatedStorageInventory, FetchFederationAuthority,
    OperationOutcome, ProposeFederatedBranch, RemoteShardAction, RequestFederatedStorageCapability,
};

use super::{
    valid_count, valid_digest, valid_digests, valid_identifier, valid_identifiers,
    valid_nonempty_bytes, valid_optional_bytes, valid_page_limit, validate_operation_result,
    validate_payload, validate_payloads, validate_shard,
};

pub(super) fn envelope(
    envelope: &FederationEnvelope,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    header(
        envelope
            .header
            .as_ref()
            .ok_or(WireContractError::InvalidMessage)?,
    )?;
    match envelope
        .message
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?
    {
        Message::Hello(value) => hello(value, limits),
        Message::Welcome(value) => welcome(value, limits),
        Message::FetchAuthority(value) => fetch_authority(value, limits),
        Message::AuthorityPage(value) => authority_page(value, limits),
        Message::FetchBranchPage(value) => fetch_branch_page(value, limits),
        Message::BranchPage(value) => branch_page(value, limits),
        Message::FetchHistoryObject(value) => fetch_history_object(value, limits),
        Message::HistoryObjectHeader(value) => history_object_header(value, limits),
        Message::FetchContentLayout(value) => fetch_content_layout(value, limits),
        Message::ContentLayoutPage(value) => content_layout_page(value, limits),
        Message::FetchContentShard(value) => fetch_content_shard(value, limits),
        Message::ContentShardHeader(value) => content_shard_header(value, limits),
        Message::ProposeBranch(value) => propose_branch(value, limits),
        Message::BranchResult(value) => branch_result(value, limits),
        Message::RequestStorageCapability(value) => request_storage_capability(value, limits),
        Message::StorageCapability(value) => storage_capability(value, limits),
        Message::StorageReceipt(value) => storage_receipt(value, limits),
        Message::FetchStorageInventory(value) => fetch_storage_inventory(value, limits),
        Message::StorageInventoryPage(value) => storage_inventory_page(value, limits),
    }
}

const MAXIMUM_HISTORY_OBJECT_BYTES: u64 = 2 * 1_024 * 1_024;

fn fetch_authority(
    value: &FetchFederationAuthority,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_optional_bytes(&value.cursor, limits.maximum_control_bytes())?;
    valid_page_limit(value.limit, limits)?;
    valid_signature(&value.signature, limits)
}

fn header(value: &FederationHeader) -> Result<(), WireContractError> {
    let version = value
        .version
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    valid_identifier(&value.relationship_id)?;
    valid_identifier(&value.sender_mesh_id)?;
    valid_identifier(&value.recipient_mesh_id)?;
    valid_identifier(&value.request_id)?;
    valid_identifier(&value.operation_id)?;
    valid_identifier(&value.trace_id)?;
    valid_nonce(&value.replay_nonce)?;
    if version.major != 1
        || value.sender_mesh_id == value.recipient_mesh_id
        || value.authority_epoch == 0
        || value.deadline_unix_micros <= 0
    {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn hello(value: &FederationHello, limits: WireLimits) -> Result<(), WireContractError> {
    valid_count(value.versions.len(), limits, false)?;
    valid_count(value.feature_bits.len(), limits, true)?;
    valid_nonempty_bytes(&value.public_identity_chain, limits.maximum_control_bytes())?;
    valid_nonce(&value.challenge_nonce)?;
    valid_signature(&value.signature, limits)?;
    if value.identity_generation == 0
        || value.versions.iter().any(|version| version.major == 0)
        || value.maximum_control_bytes == 0
        || value.maximum_data_frame_bytes == 0
        || value.maximum_streams == 0
    {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn welcome(value: &FederationWelcome, limits: WireLimits) -> Result<(), WireContractError> {
    let version = value
        .selected_version
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    valid_nonce(&value.request_challenge_nonce)?;
    valid_nonce(&value.responder_challenge_nonce)?;
    valid_signature(&value.signature, limits)?;
    if version.major != 1
        || value.identity_generation == 0
        || value.request_challenge_nonce == value.responder_challenge_nonce
        || value.authority_revision == 0
        || value.maximum_control_bytes == 0
        || value.maximum_data_frame_bytes == 0
        || value.maximum_streams == 0
    {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn authority_page(
    value: &FederationAuthorityPage,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    nonzero(value.authority_revision)?;
    validate_payloads(&value.records, limits, true)?;
    valid_optional_bytes(&value.next_cursor, limits.maximum_control_bytes())?;
    terminal_if_empty(value.records.is_empty(), &value.next_cursor)?;
    valid_digest(&value.page_digest)?;
    valid_signature(&value.signature, limits)
}

fn fetch_branch_page(
    value: &FetchFederatedBranchPage,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.grant_id)?;
    validate_payload(value.resource_scope.as_ref(), limits)?;
    valid_identifiers(&value.requested_head_ids, limits, false)?;
    valid_identifiers(&value.known_commit_ids, limits, true)?;
    unique_identifiers(&value.requested_head_ids)?;
    unique_identifiers(&value.known_commit_ids)?;
    valid_optional_bytes(&value.cursor, limits.maximum_control_bytes())?;
    valid_page_limit(value.limit, limits)?;
    valid_signature(&value.signature, limits)
}

fn unique_identifiers(values: &[Vec<u8>]) -> Result<(), WireContractError> {
    let unique = values.iter().map(Vec::as_slice).collect::<BTreeSet<_>>();
    if unique.len() == values.len() {
        Ok(())
    } else {
        Err(WireContractError::InvalidMessage)
    }
}

fn branch_page(value: &FederatedBranchPage, limits: WireLimits) -> Result<(), WireContractError> {
    valid_identifier(&value.grant_id)?;
    validate_payload(value.resource_scope.as_ref(), limits)?;
    valid_digest(&value.export_token)?;
    validate_payloads(&value.branch_commits, limits, true)?;
    valid_digests(&value.immutable_object_digests, limits, true)?;
    valid_optional_bytes(&value.next_cursor, limits.maximum_control_bytes())?;
    terminal_if_empty(
        value.branch_commits.is_empty() && value.immutable_object_digests.is_empty(),
        &value.next_cursor,
    )?;
    valid_digest(&value.page_digest)?;
    valid_signature(&value.signature, limits)
}

fn fetch_history_object(
    value: &FetchFederatedHistoryObject,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.grant_id)?;
    validate_payload(value.resource_scope.as_ref(), limits)?;
    valid_digest(&value.export_token)?;
    valid_digest(&value.object_digest)?;
    valid_signature(&value.signature, limits)
}

fn history_object_header(
    value: &FederatedHistoryObjectHeader,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.grant_id)?;
    validate_payload(value.resource_scope.as_ref(), limits)?;
    valid_digest(&value.export_token)?;
    valid_digest(&value.object_digest)?;
    valid_signature(&value.signature, limits)?;
    let maximum_frame_bytes = usize::try_from(value.maximum_frame_bytes)
        .map_err(|_| WireContractError::InvalidMessage)?;
    if value.declared_length == 0
        || value.declared_length > MAXIMUM_HISTORY_OBJECT_BYTES
        || maximum_frame_bytes == 0
        || maximum_frame_bytes > limits.maximum_data_frame_bytes()
    {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn fetch_content_layout(
    value: &FetchFederatedContentLayout,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.grant_id)?;
    validate_payload(value.resource_scope.as_ref(), limits)?;
    valid_identifier(&value.manifest_id)?;
    valid_digest(&value.export_token)?;
    valid_digest(&value.manifest_object_digest)?;
    valid_optional_bytes(&value.cursor, limits.maximum_control_bytes())?;
    valid_page_limit(value.limit, limits)?;
    valid_signature(&value.signature, limits)
}

fn content_layout_page(
    value: &FederatedContentLayoutPage,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.grant_id)?;
    validate_payload(value.resource_scope.as_ref(), limits)?;
    valid_identifier(&value.manifest_id)?;
    valid_digest(&value.export_token)?;
    valid_digest(&value.manifest_object_digest)?;
    validate_payload(value.layout_header.as_ref(), limits)?;
    validate_payloads(&value.chunks, limits, true)?;
    valid_optional_bytes(&value.next_cursor, limits.maximum_control_bytes())?;
    terminal_if_empty(value.chunks.is_empty(), &value.next_cursor)?;
    valid_digest(&value.page_digest)?;
    valid_signature(&value.signature, limits)
}

fn fetch_content_shard(
    value: &FetchFederatedContentShard,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.grant_id)?;
    validate_payload(value.resource_scope.as_ref(), limits)?;
    valid_identifier(&value.manifest_id)?;
    valid_digest(&value.export_token)?;
    valid_digest(&value.manifest_object_digest)?;
    content_shard_route(
        &value.target_id,
        value.target_generation,
        value.shard.as_ref(),
        value.expected_length,
        &value.expected_digest,
    )?;
    valid_signature(&value.signature, limits)
}

fn content_shard_header(
    value: &FederatedContentShardHeader,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.grant_id)?;
    validate_payload(value.resource_scope.as_ref(), limits)?;
    valid_identifier(&value.manifest_id)?;
    valid_digest(&value.export_token)?;
    valid_digest(&value.manifest_object_digest)?;
    content_shard_route(
        &value.target_id,
        value.target_generation,
        value.shard.as_ref(),
        value.declared_length,
        &value.content_digest,
    )?;
    let maximum_frame_bytes = usize::try_from(value.maximum_frame_bytes)
        .map_err(|_| WireContractError::InvalidMessage)?;
    if maximum_frame_bytes == 0
        || maximum_frame_bytes > limits.maximum_data_frame_bytes()
        || value.served_at_unix_micros <= 0
    {
        return Err(WireContractError::InvalidMessage);
    }
    valid_signature(&value.signature, limits)
}

fn content_shard_route(
    target_id: &[u8],
    target_generation: u64,
    shard: Option<&crate::v1::ShardIdentity>,
    length: u64,
    digest: &[u8],
) -> Result<(), WireContractError> {
    valid_identifier(target_id)?;
    validate_shard(shard)?;
    valid_digest(digest)?;
    if target_generation == 0 || length == 0 {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn propose_branch(
    value: &ProposeFederatedBranch,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.grant_id)?;
    validate_payload(value.resource_scope.as_ref(), limits)?;
    validate_payload(value.grant_use_evidence.as_ref(), limits)?;
    valid_digests(&value.branch_head_digests, limits, false)?;
    valid_digest(&value.expected_owner_head_digest)?;
    valid_signature(&value.signature, limits)
}

fn branch_result(
    value: &FederatedBranchResult,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    validate_operation_result(value.result.as_ref(), limits)?;
    validate_payload(value.accepting_swarm_receipt.as_ref(), limits)?;
    if value.owner_history_revision == Some(0) {
        return Err(WireContractError::InvalidMessage);
    }
    if let Some(receipt) = &value.protection_receipt {
        validate_payload(Some(receipt), limits)?;
    }
    if let Some(quarantine_id) = &value.quarantine_id {
        valid_identifier(quarantine_id)?;
    }
    valid_digests(&value.alternative_head_digests, limits, true)?;
    valid_signature(&value.signature, limits)?;
    validate_branch_result_shape(value)
}

fn validate_branch_result_shape(value: &FederatedBranchResult) -> Result<(), WireContractError> {
    let outcome = OperationOutcome::try_from(
        value
            .result
            .as_ref()
            .ok_or(WireContractError::InvalidMessage)?
            .outcome,
    )
    .map_err(|_| WireContractError::InvalidMessage)?;
    let owner_accepted = value.owner_history_revision.is_some();
    let protected = value.protection_receipt.is_some();
    let quarantined = value.quarantine_id.is_some();
    let has_error = value
        .result
        .as_ref()
        .is_some_and(|result| result.error.is_some());
    let valid = match outcome {
        OperationOutcome::BranchCommitted | OperationOutcome::InProgress => {
            !owner_accepted && !protected && !quarantined && !has_error
        }
        OperationOutcome::GloballyConverged => {
            owner_accepted && !protected && !quarantined && !has_error
        }
        OperationOutcome::PolicyCommitted => {
            owner_accepted && protected && !quarantined && !has_error
        }
        OperationOutcome::Rejected => !owner_accepted && !protected && has_error,
        OperationOutcome::Stale | OperationOutcome::Failed => {
            !owner_accepted && !protected && !quarantined && has_error
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(WireContractError::InvalidMessage)
    }
}

fn request_storage_capability(
    value: &RequestFederatedStorageCapability,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.allocation_id)?;
    storage_subject(
        &value.grant_id,
        &value.target_id,
        value.target_generation,
        value.shard.as_ref(),
        value.action,
        value.maximum_bytes,
    )?;
    valid_digest(&value.scope_digest)?;
    valid_signature(&value.signature, limits)
}

fn storage_capability(
    value: &FederatedStorageCapability,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.allocation_id)?;
    storage_subject(
        &value.grant_id,
        &value.target_id,
        value.target_generation,
        value.shard.as_ref(),
        value.action,
        value.maximum_bytes,
    )?;
    if value.issued_at_unix_micros <= 0
        || value.valid_until_unix_micros <= value.issued_at_unix_micros
    {
        return Err(WireContractError::InvalidMessage);
    }
    valid_nonce(&value.capability_nonce)?;
    valid_nonempty_bytes(&value.canonical_capability, limits.maximum_control_bytes())?;
    valid_signature(&value.signature, limits)
}

fn storage_receipt(
    value: &FederatedStorageReceipt,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.allocation_id)?;
    storage_subject(
        &value.grant_id,
        &value.target_id,
        value.target_generation,
        value.shard.as_ref(),
        value.action,
        value.affected_bytes,
    )?;
    if value.completed_at_unix_micros <= 0 {
        return Err(WireContractError::InvalidMessage);
    }
    valid_digest(&value.capability_digest)?;
    valid_digest(&value.result_digest)?;
    valid_signature(&value.signature, limits)
}

fn fetch_storage_inventory(
    value: &FetchFederatedStorageInventory,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.grant_id)?;
    valid_identifier(&value.target_id)?;
    nonzero(value.target_generation)?;
    valid_optional_bytes(&value.cursor, limits.maximum_control_bytes())?;
    valid_page_limit(value.limit, limits)?;
    valid_signature(&value.signature, limits)
}

fn storage_inventory_page(
    value: &FederatedStorageInventoryPage,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.grant_id)?;
    valid_identifier(&value.target_id)?;
    nonzero(value.target_generation)?;
    validate_payloads(&value.records, limits, true)?;
    valid_optional_bytes(&value.next_cursor, limits.maximum_control_bytes())?;
    terminal_if_empty(value.records.is_empty(), &value.next_cursor)?;
    valid_digest(&value.page_digest)?;
    valid_signature(&value.signature, limits)
}

fn storage_subject(
    grant_id: &[u8],
    target_id: &[u8],
    target_generation: u64,
    shard: Option<&crate::v1::ShardIdentity>,
    action: i32,
    maximum_or_affected_bytes: u64,
) -> Result<(), WireContractError> {
    valid_identifier(grant_id)?;
    valid_identifier(target_id)?;
    nonzero(target_generation)?;
    validate_shard(shard)?;
    let action =
        RemoteShardAction::try_from(action).map_err(|_| WireContractError::InvalidMessage)?;
    if action == RemoteShardAction::Unspecified || maximum_or_affected_bytes == 0 {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

fn valid_signature(value: &[u8], limits: WireLimits) -> Result<(), WireContractError> {
    if value.len() == 64
        && value.len() <= limits.maximum_control_bytes()
        && value.iter().any(|byte| *byte != 0)
    {
        Ok(())
    } else {
        Err(WireContractError::InvalidMessage)
    }
}

fn valid_nonce(value: &[u8]) -> Result<(), WireContractError> {
    valid_digest(value)?;
    if value.iter().any(|byte| *byte != 0) {
        Ok(())
    } else {
        Err(WireContractError::InvalidMessage)
    }
}

fn terminal_if_empty(is_empty: bool, next_cursor: &[u8]) -> Result<(), WireContractError> {
    if is_empty && !next_cursor.is_empty() {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}

const fn nonzero(value: u64) -> Result<(), WireContractError> {
    if value == 0 {
        Err(WireContractError::InvalidMessage)
    } else {
        Ok(())
    }
}
