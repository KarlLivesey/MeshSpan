// SPDX-License-Identifier: GPL-2.0-only

//! Backup-only federation wire shapes and exact nested-context bindings.

use super::{nonzero, valid_nonce, valid_signature};
use crate::v1::{
    ExecuteFederatedBackup, FederatedBackupCapability, FederatedBackupOperation,
    FederatedBackupPermit, FederatedBackupReady, FederatedBackupResult, FederatedBackupScope,
    FederationHeader, RemoteBackupAction, RequestFederatedBackupCapability,
    federated_backup_result::Outcome,
};
use crate::validation::{data::backup as object, valid_identifier, validate_wire_error};
use crate::{WireContractError, WireLimits};

const MAXIMUM_PERMIT_LIFETIME: i64 = 300_000_000;

pub(super) fn allocation_fetch(
    value: &crate::v1::FetchFederatedBackupAllocations,
    header: &FederationHeader,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_identifier(&value.grant_id)?;
    nonzero(value.required_bytes)?;
    if value.required_bytes > i64::MAX.unsigned_abs() {
        return Err(WireContractError::InvalidMessage);
    }
    crate::validation::valid_page_limit(value.limit, limits)?;
    valid_signature(&value.signature, limits)?;
    if !value.cursor.is_empty() {
        let cursor = crate::decode_backup_allocation_cursor(&value.cursor)?;
        if cursor.relationship_id != header.relationship_id
            || cursor.authority_epoch != header.authority_epoch
            || cursor.grant_id != value.grant_id
            || cursor.required_bytes != value.required_bytes
        {
            return Err(WireContractError::InvalidMessage);
        }
    }
    Ok(())
}

pub(super) fn allocation_page(
    value: &crate::v1::FederatedBackupAllocationPage,
    header: &FederationHeader,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_nonce(&value.request_digest)?;
    nonzero(value.authority_revision)?;
    valid_signature(&value.signature, limits)?;
    crate::validation::valid_count(value.allocations.len(), limits, true)?;
    let mut seen = std::collections::BTreeSet::new();
    for allocation in &value.allocations {
        scope(allocation.scope.as_ref(), header, true)?;
        let scope = allocation
            .scope
            .as_ref()
            .ok_or(WireContractError::InvalidMessage)?;
        if !seen.insert(&scope.allocation_id)
            || scope.allocation_revision > value.authority_revision
            || scope.grant_revision > value.authority_revision
            || allocation.maximum_bytes == 0
            || allocation.maximum_bytes > i64::MAX.unsigned_abs()
            || allocation.valid_from_unix_micros <= 0
            || allocation.valid_until_unix_micros <= allocation.valid_from_unix_micros
        {
            return Err(WireContractError::InvalidMessage);
        }
    }
    if !value.next_cursor.is_empty() {
        let cursor = crate::decode_backup_allocation_cursor(&value.next_cursor)?;
        if cursor.relationship_id != header.relationship_id
            || cursor.authority_epoch != header.authority_epoch
            || cursor.snapshot_revision != value.authority_revision
        {
            return Err(WireContractError::InvalidMessage);
        }
    }
    Ok(())
}

pub(super) fn request(
    value: &RequestFederatedBackupCapability,
    header: &FederationHeader,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    scope(value.scope.as_ref(), header, false)?;
    operation(value.operation.as_ref(), header, limits)?;
    valid_signature(&value.signature, limits)
}

pub(super) fn capability(
    value: &FederatedBackupCapability,
    header: &FederationHeader,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_nonce(&value.request_digest)?;
    valid_signature(&value.signature, limits)?;
    match (&value.permit, &value.rejection) {
        (Some(value), None) => permit(value, header, limits, true),
        (None, Some(error)) => validate_wire_error(error),
        _ => Err(WireContractError::InvalidMessage),
    }
}

pub(super) fn execute(
    value: &ExecuteFederatedBackup,
    header: &FederationHeader,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    permit(
        value
            .permit
            .as_ref()
            .ok_or(WireContractError::InvalidMessage)?,
        header,
        limits,
        false,
    )?;
    valid_signature(&value.signature, limits)
}

pub(super) fn ready(
    value: &FederatedBackupReady,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_signature(&value.signature, limits)?;
    ready_payload(value, limits)
}

pub(in crate::validation) fn ready_payload(
    value: &FederatedBackupReady,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_nonce(&value.permit_digest)?;
    match &value.rejection {
        None => object::validate_maximum_frame_bytes(value.maximum_frame_bytes, limits),
        Some(error) if value.maximum_frame_bytes == 0 => validate_wire_error(error),
        Some(_) => Err(WireContractError::InvalidMessage),
    }
}

pub(super) fn result(
    value: &FederatedBackupResult,
    header: &FederationHeader,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    valid_signature(&value.signature, limits)?;
    let operation_id = result_payload(value, limits)?;
    if value.completed_at_unix_micros > header.deadline_unix_micros
        || operation_id.is_some_and(|id| id != header.operation_id)
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}

pub(in crate::validation) fn result_payload(
    value: &FederatedBackupResult,
    limits: WireLimits,
) -> Result<Option<&[u8]>, WireContractError> {
    valid_nonce(&value.permit_digest)?;
    if value.completed_at_unix_micros <= 0 {
        return Err(WireContractError::InvalidMessage);
    }
    let operation_id = match value
        .outcome
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?
    {
        Outcome::Stored(receipt) | Outcome::Verified(receipt) | Outcome::LookedUp(receipt) => {
            object::validate_object_receipt(Some(receipt), limits)?;
            &receipt.operation_id
        }
        Outcome::Read(receipt) => {
            object::validate_read_receipt(Some(receipt))?;
            &receipt.operation_id
        }
        Outcome::Deleted(receipt) => {
            object::validate_delete_receipt(Some(receipt))?;
            &receipt.operation_id
        }
        Outcome::Rejection(error) => return validate_wire_error(error).map(|()| None),
    };
    Ok(Some(operation_id))
}

fn scope(
    value: Option<&FederatedBackupScope>,
    header: &FederationHeader,
    response: bool,
) -> Result<(), WireContractError> {
    let value = value.ok_or(WireContractError::InvalidMessage)?;
    for id in [
        &value.relationship_id,
        &value.remote_mesh_id,
        &value.provider_mesh_id,
        &value.allocation_id,
        &value.grant_id,
        &value.namespace_grant_id,
        &value.provider_node_id,
        &value.target_id,
    ] {
        valid_identifier(id)?;
    }
    for number in [
        value.target_generation,
        value.relationship_authority_epoch,
        value.grant_revision,
        value.allocation_revision,
    ] {
        nonzero(number)?;
    }
    let (sender, recipient) = if response {
        (&value.provider_mesh_id, &value.remote_mesh_id)
    } else {
        (&value.remote_mesh_id, &value.provider_mesh_id)
    };
    if sender != &header.sender_mesh_id
        || recipient != &header.recipient_mesh_id
        || value.relationship_id != header.relationship_id
        || value.relationship_authority_epoch != header.authority_epoch
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}

fn operation(
    value: Option<&FederatedBackupOperation>,
    header: &FederationHeader,
    limits: WireLimits,
) -> Result<(), WireContractError> {
    let value = value.ok_or(WireContractError::InvalidMessage)?;
    let version = value
        .contract_version
        .as_ref()
        .ok_or(WireContractError::InvalidMessage)?;
    if version.major != 1
        || version.minor != 0
        || value.operation_id != header.operation_id
        // A replay-bounded attempt may finish before the complete operation, but
        // cannot extend it. Both deadlines remain covered by the signature.
        || value.deadline_unix_micros < header.deadline_unix_micros
    {
        return Err(WireContractError::InvalidMessage);
    }
    nonzero(
        value
            .authority_revision
            .ok_or(WireContractError::InvalidMessage)?,
    )?;
    object::validate_object(value.object.as_ref())?;
    match RemoteBackupAction::try_from(value.action)
        .map_err(|_| WireContractError::InvalidMessage)?
    {
        RemoteBackupAction::Store | RemoteBackupAction::Lookup
            if value.object_reference.is_empty() && value.retirement_revision.is_none() =>
        {
            Ok(())
        }
        RemoteBackupAction::Read | RemoteBackupAction::Verify
            if value.retirement_revision.is_none() =>
        {
            object::validate_reference(&value.object_reference, limits)
        }
        RemoteBackupAction::Delete if value.retirement_revision == value.authority_revision => {
            object::validate_reference(&value.object_reference, limits)
        }
        _ => Err(WireContractError::InvalidMessage),
    }
}

fn permit(
    value: &FederatedBackupPermit,
    header: &FederationHeader,
    limits: WireLimits,
    response: bool,
) -> Result<(), WireContractError> {
    scope(value.scope.as_ref(), header, response)?;
    operation(value.operation.as_ref(), header, limits)?;
    valid_nonce(&value.capability_nonce)?;
    valid_nonce(&value.permit_digest)?;
    let lifetime = value
        .expires_at_unix_micros
        .checked_sub(value.issued_at_unix_micros)
        .ok_or(WireContractError::InvalidMessage)?;
    if value.issued_at_unix_micros <= 0
        || !(1..=MAXIMUM_PERMIT_LIFETIME).contains(&lifetime)
        || value.expires_at_unix_micros > header.deadline_unix_micros
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}
