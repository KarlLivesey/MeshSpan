// SPDX-License-Identifier: GPL-2.0-only

//! Exact conversions between signed federation wire records and backup capabilities.

use meshspan_contracts::{
    BackupDeleteRequest, BackupObjectReference, BackupReadRequest, BackupStoreRequest,
    BackupVerifyRequest, ContractError, ContractVersion, FederatedBackupPermit,
    FederatedBackupRequest, FederatedBackupScope, MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES,
    RequestContext, federated_provider_backup_identity, validate_federated_backup_permit,
};
use meshspan_domain::{
    FederationGrantId, FederationRelationshipId, FederationStorageAllocationId, MeshId, NodeId,
    OperationId, Revision, TargetId, UnixMicros,
};
use meshspan_protocol::v1 as wire;

use crate::backup_wire::{object, wire_object};

/// Encodes a provider object receipt; callers must check it against the admitted request.
#[must_use]
pub fn encode_backup_object_receipt(
    value: &meshspan_contracts::BackupObjectReceipt,
) -> wire::BackupObjectReceipt {
    crate::backup_wire::wire_object_receipt(value)
}

/// Encodes a provider read receipt without changing its measured digest or length.
#[must_use]
pub fn encode_backup_read_receipt(
    value: meshspan_contracts::BackupReadReceipt,
) -> wire::BackupReadReceipt {
    crate::backup_wire::wire_read_receipt(value)
}

/// Encodes exact retirement evidence without inventing a location-based authorisation.
#[must_use]
pub fn encode_backup_delete_receipt(
    value: meshspan_contracts::BackupDeleteReceipt,
) -> wire::BackupDeleteReceipt {
    crate::backup_wire::wire_delete_receipt(value)
}

/// Converts a provider rejection to the existing stable, non-secret wire error catalogue.
#[must_use]
pub fn encode_backup_rejection(error: ContractError) -> wire::WireError {
    crate::backup_wire::wire_error(error)
}

/// Converts a validated provider request to an unsigned capability request for transport signing.
///
/// # Errors
/// Rejects unsupported contracts, malformed scope/object, elapsed deadline or invalid retirement.
pub fn encode_federated_backup_request(
    scope: FederatedBackupScope,
    request: &FederatedBackupRequest,
    now: UnixMicros,
) -> Result<wire::RequestFederatedBackupCapability, ContractError> {
    request.validate(now)?;
    federated_provider_backup_identity(scope, request.object())?;
    Ok(wire::RequestFederatedBackupCapability {
        scope: Some(encode_scope(scope)),
        operation: Some(encode_operation(request)),
        signature: Vec::new(),
    })
}

/// Parses exact request dimensions; the caller still authenticates the signed envelope and peer.
///
/// # Errors
/// Rejects ambiguous action fields, invalid identities/revisions and elapsed deadlines.
pub fn decode_federated_backup_request(
    value: &wire::RequestFederatedBackupCapability,
    now: UnixMicros,
) -> Result<(FederatedBackupScope, FederatedBackupRequest), ContractError> {
    decode_request(value.scope.as_ref(), value.operation.as_ref(), now)
}

/// Encodes a live exact permit without altering its provider-only MAC.
///
/// # Errors
/// Rejects invalid, expired or future capabilities. This does not verify the MAC's secret key.
pub fn encode_federated_backup_permit(
    permit: &FederatedBackupPermit,
    now: UnixMicros,
) -> Result<wire::FederatedBackupPermit, ContractError> {
    validate_federated_backup_permit(permit, now)?;
    Ok(wire::FederatedBackupPermit {
        scope: Some(encode_scope(permit.scope)),
        operation: Some(encode_operation(&permit.request)),
        issued_at_unix_micros: permit.issued_at.get(),
        expires_at_unix_micros: permit.expires_at.get(),
        capability_nonce: permit.capability_nonce.to_vec(),
        permit_digest: permit.permit_digest.to_vec(),
    })
}

/// Decodes a live exact permit for provider-side MAC and current-authority verification.
///
/// # Errors
/// Rejects missing, ambiguous, malformed, expired or future permit fields. Successful decoding
/// alone never grants permission; the provider must verify the MAC and current allocation.
pub fn decode_federated_backup_permit(
    value: &wire::FederatedBackupPermit,
    now: UnixMicros,
) -> Result<FederatedBackupPermit, ContractError> {
    let (scope, request) = decode_request(value.scope.as_ref(), value.operation.as_ref(), now)?;
    let permit = FederatedBackupPermit {
        scope,
        request,
        issued_at: UnixMicros::new(value.issued_at_unix_micros),
        expires_at: UnixMicros::new(value.expires_at_unix_micros),
        capability_nonce: exact(&value.capability_nonce)?,
        permit_digest: exact(&value.permit_digest)?,
    };
    validate_federated_backup_permit(&permit, now)?;
    Ok(permit)
}

fn decode_request(
    scope: Option<&wire::FederatedBackupScope>,
    operation: Option<&wire::FederatedBackupOperation>,
    now: UnixMicros,
) -> Result<(FederatedBackupScope, FederatedBackupRequest), ContractError> {
    let scope = decode_federated_backup_scope(scope.ok_or(ContractError::InvalidInput)?)?;
    let request = decode_operation(operation.ok_or(ContractError::InvalidInput)?)?;
    request.validate(now)?;
    federated_provider_backup_identity(scope, request.object())?;
    Ok((scope, request))
}

fn encode_operation(request: &FederatedBackupRequest) -> wire::FederatedBackupOperation {
    let (action, reference, retirement) = match request {
        FederatedBackupRequest::Lookup(_) => (wire::RemoteBackupAction::Lookup, "", None),
        FederatedBackupRequest::Store(_) => (wire::RemoteBackupAction::Store, "", None),
        FederatedBackupRequest::Read(value) => (
            wire::RemoteBackupAction::Read,
            value.object_reference.as_str(),
            None,
        ),
        FederatedBackupRequest::Verify(value) => (
            wire::RemoteBackupAction::Verify,
            value.object_reference.as_str(),
            None,
        ),
        FederatedBackupRequest::Delete(value) => (
            wire::RemoteBackupAction::Delete,
            value.object_reference.as_str(),
            Some(value.retirement_revision.get()),
        ),
    };
    let context = request.context();
    wire::FederatedBackupOperation {
        contract_version: Some(wire::ProtocolVersion {
            major: u32::from(context.contract_version.major),
            minor: u32::from(context.contract_version.minor),
        }),
        operation_id: context.operation_id.as_bytes().to_vec(),
        deadline_unix_micros: context.deadline.get(),
        authority_revision: context.expected_revision.map(Revision::get),
        object: Some(wire_object(request.object())),
        action: action.into(),
        object_reference: reference.to_owned(),
        retirement_revision: retirement,
    }
}

fn decode_operation(
    value: &wire::FederatedBackupOperation,
) -> Result<FederatedBackupRequest, ContractError> {
    let version = value
        .contract_version
        .as_ref()
        .ok_or(ContractError::InvalidInput)?;
    if version.major != 1 || version.minor != 0 {
        return Err(ContractError::UnsupportedVersion);
    }
    if value.object_reference.len() > MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES {
        return Err(ContractError::InvalidInput);
    }
    let context = RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes(exact(&value.operation_id)?)
            .map_err(|_| ContractError::InvalidInput)?,
        deadline: UnixMicros::new(value.deadline_unix_micros),
        expected_revision: value.authority_revision.map(Revision::new),
    };
    let object = object(value.object.as_ref().ok_or(ContractError::InvalidInput)?)
        .map_err(|_| ContractError::InvalidInput)?;
    let action = wire::RemoteBackupAction::try_from(value.action)
        .map_err(|_| ContractError::InvalidInput)?;
    let request = match action {
        wire::RemoteBackupAction::Store
            if value.object_reference.is_empty() && value.retirement_revision.is_none() =>
        {
            FederatedBackupRequest::Store(BackupStoreRequest { context, object })
        }
        wire::RemoteBackupAction::Lookup
            if value.object_reference.is_empty() && value.retirement_revision.is_none() =>
        {
            FederatedBackupRequest::Lookup(meshspan_contracts::BackupLookupRequest {
                context,
                object,
            })
        }
        wire::RemoteBackupAction::Read if value.retirement_revision.is_none() => {
            FederatedBackupRequest::Read(BackupReadRequest {
                context,
                object,
                object_reference: BackupObjectReference::new(value.object_reference.clone())?,
            })
        }
        wire::RemoteBackupAction::Verify if value.retirement_revision.is_none() => {
            FederatedBackupRequest::Verify(BackupVerifyRequest {
                context,
                object,
                object_reference: BackupObjectReference::new(value.object_reference.clone())?,
            })
        }
        wire::RemoteBackupAction::Delete => FederatedBackupRequest::Delete(BackupDeleteRequest {
            context,
            object,
            object_reference: BackupObjectReference::new(value.object_reference.clone())?,
            retirement_revision: Revision::new(
                value
                    .retirement_revision
                    .ok_or(ContractError::InvalidInput)?,
            ),
        }),
        _ => return Err(ContractError::InvalidInput),
    };
    Ok(request)
}

fn encode_scope(scope: FederatedBackupScope) -> wire::FederatedBackupScope {
    wire::FederatedBackupScope {
        relationship_id: scope.relationship_id.as_bytes().to_vec(),
        remote_mesh_id: scope.remote_mesh_id.as_bytes().to_vec(),
        provider_mesh_id: scope.provider_mesh_id.as_bytes().to_vec(),
        allocation_id: scope.allocation_id.as_bytes().to_vec(),
        grant_id: scope.grant_id.as_bytes().to_vec(),
        namespace_grant_id: scope.namespace_grant_id.as_bytes().to_vec(),
        provider_node_id: scope.provider_node_id.as_bytes().to_vec(),
        target_id: scope.target_id.as_bytes().to_vec(),
        target_generation: scope.target_generation,
        relationship_authority_epoch: scope.relationship_authority_epoch,
        grant_revision: scope.grant_revision.get(),
        allocation_revision: scope.allocation_revision.get(),
    }
}

/// Parses discovered route identities without granting access or proving object compatibility.
/// Callers still validate the scope against the exact object and current remote authority.
/// # Errors
/// Rejects malformed or missing identifiers.
pub fn decode_federated_backup_scope(
    value: &wire::FederatedBackupScope,
) -> Result<FederatedBackupScope, ContractError> {
    Ok(FederatedBackupScope {
        relationship_id: FederationRelationshipId::from_bytes(exact(&value.relationship_id)?)
            .map_err(|_| ContractError::InvalidInput)?,
        remote_mesh_id: MeshId::from_bytes(exact(&value.remote_mesh_id)?)
            .map_err(|_| ContractError::InvalidInput)?,
        provider_mesh_id: MeshId::from_bytes(exact(&value.provider_mesh_id)?)
            .map_err(|_| ContractError::InvalidInput)?,
        allocation_id: FederationStorageAllocationId::from_bytes(exact(&value.allocation_id)?)
            .map_err(|_| ContractError::InvalidInput)?,
        grant_id: FederationGrantId::from_bytes(exact(&value.grant_id)?)
            .map_err(|_| ContractError::InvalidInput)?,
        namespace_grant_id: FederationGrantId::from_bytes(exact(&value.namespace_grant_id)?)
            .map_err(|_| ContractError::InvalidInput)?,
        provider_node_id: NodeId::from_bytes(exact(&value.provider_node_id)?)
            .map_err(|_| ContractError::InvalidInput)?,
        target_id: TargetId::from_bytes(exact(&value.target_id)?)
            .map_err(|_| ContractError::InvalidInput)?,
        target_generation: value.target_generation,
        relationship_authority_epoch: value.relationship_authority_epoch,
        grant_revision: Revision::new(value.grant_revision),
        allocation_revision: Revision::new(value.allocation_revision),
    })
}

fn exact<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ContractError> {
    bytes.try_into().map_err(|_| ContractError::InvalidInput)
}
