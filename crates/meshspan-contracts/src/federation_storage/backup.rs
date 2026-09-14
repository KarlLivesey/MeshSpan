// SPDX-License-Identifier: GPL-2.0-only

//! Exact backup-object capabilities for the federated provider and its quota issuer.

use meshspan_domain::{
    BackupDestinationId, FederationGrantId, FederationRelationshipId,
    FederationStorageAllocationId, MeshId, NodeId, Revision, TargetId, UnixMicros, uuid_v8,
};

use super::FederatedStoragePermitMacKey;
use crate::{
    BackupDeleteRequest, BackupObjectIdentity, BackupReadRequest, BackupStoreRequest,
    BackupVerifyRequest, ContractError, RequestContext, validate_backup_delete_request,
    validate_backup_read_request, validate_backup_store_request, validate_backup_verify_request,
};

/// Maximum capability lifetime; expiry never proves that reserved bytes are absent.
pub const MAXIMUM_FEDERATED_BACKUP_PERMIT_LIFETIME_MICROS: i64 = 300_000_000;

/// Current bilateral allocation dimensions, independent of the consumer's backup catalogue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederatedBackupScope {
    /// Mutually approved relationship carrying this capability.
    pub relationship_id: FederationRelationshipId,
    /// Authenticated consumer swarm which owns the encrypted backup.
    pub remote_mesh_id: MeshId,
    /// Swarm issuing and executing this capability.
    pub provider_mesh_id: MeshId,
    /// Disjoint capacity allocation shared with any shard workload using this allocation.
    pub allocation_id: FederationStorageAllocationId,
    /// Current bilateral storage permission, including explicit successors.
    pub grant_id: FederationGrantId,
    /// Immutable originating grant of the allocation; names bytes, never grants permission.
    pub namespace_grant_id: FederationGrantId,
    /// Sole provider node permitted to execute this capability.
    pub provider_node_id: NodeId,
    /// Exact physical storage target; not itself read or deletion authority.
    pub target_id: TargetId,
    /// Current target incarnation.
    pub target_generation: u64,
    /// Relationship authority epoch fencing older capabilities.
    pub relationship_authority_epoch: u64,
    /// Current effective storage-grant revision.
    pub grant_revision: Revision,
    /// Current immutable allocation revision.
    pub allocation_revision: Revision,
}

/// Exactly one existing backup-provider operation, without a fabricated shard identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FederatedBackupRequest {
    /// Recover exact retained provider evidence without the original opaque reference.
    Lookup(crate::BackupLookupRequest),
    /// Store exactly the declared encrypted container.
    Store(BackupStoreRequest),
    /// Read the exact retained encrypted object.
    Read(BackupReadRequest),
    /// Independently verify the exact retained encrypted object.
    Verify(BackupVerifyRequest),
    /// Delete only the exact object at its positive retirement revision.
    Delete(BackupDeleteRequest),
}

impl FederatedBackupRequest {
    /// Returns the operation, consumer catalogue revision and attempt deadline.
    #[must_use]
    pub const fn context(&self) -> RequestContext {
        match self {
            Self::Lookup(value) => value.context,
            Self::Store(value) => value.context,
            Self::Read(value) => value.context,
            Self::Verify(value) => value.context,
            Self::Delete(value) => value.context,
        }
    }

    /// Returns the immutable encrypted container named by this operation.
    #[must_use]
    pub const fn object(&self) -> BackupObjectIdentity {
        match self {
            Self::Lookup(value) => value.object,
            Self::Store(value) => value.object,
            Self::Read(value) => value.object,
            Self::Verify(value) => value.object,
            Self::Delete(value) => value.object,
        }
    }

    /// Checks the existing provider contract; this does not establish federation authority.
    ///
    /// # Errors
    /// Rejects malformed identity, unsupported version, elapsed deadline or invalid retirement.
    pub fn validate(&self, now: UnixMicros) -> Result<(), ContractError> {
        match self {
            Self::Lookup(value) => crate::validate_backup_lookup_request(value, now),
            Self::Store(value) => validate_backup_store_request(*value, now),
            Self::Read(value) => validate_backup_read_request(value, now),
            Self::Verify(value) => validate_backup_verify_request(value, now),
            Self::Delete(value) => validate_backup_delete_request(value, now),
        }
    }
}

/// Short-lived provider-issued authority for one complete backup operation.
///
/// The receiver must additionally revalidate the authenticated swarm and current relationship,
/// grant, allocation and target. Neither a valid MAC nor a consumer catalogue revision proves
/// those provider-side permissions. The provider never receives decryption keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederatedBackupPermit {
    /// Exact bilateral provider authority selected at issuance.
    pub scope: FederatedBackupScope,
    /// Complete operation, including locator and retirement revision when applicable.
    pub request: FederatedBackupRequest,
    /// Inclusive issuance instant in mesh time.
    pub issued_at: UnixMicros,
    /// Exclusive expiry, no later than the request's deadline.
    pub expires_at: UnixMicros,
    /// Nonzero provider-issued nonce retained for exact retries.
    pub capability_nonce: [u8; 32],
    /// Domain-separated keyed digest; not an external swarm signature.
    pub permit_digest: [u8; 32],
}

/// Validates shape, request semantics and the bounded capability interval.
///
/// # Errors
/// Rejects reflected swarms, sentinel fences, invalid requests or expired/future capabilities.
/// Callers still verify the MAC and fresh bilateral authority before any provider IO.
pub fn validate_federated_backup_permit(
    permit: &FederatedBackupPermit,
    now: UnixMicros,
) -> Result<(), ContractError> {
    validate_scope(permit.scope)?;
    permit.request.validate(now)?;
    let lifetime = permit.expires_at.get().checked_sub(permit.issued_at.get());
    if permit.issued_at.get() <= 0
        || lifetime.is_none_or(|value| {
            !(1..=MAXIMUM_FEDERATED_BACKUP_PERMIT_LIFETIME_MICROS).contains(&value)
        })
        || permit.expires_at > permit.request.context().deadline
        || permit.capability_nonce == [0; 32]
        || permit.permit_digest == [0; 32]
    {
        return Err(ContractError::InvalidInput);
    }
    if now < permit.issued_at || now >= permit.expires_at {
        return Err(ContractError::DeadlineExceeded);
    }
    Ok(())
}

/// Computes an exact operation digest for signing and durable replay admission.
#[must_use]
pub fn federated_backup_request_digest(
    scope: FederatedBackupScope,
    request: &FederatedBackupRequest,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.federation.backup-request.v1");
    hash_scope(&mut digest, scope);
    hash_request(&mut digest, request);
    digest.finalize().into()
}

/// Computes the provider-only MAC, excluding the existing `permit_digest` value.
#[must_use]
pub fn federated_backup_permit_mac(
    key: &FederatedStoragePermitMacKey,
    permit: &FederatedBackupPermit,
) -> [u8; 32] {
    let mut mac = blake3::Hasher::new_keyed(&key.0);
    mac.update(b"meshspan.federation.backup-permit.v1");
    mac.update(&federated_backup_request_digest(
        permit.scope,
        &permit.request,
    ));
    mac.update(&permit.issued_at.get().to_be_bytes());
    mac.update(&permit.expires_at.get().to_be_bytes());
    mac.update(&permit.capability_nonce);
    mac.finalize().into()
}

/// Checks the exact backup MAC using BLAKE3's constant-time hash comparison.
#[must_use]
pub fn verify_federated_backup_permit_mac(
    key: &FederatedStoragePermitMacKey,
    permit: &FederatedBackupPermit,
) -> bool {
    blake3::Hash::from_bytes(federated_backup_permit_mac(key, permit))
        == blake3::Hash::from_bytes(permit.permit_digest)
}

/// Derives a tenant/allocation-isolated provider identity from a logical backup object.
///
/// Provider IO uses this identity; federation requests/receipts retain the logical one.
/// Permission epochs do not rename stored bytes. Changing the payload under an existing backup
/// ID remains a provider-catalogue conflict, rather than silently choosing a different location.
///
/// # Errors
/// Rejects invalid scope or malformed object identity before constructing a provider locator.
pub fn federated_provider_backup_identity(
    scope: FederatedBackupScope,
    object: BackupObjectIdentity,
) -> Result<BackupObjectIdentity, ContractError> {
    validate_scope(scope)?;
    if object.provider_generation == 0 || object.byte_length == 0 || object.digest == [0; 32] {
        return Err(ContractError::InvalidInput);
    }
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.federation.provider-backup-namespace.v1");
    digest.update(&scope.relationship_id.as_bytes());
    digest.update(&scope.remote_mesh_id.as_bytes());
    digest.update(&scope.provider_mesh_id.as_bytes());
    digest.update(&scope.allocation_id.as_bytes());
    digest.update(&scope.namespace_grant_id.as_bytes());
    digest.update(&scope.provider_node_id.as_bytes());
    digest.update(&scope.target_id.as_bytes());
    digest.update(&scope.target_generation.to_be_bytes());
    digest.update(&object.destination_id.as_bytes());
    digest.update(&object.provider_generation.to_be_bytes());
    let identifier = uuid_v8(
        digest.finalize().as_bytes()[..16]
            .try_into()
            .map_err(|_| ContractError::InternalContract)?,
    );
    Ok(BackupObjectIdentity {
        destination_id: BackupDestinationId::from_bytes(identifier)
            .map_err(|_| ContractError::InternalContract)?,
        provider_generation: scope.target_generation,
        ..object
    })
}

fn validate_scope(scope: FederatedBackupScope) -> Result<(), ContractError> {
    if scope.remote_mesh_id == scope.provider_mesh_id
        || scope.target_generation == 0
        || scope.relationship_authority_epoch == 0
        || scope.grant_revision == Revision::ZERO
        || scope.allocation_revision == Revision::ZERO
    {
        Err(ContractError::InvalidInput)
    } else {
        Ok(())
    }
}

fn hash_scope(digest: &mut blake3::Hasher, scope: FederatedBackupScope) {
    digest.update(&scope.relationship_id.as_bytes());
    digest.update(&scope.remote_mesh_id.as_bytes());
    digest.update(&scope.provider_mesh_id.as_bytes());
    digest.update(&scope.allocation_id.as_bytes());
    digest.update(&scope.grant_id.as_bytes());
    digest.update(&scope.namespace_grant_id.as_bytes());
    digest.update(&scope.provider_node_id.as_bytes());
    digest.update(&scope.target_id.as_bytes());
    digest.update(&scope.target_generation.to_be_bytes());
    digest.update(&scope.relationship_authority_epoch.to_be_bytes());
    digest.update(&scope.grant_revision.get().to_be_bytes());
    digest.update(&scope.allocation_revision.get().to_be_bytes());
}

fn hash_request(digest: &mut blake3::Hasher, request: &FederatedBackupRequest) {
    let (action, reference, retirement) = match request {
        FederatedBackupRequest::Lookup(_) => (5, "", 0),
        FederatedBackupRequest::Store(_) => (1, "", 0),
        FederatedBackupRequest::Read(value) => (2, value.object_reference.as_str(), 0),
        FederatedBackupRequest::Verify(value) => (3, value.object_reference.as_str(), 0),
        FederatedBackupRequest::Delete(value) => (
            4,
            value.object_reference.as_str(),
            value.retirement_revision.get(),
        ),
    };
    let context = request.context();
    let object = request.object();
    digest.update(&[action]);
    digest.update(&context.operation_id.as_bytes());
    digest.update(&context.contract_version.major.to_be_bytes());
    digest.update(&context.contract_version.minor.to_be_bytes());
    digest.update(&context.deadline.get().to_be_bytes());
    // Presence is explicit even though the provider currently requires a positive revision.
    digest.update(&[u8::from(context.expected_revision.is_some())]);
    digest.update(
        &context
            .expected_revision
            .map_or(0, Revision::get)
            .to_be_bytes(),
    );
    digest.update(&object.backup_id.as_bytes());
    digest.update(&object.destination_id.as_bytes());
    digest.update(&object.provider_generation.to_be_bytes());
    digest.update(&object.byte_length.to_be_bytes());
    digest.update(&object.digest);
    digest.update(&(reference.len() as u64).to_be_bytes());
    digest.update(reference.as_bytes());
    digest.update(&retirement.to_be_bytes());
}

#[cfg(test)]
mod tests;
