// SPDX-License-Identifier: GPL-2.0-only

//! Backup capability issuance and execution admission through current bilateral metadata.

mod execution;
mod forwarding;
mod relay;
pub use execution::{
    FederationBackupOwnerService, FederationBackupOwnerStreamContext, FederationBackupStreamContext,
};
pub use forwarding::FederationBackupForwardContext;
pub use relay::authorise_forwarded_backup;

use meshspan_contracts::{
    ContractError, FederatedBackupPermit, FederatedBackupRequest, FederatedBackupScope,
    FederatedStoragePermitMacKey, federated_backup_permit_mac, verify_federated_backup_permit_mac,
};
use meshspan_data_plane::{
    decode_federated_backup_permit, decode_federated_backup_request, encode_federated_backup_permit,
};
use meshspan_domain::{NodeId, UnixMicros};
use meshspan_metadata::{AuthoritativeRepository, FederationStorageAllocationAuthority};
use meshspan_protocol::{
    WireLimits,
    v1::{FederatedBackupCapability, federation_envelope::Message},
};
use meshspan_transport::{
    AuthenticatedFederationBackupRequest, FederationLocalIdentity, FederationLocalIdentityBinding,
    OutboundFederationBackupMessage, TransportError, signed_federation_backup_message,
};
use thiserror::Error;

/// Fresh, bounded issuance inputs; capacity is admitted separately before `BackupReady`.
pub struct FederationBackupIssueRequest<'a> {
    /// Signature- and mTLS-authenticated consumer request.
    pub authenticated: &'a AuthenticatedFederationBackupRequest,
    /// Fresh response-envelope nonce.
    pub response_nonce: [u8; 32],
    /// Fresh provider-only capability nonce, distinct from both envelope nonces.
    pub capability_nonce: [u8; 32],
    /// Exclusive expiry, within allocation, request and five-minute bounds.
    pub expires_at: UnixMicros,
    /// Current mesh time used for all authority checks.
    pub observed_at: UnixMicros,
    /// Negotiated framing bounds.
    pub limits: WireLimits,
}

/// Signed capability ready for delivery and its exact provider-side contract.
pub struct IssuedFederationBackupCapability {
    outbound: OutboundFederationBackupMessage,
    permit: FederatedBackupPermit,
}

impl IssuedFederationBackupCapability {
    /// Exact signed wire response. Issuance alone is not a capacity reservation or IO receipt.
    #[must_use]
    pub const fn outbound(&self) -> &OutboundFederationBackupMessage {
        &self.outbound
    }

    /// Provider-key-authenticated exact scope and operation.
    #[must_use]
    pub const fn permit(&self) -> &FederatedBackupPermit {
        &self.permit
    }
}

/// Execution request admitted at one instant, not indefinite authority for a live stream.
pub struct AuthorisedFederatedBackup {
    permit: FederatedBackupPermit,
    authority: FederationStorageAllocationAuthority,
}

impl AuthorisedFederatedBackup {
    /// Exact consumer operation the provider may execute after physical admission.
    #[must_use]
    pub const fn request(&self) -> &FederatedBackupRequest {
        &self.permit.request
    }

    /// Exact namespace/allocation routing boundary.
    #[must_use]
    pub const fn scope(&self) -> FederatedBackupScope {
        self.permit.scope
    }

    /// Current provider metadata evidence for capacity admission.
    #[must_use]
    pub const fn authority(&self) -> FederationStorageAllocationAuthority {
        self.authority
    }

    /// Exact permit needed for bounded-stream revalidation and response binding.
    #[must_use]
    pub const fn permit(&self) -> &FederatedBackupPermit {
        &self.permit
    }
}

/// Composes peer-authenticated requests with metadata authority and a provider-only MAC key.
pub struct FederationBackupCapabilityService<'a, 'identity> {
    repository: &'a AuthoritativeRepository,
    node_id: NodeId,
    identity: &'a FederationLocalIdentity<'identity>,
    permit_key: &'a FederatedStoragePermitMacKey,
}

impl<'a, 'identity> FederationBackupCapabilityService<'a, 'identity> {
    /// Borrows existing authority and keys without exporting or copying secrets.
    #[must_use]
    pub const fn new(
        repository: &'a AuthoritativeRepository,
        node_id: NodeId,
        identity: &'a FederationLocalIdentity<'identity>,
        permit_key: &'a FederatedStoragePermitMacKey,
    ) -> Self {
        Self {
            repository,
            node_id,
            identity,
            permit_key,
        }
    }

    /// Issues a signed exact capability for a local or same-swarm owner under bilateral authority.
    ///
    /// No capacity is held by issuance: execution must reserve against the allocation and
    /// physical folder before sending ready. Losing this response cannot strand a reservation.
    ///
    /// # Errors
    /// Rejects wrong peer/node/scope, revoked authority, invalid lifetimes/nonces or signing failure.
    pub fn issue(
        &self,
        input: &FederationBackupIssueRequest<'_>,
    ) -> Result<IssuedFederationBackupCapability, FederationBackupCapabilityError> {
        let Message::RequestBackupCapability(value) = input.authenticated.message() else {
            return Err(ContractError::InvalidInput.into());
        };
        let (scope, request) = decode_federated_backup_request(value, input.observed_at)?;
        let authority =
            self.gateway_authority(input.authenticated, scope, &request, input.observed_at)?;
        if input.expires_at > authority.valid_until()
            || input.capability_nonce == input.response_nonce
            || input.capability_nonce == input.authenticated.request_replay_nonce()?
        {
            return Err(ContractError::InvalidInput.into());
        }
        let mut permit = FederatedBackupPermit {
            scope,
            request,
            issued_at: input.observed_at,
            expires_at: input.expires_at,
            capability_nonce: input.capability_nonce,
            permit_digest: [0; 32],
        };
        permit.permit_digest = federated_backup_permit_mac(self.permit_key, &permit);
        let message = Message::BackupCapability(FederatedBackupCapability {
            request_digest: input.authenticated.capability_request_digest()?.to_vec(),
            permit: Some(encode_federated_backup_permit(&permit, input.observed_at)?),
            rejection: None,
            signature: Vec::new(),
        });
        let outbound = signed_federation_backup_message(
            self.identity,
            input.authenticated.response_context(input.response_nonce)?,
            message,
            input.limits,
            input.observed_at,
        )?;
        Ok(IssuedFederationBackupCapability { outbound, permit })
    }

    /// Admits an exact signed execution request after MAC, current peer and metadata checks.
    ///
    /// # Errors
    /// Rejects substituted/expired capability, wrong node, stale/revoked grant/allocation or
    /// unavailable metadata. A valid MAC cannot bypass fresh authority, including read/delete.
    pub fn authorise(
        &self,
        authenticated: &AuthenticatedFederationBackupRequest,
        now: UnixMicros,
    ) -> Result<AuthorisedFederatedBackup, FederationBackupCapabilityError> {
        let admitted = self.authorise_gateway(authenticated, now)?;
        if admitted.scope().provider_node_id != self.node_id {
            return Err(ContractError::Unauthorized.into());
        }
        Ok(admitted)
    }

    /// Validates a gateway-owned permit for forwarding to its exact same-swarm storage owner.
    /// This is not authority to execute against a local provider belonging to another node.
    ///
    /// # Errors
    /// Rejects invalid MAC, expired lifetime and stale consumer or bilateral authority.
    pub fn authorise_gateway(
        &self,
        authenticated: &AuthenticatedFederationBackupRequest,
        now: UnixMicros,
    ) -> Result<AuthorisedFederatedBackup, FederationBackupCapabilityError> {
        let Message::ExecuteBackup(value) = authenticated.message() else {
            return Err(ContractError::InvalidInput.into());
        };
        let permit = decode_federated_backup_permit(
            value.permit.as_ref().ok_or(ContractError::InvalidInput)?,
            now,
        )?;
        if !verify_federated_backup_permit_mac(self.permit_key, &permit) {
            return Err(ContractError::Unauthorized.into());
        }
        let authority =
            self.gateway_authority(authenticated, permit.scope, &permit.request, now)?;
        if permit.expires_at > authority.valid_until() {
            return Err(ContractError::Stale.into());
        }
        Ok(AuthorisedFederatedBackup { permit, authority })
    }

    fn gateway_authority(
        &self,
        authenticated: &AuthenticatedFederationBackupRequest,
        scope: FederatedBackupScope,
        request: &FederatedBackupRequest,
        now: UnixMicros,
    ) -> Result<FederationStorageAllocationAuthority, ContractError> {
        let identity = self.identity.binding();
        if scope.provider_mesh_id != identity.local_mesh_id
            || scope.remote_mesh_id != identity.remote_mesh_id
            || scope.relationship_id != identity.relationship_id
            || scope.relationship_authority_epoch != identity.authority_epoch
        {
            return Err(ContractError::Unauthorized);
        }
        let (allocation, current_identity) = self
            .repository
            .with_read_view(|view| {
                current_backup_authority(view, authenticated, scope, request, now)
            })
            .map_err(|_| ContractError::Unavailable)??;
        if current_identity != identity {
            return Err(ContractError::Stale);
        }
        Ok(allocation)
    }
}

fn current_backup_authority(
    repository: &AuthoritativeRepository,
    authenticated: &AuthenticatedFederationBackupRequest,
    scope: FederatedBackupScope,
    request: &FederatedBackupRequest,
    now: UnixMicros,
) -> Result<
    (
        FederationStorageAllocationAuthority,
        FederationLocalIdentityBinding,
    ),
    ContractError,
> {
    if scope.provider_mesh_id != authenticated.local_mesh_id()
        || scope.remote_mesh_id != authenticated.remote_mesh_id()
        || scope.relationship_id != authenticated.relationship_id()
        || scope.relationship_authority_epoch != authenticated.authority_epoch()
    {
        return Err(ContractError::Unauthorized);
    }
    let allocation =
        repository.require_federated_backup_authority(scope, request.object().byte_length, now)?;
    let current = crate::federation_connection_authority(repository, scope.relationship_id, now)
        .map_err(|error| match error {
            crate::FederationAuthorityError::Metadata(_) => ContractError::Unavailable,
            crate::FederationAuthorityError::InvalidProjection
            | crate::FederationAuthorityError::IdentityNotCurrent => ContractError::Unauthorized,
        })?
        .ok_or(ContractError::Unauthorized)?;
    if current.peer != authenticated.peer_binding() {
        return Err(ContractError::Stale);
    }
    Ok((allocation, current.local_identity))
}

/// Admission failure, with no implied successful provider IO.
#[derive(Debug, Error)]
pub enum FederationBackupCapabilityError {
    /// Exact request or current metadata authority rejected admission.
    #[error("federated backup capability rejected")]
    Contract(#[from] ContractError),
    /// Signed correlation or transport construction failed.
    #[error("federated backup capability transport failed")]
    Transport(#[from] TransportError),
}
