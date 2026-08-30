// SPDX-License-Identifier: GPL-2.0-only

//! Composition of authenticated bilateral authority into one provider-local shard permit.

use meshspan_contracts::{
    FederatedShardPermit, FederatedStoragePermitMacKey, ShardIdentity, federated_shard_permit_mac,
};
use meshspan_data_plane::encode_federated_shard_permit;
use meshspan_domain::{
    FederationGrantId, FederationStorageAction, FederationStorageAllocationId, TargetId, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeRepository, FederationStorageAuthorityRequest,
    FederationStorageCapabilityLedgerError, FederationStorageCapabilityPresentation,
    FederationStorageQuotaDisposition, FederationStorageQuotaError,
    FederationStorageWriteReservation, FederationStorageWriteReservationRequest,
    FederationStorageWriteState, LocalDatabase, MAXIMUM_FEDERATED_STORAGE_WRITE_LIFETIME_MICROS,
    RepositoryError,
};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::{
    FederatedStorageCapability, RemoteShardAction, RequestFederatedStorageCapability,
};
use meshspan_transport::{
    AuthenticatedFederationStorageCapabilityRequest, FederationExchangeContext,
    FederationLocalIdentity, OutboundFederationStorageCapability, TransportError,
    signed_federation_storage_capability,
};
use thiserror::Error;

/// Fresh non-authoritative inputs used to issue one exact capability response.
#[derive(Clone, Copy, Debug)]
pub struct FederationStorageCapabilityIssueRequest<'a> {
    /// Request whose mTLS identity, signature, relationship and replay nonce already passed.
    pub authenticated: &'a AuthenticatedFederationStorageCapabilityRequest,
    /// Fresh response-envelope nonce.
    pub response_replay_nonce: [u8; 32],
    /// Fresh opaque data-plane capability nonce.
    pub capability_nonce: [u8; 32],
    /// Exclusive capability expiry selected within every authority bound.
    pub valid_until: UnixMicros,
    /// Current quorum-derived mesh time used for every authority decision.
    pub observed_at: UnixMicros,
    /// Negotiated federation framing limits.
    pub limits: WireLimits,
}

/// Signed response plus the exact provider-only permit and quota transition outcome.
pub struct IssuedFederationStorageCapability {
    outbound: OutboundFederationStorageCapability,
    permit: FederatedShardPermit,
    quota_disposition: Option<FederationStorageQuotaDisposition>,
}

impl IssuedFederationStorageCapability {
    /// Returns the signed bounded federation response.
    #[must_use]
    pub const fn outbound(&self) -> &OutboundFederationStorageCapability {
        &self.outbound
    }

    /// Returns the exact opaque permit encoded into the response.
    #[must_use]
    pub const fn permit(&self) -> &FederatedShardPermit {
        &self.permit
    }

    /// Returns the local capacity transition for put/repair, or `None` for non-capacity actions.
    #[must_use]
    pub const fn quota_disposition(&self) -> Option<FederationStorageQuotaDisposition> {
        self.quota_disposition
    }
}

/// Provider-side issuer which composes replicated authority, local quota and private key material.
pub struct FederationStorageCapabilityIssuer<'a, 'identity> {
    repository: &'a AuthoritativeRepository,
    local_database: &'a mut LocalDatabase,
    local_identity: &'a FederationLocalIdentity<'identity>,
    permit_key: &'a FederatedStoragePermitMacKey,
}

impl<'a, 'identity> FederationStorageCapabilityIssuer<'a, 'identity> {
    /// Creates an issuer without copying or exposing either signing key.
    #[must_use]
    pub const fn new(
        repository: &'a AuthoritativeRepository,
        local_database: &'a mut LocalDatabase,
        local_identity: &'a FederationLocalIdentity<'identity>,
        permit_key: &'a FederatedStoragePermitMacKey,
    ) -> Self {
        Self {
            repository,
            local_database,
            local_identity,
            permit_key,
        }
    }

    /// Revalidates current bilateral authority, signs the exact permit and atomically holds quota.
    ///
    /// Signing occurs before the local reservation transaction, so local construction failure
    /// cannot strand quota. Network delivery occurs after this method and exact retries reuse the
    /// durable reservation.
    ///
    /// # Errors
    ///
    /// Rejects malformed or reflected inputs, stale/revoked/substituted authority, forbidden
    /// ordinary reads, exhausted local allocation quota, signing and persistence failure.
    pub fn issue(
        &mut self,
        request: FederationStorageCapabilityIssueRequest<'_>,
    ) -> Result<IssuedFederationStorageCapability, FederationStorageCapabilityIssuerError> {
        let admitted = AdmittedRequest::from_authenticated(request.authenticated)?;
        let response_context = request
            .authenticated
            .response_context(request.response_replay_nonce)?;
        self.issue_admitted(IssueParameters::from(request), admitted, response_context)
    }

    fn issue_admitted(
        &mut self,
        request: IssueParameters,
        admitted: AdmittedRequest<'_>,
        response_context: FederationExchangeContext,
    ) -> Result<IssuedFederationStorageCapability, FederationStorageCapabilityIssuerError> {
        let parsed = ParsedRequest::new(request, admitted)?;
        let authority = self
            .repository
            .active_federation_storage_allocation_authority(parsed.authority_request(
                admitted.relationship_id,
                admitted.remote_mesh_id,
                self.local_database.node_id(),
                request.observed_at,
            ))?
            .ok_or(FederationStorageCapabilityIssuerError::AuthorityUnavailable)?;
        let prior_reservation = if parsed.action.reserves_capacity() {
            self.local_database
                .federated_storage_write(admitted.operation_id)?
        } else {
            None
        };
        let prior_presentation = self
            .local_database
            .federated_storage_capability_for_operation(admitted.operation_id)?;
        let issuance = PermitIssuance::select(
            parsed,
            request,
            admitted,
            prior_reservation.as_ref(),
            prior_presentation.as_ref(),
        )?;
        parsed.validate_authority(
            authority,
            self.local_identity,
            issuance.expires_at(),
            request.observed_at,
        )?;
        let mut permit = parsed.permit(
            authority,
            self.local_identity,
            self.local_database.node_id(),
            admitted,
            issuance,
        );
        permit.permit_digest = federated_shard_permit_mac(self.permit_key, &permit);
        issuance.validate_permit(&permit)?;
        let outbound = signed_federation_storage_capability(
            self.local_identity,
            response_context,
            parsed.wire_capability(&permit),
            request.limits,
            request.observed_at,
        )?;
        let quota_disposition = if permit.action.reserves_capacity() {
            if issuance.is_replay() {
                Some(FederationStorageQuotaDisposition::Replayed)
            } else {
                Some(
                    self.local_database
                        .reserve_federated_storage_write(
                            authority,
                            FederationStorageWriteReservationRequest {
                                operation_id: permit.operation_id,
                                request_digest: permit.request_digest,
                                capability_nonce: permit.capability_nonce,
                                shard: permit.shard,
                                action: permit.action,
                                permit_digest: permit.permit_digest,
                                expires_at: permit.expires_at,
                                issued_at: permit.issued_at,
                            },
                        )?
                        .0,
                )
            }
        } else {
            None
        };
        self.local_database.record_federated_storage_capability(
            &FederationStorageCapabilityPresentation {
                capability_digest: outbound.capability_digest(),
                permit,
                protocol_major: response_context.version.major,
                protocol_minor: response_context.version.minor,
                request_id: response_context.request_id,
                trace_id: response_context.trace_id,
                request_deadline: response_context.deadline,
                response_replay_nonce: response_context.replay_nonce,
                recorded_at: request.observed_at,
            },
        )?;
        Ok(IssuedFederationStorageCapability {
            outbound,
            permit,
            quota_disposition,
        })
    }
}

#[derive(Clone, Copy)]
struct IssueParameters {
    response_replay_nonce: [u8; 32],
    capability_nonce: [u8; 32],
    valid_until: UnixMicros,
    observed_at: UnixMicros,
    limits: WireLimits,
}

impl From<FederationStorageCapabilityIssueRequest<'_>> for IssueParameters {
    fn from(request: FederationStorageCapabilityIssueRequest<'_>) -> Self {
        Self {
            response_replay_nonce: request.response_replay_nonce,
            capability_nonce: request.capability_nonce,
            valid_until: request.valid_until,
            observed_at: request.observed_at,
            limits: request.limits,
        }
    }
}

#[derive(Clone, Copy)]
struct AdmittedRequest<'a> {
    relationship_id: meshspan_domain::FederationRelationshipId,
    remote_mesh_id: meshspan_domain::MeshId,
    operation_id: meshspan_domain::OperationId,
    request_digest: [u8; 32],
    request_replay_nonce: [u8; 32],
    request: &'a RequestFederatedStorageCapability,
}

impl<'a> AdmittedRequest<'a> {
    fn from_authenticated(
        request: &'a AuthenticatedFederationStorageCapabilityRequest,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            relationship_id: request.relationship_id(),
            remote_mesh_id: request.remote_mesh_id(),
            operation_id: request.operation_id(),
            request_digest: request.request_digest(),
            request_replay_nonce: request.request_replay_nonce()?,
            request: request.request(),
        })
    }
}

#[derive(Clone, Copy)]
struct ParsedRequest {
    allocation_id: FederationStorageAllocationId,
    grant_id: FederationGrantId,
    target_id: TargetId,
    target_generation: u64,
    shard: ShardIdentity,
    action: FederationStorageAction,
    maximum_bytes: u64,
    scope_digest: [u8; 32],
}

impl ParsedRequest {
    fn new(
        issue: IssueParameters,
        admitted: AdmittedRequest<'_>,
    ) -> Result<Self, FederationStorageCapabilityIssuerError> {
        let request = admitted.request;
        let parsed = Self {
            allocation_id: FederationStorageAllocationId::from_bytes(identifier_bytes(
                &request.allocation_id,
            )?)
            .map_err(|_| FederationStorageCapabilityIssuerError::InvalidRequest)?,
            grant_id: FederationGrantId::from_bytes(identifier_bytes(&request.grant_id)?)
                .map_err(|_| FederationStorageCapabilityIssuerError::InvalidRequest)?,
            target_id: TargetId::from_bytes(identifier_bytes(&request.target_id)?)
                .map_err(|_| FederationStorageCapabilityIssuerError::InvalidRequest)?,
            target_generation: request.target_generation,
            shard: shard(request.shard.as_ref())?,
            action: action(request.action)?,
            maximum_bytes: request.maximum_bytes,
            scope_digest: digest(&request.scope_digest)?,
        };
        let maximum_lifetime = i64::try_from(MAXIMUM_FEDERATED_STORAGE_WRITE_LIFETIME_MICROS)
            .map_err(|_| FederationStorageCapabilityIssuerError::InvalidRequest)?;
        let lifetime = issue.valid_until.get().checked_sub(issue.observed_at.get());
        let valid = issue.capability_nonce != [0; 32]
            && issue.capability_nonce != issue.response_replay_nonce
            && issue.capability_nonce != admitted.request_replay_nonce
            && parsed.maximum_bytes > 0
            && lifetime.is_some_and(|value| value > 0 && value <= maximum_lifetime);
        if valid {
            Ok(parsed)
        } else {
            Err(FederationStorageCapabilityIssuerError::InvalidRequest)
        }
    }

    const fn authority_request(
        self,
        relationship_id: meshspan_domain::FederationRelationshipId,
        remote_mesh_id: meshspan_domain::MeshId,
        provider_node_id: meshspan_domain::NodeId,
        observed_at: UnixMicros,
    ) -> FederationStorageAuthorityRequest {
        FederationStorageAuthorityRequest {
            relationship_id,
            remote_mesh_id,
            provider_node_id,
            allocation_id: self.allocation_id,
            grant_id: self.grant_id,
            target_id: self.target_id,
            target_generation: self.target_generation,
            requested_bytes: self.maximum_bytes,
            observed_at,
        }
    }

    fn validate_authority(
        self,
        authority: meshspan_metadata::FederationStorageAllocationAuthority,
        identity: &FederationLocalIdentity<'_>,
        valid_until: UnixMicros,
        observed_at: UnixMicros,
    ) -> Result<(), FederationStorageCapabilityIssuerError> {
        let binding = identity.binding();
        let valid = authority.relationship_id() == binding.relationship_id
            && authority.provider_mesh_id() == binding.local_mesh_id
            && authority.remote_mesh_id() == binding.remote_mesh_id
            && authority.relationship_authority_epoch() == binding.authority_epoch
            && authority.observed_at() == observed_at
            && valid_until <= authority.allocation().valid_until()
            && (self.action != FederationStorageAction::Get
                || authority.participation().serves_reads());
        if valid {
            Ok(())
        } else {
            Err(FederationStorageCapabilityIssuerError::AuthorityUnavailable)
        }
    }

    fn permit(
        self,
        authority: meshspan_metadata::FederationStorageAllocationAuthority,
        identity: &FederationLocalIdentity<'_>,
        provider_node_id: meshspan_domain::NodeId,
        admitted: AdmittedRequest<'_>,
        issuance: PermitIssuance,
    ) -> FederatedShardPermit {
        let binding = identity.binding();
        FederatedShardPermit {
            operation_id: admitted.operation_id,
            relationship_id: binding.relationship_id,
            remote_mesh_id: binding.remote_mesh_id,
            provider_mesh_id: binding.local_mesh_id,
            allocation_id: self.allocation_id,
            grant_id: self.grant_id,
            provider_node_id,
            target_id: self.target_id,
            target_generation: self.target_generation,
            shard: self.shard,
            action: self.action,
            maximum_bytes: authority.requested_bytes(),
            relationship_authority_epoch: authority.relationship_authority_epoch(),
            grant_revision: authority.grant_revision(),
            allocation_revision: authority.allocation_revision(),
            issued_at: issuance.issued_at(),
            expires_at: issuance.expires_at(),
            capability_nonce: issuance.capability_nonce(),
            scope_digest: self.scope_digest,
            request_digest: admitted.request_digest,
            permit_digest: [0; 32],
        }
    }

    fn wire_capability(self, permit: &FederatedShardPermit) -> FederatedStorageCapability {
        FederatedStorageCapability {
            grant_id: self.grant_id.as_bytes().to_vec(),
            target_id: self.target_id.as_bytes().to_vec(),
            target_generation: self.target_generation,
            shard: Some(wire_shard(self.shard)),
            action: wire_action(self.action).into(),
            maximum_bytes: self.maximum_bytes,
            valid_until_unix_micros: permit.expires_at.get(),
            capability_nonce: permit.capability_nonce.to_vec(),
            canonical_capability: encode_federated_shard_permit(*permit),
            signature: Vec::new(),
            allocation_id: self.allocation_id.as_bytes().to_vec(),
            issued_at_unix_micros: permit.issued_at.get(),
        }
    }
}

#[derive(Clone, Copy)]
struct PermitIssuance {
    capability_nonce: [u8; 32],
    issued_at: UnixMicros,
    expires_at: UnixMicros,
    replayed_permit_digest: Option<[u8; 32]>,
}

impl PermitIssuance {
    fn select(
        parsed: ParsedRequest,
        issue: IssueParameters,
        admitted: AdmittedRequest<'_>,
        prior_reservation: Option<&FederationStorageWriteReservation>,
        prior_presentation: Option<&FederationStorageCapabilityPresentation>,
    ) -> Result<Self, FederationStorageCapabilityIssuerError> {
        if let Some(presentation) = prior_presentation {
            return Self::from_presentation(parsed, issue, admitted, presentation);
        }
        let Some(prior) = prior_reservation else {
            return Ok(Self {
                capability_nonce: issue.capability_nonce,
                issued_at: issue.observed_at,
                expires_at: issue.valid_until,
                replayed_permit_digest: None,
            });
        };
        let valid = prior.allocation_id == parsed.allocation_id
            && prior.request_digest == admitted.request_digest
            && prior.shard == parsed.shard
            && prior.action == parsed.action
            && prior.maximum_bytes == parsed.maximum_bytes
            && prior.expires_at > issue.observed_at
            && prior.state != FederationStorageWriteState::Released
            && prior.capability_nonce != admitted.request_replay_nonce
            && prior.capability_nonce != issue.response_replay_nonce;
        if valid {
            Ok(Self {
                capability_nonce: prior.capability_nonce,
                issued_at: prior.issued_at,
                expires_at: prior.expires_at,
                replayed_permit_digest: Some(prior.permit_digest),
            })
        } else {
            Err(FederationStorageCapabilityIssuerError::InvalidRequest)
        }
    }

    fn from_presentation(
        parsed: ParsedRequest,
        issue: IssueParameters,
        admitted: AdmittedRequest<'_>,
        presentation: &FederationStorageCapabilityPresentation,
    ) -> Result<Self, FederationStorageCapabilityIssuerError> {
        let permit = presentation.permit;
        let valid = permit.operation_id == admitted.operation_id
            && permit.relationship_id == admitted.relationship_id
            && permit.remote_mesh_id == admitted.remote_mesh_id
            && permit.allocation_id == parsed.allocation_id
            && permit.grant_id == parsed.grant_id
            && permit.target_id == parsed.target_id
            && permit.target_generation == parsed.target_generation
            && permit.shard == parsed.shard
            && permit.action == parsed.action
            && permit.maximum_bytes == parsed.maximum_bytes
            && permit.scope_digest == parsed.scope_digest
            && permit.request_digest == admitted.request_digest
            && permit.expires_at > issue.observed_at;
        if valid {
            Ok(Self {
                capability_nonce: permit.capability_nonce,
                issued_at: permit.issued_at,
                expires_at: permit.expires_at,
                replayed_permit_digest: Some(permit.permit_digest),
            })
        } else {
            Err(FederationStorageCapabilityIssuerError::InvalidRequest)
        }
    }

    const fn capability_nonce(self) -> [u8; 32] {
        self.capability_nonce
    }

    const fn issued_at(self) -> UnixMicros {
        self.issued_at
    }

    const fn expires_at(self) -> UnixMicros {
        self.expires_at
    }

    const fn is_replay(self) -> bool {
        self.replayed_permit_digest.is_some()
    }

    fn validate_permit(
        self,
        permit: &FederatedShardPermit,
    ) -> Result<(), FederationStorageCapabilityIssuerError> {
        if self
            .replayed_permit_digest
            .is_some_and(|digest| digest != permit.permit_digest)
        {
            return Err(FederationStorageCapabilityIssuerError::AuthorityUnavailable);
        }
        Ok(())
    }
}

fn identifier_bytes(bytes: &[u8]) -> Result<[u8; 16], FederationStorageCapabilityIssuerError> {
    bytes
        .try_into()
        .map_err(|_| FederationStorageCapabilityIssuerError::InvalidRequest)
}

fn shard(
    value: Option<&meshspan_protocol::v1::ShardIdentity>,
) -> Result<ShardIdentity, FederationStorageCapabilityIssuerError> {
    let value = value.ok_or(FederationStorageCapabilityIssuerError::InvalidRequest)?;
    let shard = ShardIdentity {
        manifest_digest: digest(&value.manifest_digest)?,
        stripe_index: value.stripe_index,
        shard_index: u16::try_from(value.shard_index)
            .map_err(|_| FederationStorageCapabilityIssuerError::InvalidRequest)?,
        generation: value.generation,
    };
    if shard.generation == 0 {
        Err(FederationStorageCapabilityIssuerError::InvalidRequest)
    } else {
        Ok(shard)
    }
}

fn digest(bytes: &[u8]) -> Result<[u8; 32], FederationStorageCapabilityIssuerError> {
    let value = bytes
        .try_into()
        .map_err(|_| FederationStorageCapabilityIssuerError::InvalidRequest)?;
    if value == [0; 32] {
        Err(FederationStorageCapabilityIssuerError::InvalidRequest)
    } else {
        Ok(value)
    }
}

fn action(value: i32) -> Result<FederationStorageAction, FederationStorageCapabilityIssuerError> {
    let action = RemoteShardAction::try_from(value)
        .map_err(|_| FederationStorageCapabilityIssuerError::InvalidRequest)?;
    match action {
        RemoteShardAction::Put => Ok(FederationStorageAction::Put),
        RemoteShardAction::Get => Ok(FederationStorageAction::Get),
        RemoteShardAction::Scrub => Ok(FederationStorageAction::Scrub),
        RemoteShardAction::Repair => Ok(FederationStorageAction::Repair),
        RemoteShardAction::Retire => Ok(FederationStorageAction::Retire),
        RemoteShardAction::Reclaim => Ok(FederationStorageAction::Reclaim),
        RemoteShardAction::Unspecified => {
            Err(FederationStorageCapabilityIssuerError::InvalidRequest)
        }
    }
}

const fn wire_action(action: FederationStorageAction) -> RemoteShardAction {
    match action {
        FederationStorageAction::Put => RemoteShardAction::Put,
        FederationStorageAction::Get => RemoteShardAction::Get,
        FederationStorageAction::Scrub => RemoteShardAction::Scrub,
        FederationStorageAction::Repair => RemoteShardAction::Repair,
        FederationStorageAction::Retire => RemoteShardAction::Retire,
        FederationStorageAction::Reclaim => RemoteShardAction::Reclaim,
    }
}

fn wire_shard(shard: ShardIdentity) -> meshspan_protocol::v1::ShardIdentity {
    meshspan_protocol::v1::ShardIdentity {
        manifest_digest: shard.manifest_digest.to_vec(),
        stripe_index: shard.stripe_index,
        shard_index: u32::from(shard.shard_index),
        generation: shard.generation,
    }
}

/// Fail-closed capability issuance errors without remote-controlled payload detail.
#[derive(Debug, Error)]
pub enum FederationStorageCapabilityIssuerError {
    /// Structurally admitted input still failed typed/cross-field validation.
    #[error("federated storage capability request is invalid")]
    InvalidRequest,
    /// Current replicated relationship, grant, allocation or read policy withheld authority.
    #[error("federated storage capability authority is unavailable")]
    AuthorityUnavailable,
    /// Authoritative metadata could not be read consistently.
    #[error("federated storage capability metadata failed")]
    Metadata(#[from] RepositoryError),
    /// Node-local allocation accounting rejected or could not persist the reservation.
    #[error("federated storage capability quota failed")]
    Quota(#[from] FederationStorageQuotaError),
    /// Durable signed-capability correlation could not be recorded safely.
    #[error("federated storage capability ledger failed")]
    CapabilityLedger(#[from] FederationStorageCapabilityLedgerError),
    /// Signed bounded response construction failed.
    #[error("federated storage capability transport failed")]
    Transport(#[from] TransportError),
}

#[cfg(test)]
mod tests;
