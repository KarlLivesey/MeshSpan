// SPDX-License-Identifier: GPL-2.0-only

//! Federated-swarm authority adapter for the shared provider shard state machine.

use meshspan_contracts::{
    ContractError, FederatedShardPermit, FederatedStoragePermitMacKey, ReservationClass,
    ShardReadPermit, ShardReceipt, StorageProvider, federated_shard_read_result_digest,
    read_permit_mac, verify_federated_shard_permit_mac,
};
use meshspan_domain::{FederationStorageAction, UnixMicros};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{GetShardRequest, PutShardBegin};
use meshspan_transport::{
    AcceptedStream, AuthenticatedFederationPeer, StreamKind, receive_data_control,
};

use super::{PreparedPut, RemoteShardService, reject_get, reject_put};
use crate::DataPlaneError;
use crate::capability::decode_federated_shard_permit;
use crate::wire::{request_context, shard};

/// Exact durable result which must receive a provider-swarm signature before acknowledgement.
#[derive(Clone, Copy)]
pub struct FederatedShardOutcome {
    permit: FederatedShardPermit,
    capability_digest: [u8; 32],
    affected_bytes: u64,
    result_digest: [u8; 32],
    completed_at: UnixMicros,
}

/// Exact durable write evidence retained by provider-local accounting across retries.
#[derive(Clone, Copy)]
pub struct FederatedWriteEvidence {
    completed_at: UnixMicros,
    result_digest: [u8; 32],
}

impl FederatedWriteEvidence {
    /// Constructs validated durable evidence loaded from the provider operation ledger.
    ///
    /// # Errors
    ///
    /// Rejects a non-positive completion instant or empty result digest.
    pub fn new(completed_at: UnixMicros, result_digest: [u8; 32]) -> Result<Self, ContractError> {
        if completed_at.get() <= 0 || result_digest == [0; 32] {
            Err(ContractError::Corrupt)
        } else {
            Ok(Self {
                completed_at,
                result_digest,
            })
        }
    }
}

impl FederatedShardOutcome {
    /// Returns the exact provider permit whose authority was revalidated before IO.
    #[must_use]
    pub const fn permit(&self) -> &FederatedShardPermit {
        &self.permit
    }

    /// Returns the exact signed capability presentation used by the requester.
    #[must_use]
    pub const fn capability_digest(&self) -> [u8; 32] {
        self.capability_digest
    }

    /// Returns bytes transferred or durably affected by the operation.
    #[must_use]
    pub const fn affected_bytes(&self) -> u64 {
        self.affected_bytes
    }

    /// Returns canonical result evidence bound to the permit and durable result.
    #[must_use]
    pub const fn result_digest(&self) -> [u8; 32] {
        self.result_digest
    }

    /// Returns the provider completion instant.
    #[must_use]
    pub const fn completed_at(&self) -> UnixMicros {
        self.completed_at
    }
}

/// Current-authority and durable-accounting boundary around federated provider IO.
pub trait FederatedShardAuthority {
    /// Revalidates the exact relationship, grant, allocation, target and reservation before IO.
    ///
    /// # Errors
    ///
    /// Rejects stale, revoked, substituted or locally unavailable authority.
    fn authorise(
        &self,
        permit: &FederatedShardPermit,
        capability_digest: [u8; 32],
        observed_at: UnixMicros,
    ) -> Result<(), ContractError>;

    /// Records one durable provider write before success may cross the federation boundary.
    ///
    /// # Errors
    ///
    /// Rejects missing/conflicting quota reservations or receipt substitution.
    fn commit_write(
        &mut self,
        permit: &FederatedShardPermit,
        receipt: ShardReceipt,
        completed_at: UnixMicros,
    ) -> Result<FederatedWriteEvidence, ContractError>;
}

impl<Provider: StorageProvider> RemoteShardService<Provider> {
    /// Serves one data stream authenticated as a current federation swarm peer.
    ///
    /// # Errors
    ///
    /// Rejects non-data streams, malformed messages, wrong swarm/relationship/epoch, invalid
    /// provider MACs, stale current authority, excessive bytes and provider or transport failure.
    pub async fn serve_federated_stream<Authority: FederatedShardAuthority>(
        &mut self,
        mut stream: AcceptedStream,
        peer: AuthenticatedFederationPeer,
        permit_key: &FederatedStoragePermitMacKey,
        authority: &mut Authority,
        limits: WireLimits,
        observed_at: UnixMicros,
    ) -> Result<Option<FederatedShardOutcome>, DataPlaneError> {
        if stream.kind != StreamKind::Data {
            return Err(DataPlaneError::InvalidMessage);
        }
        let first = receive_data_control(&mut stream.receive, limits)
            .await?
            .into_inner();
        match first.message.ok_or(DataPlaneError::InvalidMessage)? {
            Message::PutShardBegin(begin) => {
                self.serve_federated_put(
                    &mut stream,
                    FederatedServeContext {
                        peer,
                        permit_key,
                        authority,
                        limits,
                        observed_at,
                    },
                    begin,
                )
                .await
            }
            Message::GetShardRequest(request) => {
                self.serve_federated_get(
                    &mut stream,
                    FederatedServeContext {
                        peer,
                        permit_key,
                        authority,
                        limits,
                        observed_at,
                    },
                    request,
                )
                .await
            }
            _ => Err(DataPlaneError::InvalidMessage),
        }
    }

    async fn serve_federated_put<Authority: FederatedShardAuthority>(
        &mut self,
        stream: &mut AcceptedStream,
        context: FederatedServeContext<'_, Authority>,
        begin: PutShardBegin,
    ) -> Result<Option<FederatedShardOutcome>, DataPlaneError> {
        let permit = match self.authorise_federated_put(
            context.peer,
            context.permit_key,
            context.authority,
            context.observed_at,
            &begin,
        ) {
            Ok(permit) => permit,
            Err(error) => {
                reject_put(stream, context.limits, error).await?;
                return Ok(None);
            }
        };
        let capability_digest = digest(&begin.federation_capability_digest)?;
        let provider_context = request_context(
            begin
                .header
                .as_ref()
                .ok_or(DataPlaneError::InvalidMessage)?,
            permit.allocation_revision,
        )?;
        let reservation_class = match permit.action {
            FederationStorageAction::Put => ReservationClass::ForegroundWrite,
            FederationStorageAction::Repair => ReservationClass::Repair,
            _ => {
                reject_put(stream, context.limits, ContractError::Unauthorized).await?;
                return Ok(None);
            }
        };
        let prepared = PreparedPut {
            context: provider_context,
            shard: permit.shard,
            reservation_class,
        };
        let mut write_evidence = None;
        let receipt = self
            .serve_prepared_put(
                stream,
                context.limits,
                context.observed_at,
                begin,
                prepared,
                |receipt| {
                    write_evidence = Some(context.authority.commit_write(
                        &permit,
                        receipt,
                        context.observed_at,
                    )?);
                    Ok(receipt)
                },
            )
            .await?;
        match (receipt, write_evidence) {
            (Some(receipt), Some(evidence)) => Ok(Some(FederatedShardOutcome {
                permit,
                capability_digest,
                affected_bytes: receipt.length,
                result_digest: evidence.result_digest,
                completed_at: evidence.completed_at,
            })),
            (None, None) => Ok(None),
            _ => Err(DataPlaneError::InvalidMessage),
        }
    }

    async fn serve_federated_get<Authority: FederatedShardAuthority>(
        &self,
        stream: &mut AcceptedStream,
        context: FederatedServeContext<'_, Authority>,
        request: GetShardRequest,
    ) -> Result<Option<FederatedShardOutcome>, DataPlaneError> {
        let permit = match self.authorise_federated_get(
            context.peer,
            context.permit_key,
            context.authority,
            context.observed_at,
            &request,
        ) {
            Ok(permit) => permit,
            Err(error) => {
                reject_get(stream, context.limits, error).await?;
                return Ok(None);
            }
        };
        let capability_digest = digest(&request.federation_capability_digest)?;
        let header = request
            .header
            .as_ref()
            .ok_or(DataPlaneError::InvalidMessage)?;
        let provider_context = request_context(header, permit.allocation_revision)?;
        let mut read_permit = ShardReadPermit {
            operation_id: permit.operation_id,
            mesh_id: permit.provider_mesh_id,
            target_id: permit.target_id,
            target_generation: permit.target_generation,
            shard: permit.shard,
            authorization_revision: permit.allocation_revision,
            expires_at: permit.expires_at,
            permit_digest: [0; 32],
        };
        read_permit.permit_digest = read_permit_mac(&self.write_key, read_permit);
        let maximum_bytes = usize::try_from(permit.maximum_bytes)
            .ok()
            .map_or(self.maximum_shard_bytes, |maximum| {
                maximum.min(self.maximum_shard_bytes)
            });
        let evidence = self
            .serve_authorised_get(
                stream,
                context.limits,
                context.observed_at,
                provider_context,
                read_permit,
                maximum_bytes,
            )
            .await?;
        Ok(evidence.map(|evidence| FederatedShardOutcome {
            permit,
            capability_digest,
            affected_bytes: evidence.affected_bytes,
            result_digest: federated_shard_read_result_digest(
                &permit,
                evidence.affected_bytes,
                evidence.content_digest,
                context.observed_at,
            ),
            completed_at: context.observed_at,
        }))
    }

    fn authorise_federated_put<Authority: FederatedShardAuthority>(
        &self,
        peer: AuthenticatedFederationPeer,
        permit_key: &FederatedStoragePermitMacKey,
        authority: &Authority,
        observed_at: UnixMicros,
        begin: &PutShardBegin,
    ) -> Result<FederatedShardPermit, ContractError> {
        let permit = decode_federated_shard_permit(&begin.write_capability)
            .map_err(|_| ContractError::Unauthorized)?;
        let header = begin.header.as_ref().ok_or(ContractError::InvalidInput)?;
        let requested_shard = begin
            .shard
            .as_ref()
            .ok_or(ContractError::InvalidInput)
            .and_then(|value| shard(value).map_err(|_| ContractError::InvalidInput))?;
        let capability_digest = digest(&begin.federation_capability_digest)?;
        let context = request_context(header, permit.allocation_revision)
            .map_err(|_| ContractError::InvalidInput)?;
        let valid = matches!(
            permit.action,
            FederationStorageAction::Put | FederationStorageAction::Repair
        ) && common_authority(
            self,
            peer,
            permit_key,
            authority,
            observed_at,
            &permit,
            capability_digest,
        ) && context.operation_id == permit.operation_id
            && context.deadline > observed_at
            && context.deadline <= permit.expires_at
            && header.mesh_id.as_slice() == permit.remote_mesh_id.as_bytes()
            && begin.target_id.as_slice() == self.target_id.as_bytes()
            && begin.target_generation == self.target_generation
            && requested_shard == permit.shard
            && begin.declared_length > 0
            && begin.declared_length <= permit.maximum_bytes
            && begin.declared_length <= self.maximum_shard_bytes as u64;
        if valid {
            Ok(permit)
        } else {
            Err(ContractError::Unauthorized)
        }
    }

    fn authorise_federated_get<Authority: FederatedShardAuthority>(
        &self,
        peer: AuthenticatedFederationPeer,
        permit_key: &FederatedStoragePermitMacKey,
        authority: &Authority,
        observed_at: UnixMicros,
        request: &GetShardRequest,
    ) -> Result<FederatedShardPermit, ContractError> {
        let permit = decode_federated_shard_permit(&request.read_capability)
            .map_err(|_| ContractError::Unauthorized)?;
        let header = request.header.as_ref().ok_or(ContractError::InvalidInput)?;
        let requested_shard = request
            .shard
            .as_ref()
            .ok_or(ContractError::InvalidInput)
            .and_then(|value| shard(value).map_err(|_| ContractError::InvalidInput))?;
        let capability_digest = digest(&request.federation_capability_digest)?;
        let context = request_context(header, permit.allocation_revision)
            .map_err(|_| ContractError::InvalidInput)?;
        let valid = permit.action == FederationStorageAction::Get
            && common_authority(
                self,
                peer,
                permit_key,
                authority,
                observed_at,
                &permit,
                capability_digest,
            )
            && context.operation_id == permit.operation_id
            && context.deadline > observed_at
            && context.deadline <= permit.expires_at
            && header.mesh_id.as_slice() == permit.remote_mesh_id.as_bytes()
            && request.target_id.as_slice() == self.target_id.as_bytes()
            && request.target_generation == self.target_generation
            && requested_shard == permit.shard;
        if valid {
            Ok(permit)
        } else {
            Err(ContractError::Unauthorized)
        }
    }
}

struct FederatedServeContext<'a, Authority> {
    peer: AuthenticatedFederationPeer,
    permit_key: &'a FederatedStoragePermitMacKey,
    authority: &'a mut Authority,
    limits: WireLimits,
    observed_at: UnixMicros,
}

fn common_authority<Provider: StorageProvider, Authority: FederatedShardAuthority>(
    service: &RemoteShardService<Provider>,
    peer: AuthenticatedFederationPeer,
    permit_key: &FederatedStoragePermitMacKey,
    authority: &Authority,
    observed_at: UnixMicros,
    permit: &FederatedShardPermit,
    capability_digest: [u8; 32],
) -> bool {
    verify_federated_shard_permit_mac(permit_key, permit)
        && permit.relationship_id == peer.relationship_id()
        && permit.remote_mesh_id == peer.remote_mesh_id()
        && permit.provider_mesh_id == peer.local_mesh_id()
        && permit.relationship_authority_epoch == peer.authority_epoch()
        && permit.provider_mesh_id == service.mesh_id
        && permit.provider_node_id == service.node_id
        && permit.target_id == service.target_id
        && permit.target_generation == service.target_generation
        && permit.expires_at > observed_at
        && authority
            .authorise(permit, capability_digest, observed_at)
            .is_ok()
}

fn digest(value: &[u8]) -> Result<[u8; 32], ContractError> {
    let digest = value.try_into().map_err(|_| ContractError::Unauthorized)?;
    if digest == [0; 32] {
        Err(ContractError::Unauthorized)
    } else {
        Ok(digest)
    }
}
