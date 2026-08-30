// SPDX-License-Identifier: GPL-2.0-only

//! Federated-swarm authority adapter for the shared provider shard state machine.

use meshspan_contracts::{
    ContractError, FederatedShardPermit, FederatedStoragePermitMacKey, ReclamationReceipt,
    RemovalPermit, ReservationClass, ShardReadPermit, ShardReceipt, StorageProvider,
    TombstoneReceipt, federated_provider_shard_identity, federated_shard_read_result_digest,
    read_permit_mac, removal_permit_mac, verify_federated_shard_permit_mac,
};
use meshspan_domain::{FederationStorageAction, UnixMicros};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{
    DeleteShardRequest, GetShardRequest, PutShardBegin, ReclaimShardRequest,
};
use meshspan_transport::{
    AcceptedStream, AuthenticatedFederationPeer, StreamKind, receive_data_control,
};

use super::removal::{reject_delete, reject_reclaim, send_delete_result, send_reclaim_result};
use super::{AuthorisedGet, PreparedPut, RemoteShardService, reject_get, reject_put};
use crate::DataPlaneError;
use crate::capability::decode_federated_shard_permit;
use crate::wire::{request_context, shard, tombstone_receipt};

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

/// Exact durable logical retirement retained by provider-local accounting across retries.
#[derive(Clone, Copy)]
pub struct FederatedRetirementEvidence {
    tombstone: TombstoneReceipt,
    affected_bytes: u64,
    completed_at: UnixMicros,
}

impl FederatedRetirementEvidence {
    /// Constructs validated durable logical-retirement evidence.
    ///
    /// # Errors
    ///
    /// Rejects zero affected bytes, non-positive completion time or an empty result digest.
    pub fn new(
        tombstone: TombstoneReceipt,
        affected_bytes: u64,
        completed_at: UnixMicros,
    ) -> Result<Self, ContractError> {
        if affected_bytes == 0 || completed_at.get() <= 0 || tombstone.tombstone_digest == [0; 32] {
            Err(ContractError::Corrupt)
        } else {
            Ok(Self {
                tombstone,
                affected_bytes,
                completed_at,
            })
        }
    }
}

/// Exact physical reclamation retained with its atomic quota release across retries.
#[derive(Clone, Copy)]
pub struct FederatedReclamationEvidence {
    receipt: ReclamationReceipt,
}

impl FederatedReclamationEvidence {
    /// Constructs validated durable physical-reclamation evidence.
    ///
    /// # Errors
    ///
    /// Rejects zero reclaimed bytes or an empty durable result digest.
    pub fn new(receipt: ReclamationReceipt) -> Result<Self, ContractError> {
        if receipt.reclaimed_bytes == 0 || receipt.reclamation_digest == [0; 32] {
            Err(ContractError::Corrupt)
        } else {
            Ok(Self { receipt })
        }
    }
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

    /// Records a provider tombstone before logical retirement success may cross federation.
    ///
    /// # Errors
    ///
    /// Rejects stale, conflicting, unavailable or corrupt capability and lifecycle evidence.
    fn commit_retirement(
        &mut self,
        permit: &FederatedShardPermit,
        capability_digest: [u8; 32],
        provider_tombstone: TombstoneReceipt,
        completed_at: UnixMicros,
    ) -> Result<FederatedRetirementEvidence, ContractError>;

    /// Resolves an exact logical tombstone to provider-local unlink authority.
    ///
    /// # Errors
    ///
    /// Rejects unknown, substituted, unavailable or corrupt lifecycle evidence.
    fn provider_tombstone(
        &self,
        permit: &FederatedShardPermit,
        logical_tombstone: TombstoneReceipt,
    ) -> Result<TombstoneReceipt, ContractError>;

    /// Atomically records physical unlink and releases exact provider-local quota.
    ///
    /// # Errors
    ///
    /// Rejects stale, conflicting, unavailable or corrupt reclamation and quota evidence.
    fn commit_reclamation(
        &mut self,
        permit: &FederatedShardPermit,
        capability_digest: [u8; 32],
        logical_tombstone: TombstoneReceipt,
        provider_reclamation: ReclamationReceipt,
    ) -> Result<FederatedReclamationEvidence, ContractError>;
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
            Message::DeleteShardRequest(request) => {
                self.serve_federated_retire(
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
            Message::ReclaimShardRequest(request) => {
                self.serve_federated_reclaim(
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
            shard: federated_provider_shard_identity(
                permit.remote_mesh_id,
                permit.scope_digest,
                permit.shard,
            ),
            reservation_class,
        };
        let provider_shard = prepared.shard;
        let mut write_evidence = None;
        let receipt = self
            .serve_prepared_put(
                stream,
                context.limits,
                context.observed_at,
                begin,
                prepared,
                |receipt| {
                    let receipt = logical_receipt(receipt, provider_shard, permit.shard)?;
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
        let provider_shard = federated_provider_shard_identity(
            permit.remote_mesh_id,
            permit.scope_digest,
            permit.shard,
        );
        let mut read_permit = ShardReadPermit {
            operation_id: permit.operation_id,
            mesh_id: permit.provider_mesh_id,
            target_id: permit.target_id,
            target_generation: permit.target_generation,
            shard: provider_shard,
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
                AuthorisedGet {
                    context: provider_context,
                    permit: read_permit,
                    response_shard: permit.shard,
                    maximum_bytes,
                },
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

    async fn serve_federated_retire<Authority: FederatedShardAuthority>(
        &mut self,
        stream: &mut AcceptedStream,
        context: FederatedServeContext<'_, Authority>,
        request: DeleteShardRequest,
    ) -> Result<Option<FederatedShardOutcome>, DataPlaneError> {
        let permit = match self.authorise_federated_lifecycle(
            &context,
            LifecycleWireRequest {
                header: request.header.as_ref(),
                target_id: &request.target_id,
                target_generation: request.target_generation,
                shard: request.shard.as_ref(),
                capability: &request.federation_capability,
                capability_digest: &request.federation_capability_digest,
            },
            FederationStorageAction::Retire,
        ) {
            Ok(permit) => permit,
            Err(error) => {
                reject_delete(stream, context.limits, error).await?;
                return Ok(None);
            }
        };
        let capability_digest = digest(&request.federation_capability_digest)?;
        let provider_shard = federated_provider_shard_identity(
            permit.remote_mesh_id,
            permit.scope_digest,
            permit.shard,
        );
        let local_fence = self.provider.removal_authority_fence();
        let mut removal = RemovalPermit {
            operation_id: permit.operation_id,
            mesh_id: permit.provider_mesh_id,
            target_id: permit.target_id,
            shard: provider_shard,
            target_generation: permit.target_generation,
            authority_epoch: local_fence.authority_epoch,
            catalogue_revision: local_fence.catalogue_revision,
            expires_at: permit.expires_at,
            permit_digest: [0; 32],
        };
        removal.permit_digest = removal_permit_mac(&self.write_key, removal);
        let provider_tombstone = match self.provider.tombstone(removal, context.observed_at) {
            Ok(receipt) => receipt,
            Err(error) => {
                reject_delete(stream, context.limits, error).await?;
                return Ok(None);
            }
        };
        let evidence = match context.authority.commit_retirement(
            &permit,
            capability_digest,
            provider_tombstone,
            context.observed_at,
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                reject_delete(stream, context.limits, error).await?;
                return Ok(None);
            }
        };
        send_delete_result(stream, context.limits, Ok(evidence.tombstone)).await?;
        Ok(Some(FederatedShardOutcome {
            permit,
            capability_digest,
            affected_bytes: evidence.affected_bytes,
            result_digest: evidence.tombstone.tombstone_digest,
            completed_at: evidence.completed_at,
        }))
    }

    async fn serve_federated_reclaim<Authority: FederatedShardAuthority>(
        &mut self,
        stream: &mut AcceptedStream,
        context: FederatedServeContext<'_, Authority>,
        request: ReclaimShardRequest,
    ) -> Result<Option<FederatedShardOutcome>, DataPlaneError> {
        let permit = match self.authorise_federated_lifecycle(
            &context,
            LifecycleWireRequest {
                header: request.header.as_ref(),
                target_id: &request.target_id,
                target_generation: request.target_generation,
                shard: request.shard.as_ref(),
                capability: &request.federation_capability,
                capability_digest: &request.federation_capability_digest,
            },
            FederationStorageAction::Reclaim,
        ) {
            Ok(permit) => permit,
            Err(error) => {
                reject_reclaim(stream, context.limits, error).await?;
                return Ok(None);
            }
        };
        let Ok(logical_tombstone) = tombstone_receipt(request.tombstone_receipt.as_ref()) else {
            reject_reclaim(stream, context.limits, ContractError::InvalidInput).await?;
            return Ok(None);
        };
        let provider_tombstone = match context
            .authority
            .provider_tombstone(&permit, logical_tombstone)
        {
            Ok(receipt) => receipt,
            Err(error) => {
                reject_reclaim(stream, context.limits, error).await?;
                return Ok(None);
            }
        };
        let provider_reclamation = match self
            .provider
            .unlink_tombstoned(provider_tombstone, context.observed_at)
        {
            Ok(receipt) => receipt,
            Err(error) => {
                reject_reclaim(stream, context.limits, error).await?;
                return Ok(None);
            }
        };
        let capability_digest = digest(&request.federation_capability_digest)?;
        let evidence = match context.authority.commit_reclamation(
            &permit,
            capability_digest,
            logical_tombstone,
            provider_reclamation,
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                reject_reclaim(stream, context.limits, error).await?;
                return Ok(None);
            }
        };
        send_reclaim_result(stream, context.limits, Ok(evidence.receipt)).await?;
        Ok(Some(FederatedShardOutcome {
            permit,
            capability_digest,
            affected_bytes: evidence.receipt.reclaimed_bytes,
            result_digest: evidence.receipt.reclamation_digest,
            completed_at: evidence.receipt.bytes_unlinked_at,
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

    fn authorise_federated_lifecycle<Authority: FederatedShardAuthority>(
        &self,
        context: &FederatedServeContext<'_, Authority>,
        request: LifecycleWireRequest<'_>,
        expected_action: FederationStorageAction,
    ) -> Result<FederatedShardPermit, ContractError> {
        let permit = decode_federated_shard_permit(request.capability)
            .map_err(|_| ContractError::Unauthorized)?;
        let header = request.header.ok_or(ContractError::InvalidInput)?;
        let requested_shard = request
            .shard
            .ok_or(ContractError::InvalidInput)
            .and_then(|value| shard(value).map_err(|_| ContractError::InvalidInput))?;
        let capability_digest = digest(request.capability_digest)?;
        let request_context = request_context(header, permit.allocation_revision)
            .map_err(|_| ContractError::InvalidInput)?;
        let valid = permit.action == expected_action
            && common_authority(
                self,
                context.peer,
                context.permit_key,
                context.authority,
                context.observed_at,
                &permit,
                capability_digest,
            )
            && request_context.operation_id == permit.operation_id
            && request_context.deadline > context.observed_at
            && request_context.deadline <= permit.expires_at
            && header.mesh_id.as_slice() == permit.remote_mesh_id.as_bytes()
            && request.target_id == self.target_id.as_bytes()
            && request.target_generation == self.target_generation
            && requested_shard == permit.shard;
        if valid {
            Ok(permit)
        } else {
            Err(ContractError::Unauthorized)
        }
    }
}

fn logical_receipt(
    receipt: ShardReceipt,
    provider_shard: meshspan_contracts::ShardIdentity,
    logical_shard: meshspan_contracts::ShardIdentity,
) -> Result<ShardReceipt, ContractError> {
    if receipt.shard != provider_shard {
        return Err(ContractError::Conflict);
    }
    Ok(ShardReceipt {
        shard: logical_shard,
        ..receipt
    })
}

struct FederatedServeContext<'a, Authority> {
    peer: AuthenticatedFederationPeer,
    permit_key: &'a FederatedStoragePermitMacKey,
    authority: &'a mut Authority,
    limits: WireLimits,
    observed_at: UnixMicros,
}

#[derive(Clone, Copy)]
struct LifecycleWireRequest<'a> {
    header: Option<&'a meshspan_protocol::v1::RequestHeader>,
    target_id: &'a [u8],
    target_generation: u64,
    shard: Option<&'a meshspan_protocol::v1::ShardIdentity>,
    capability: &'a [u8],
    capability_digest: &'a [u8],
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
