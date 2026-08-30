// SPDX-License-Identifier: GPL-2.0-only

//! Provider-neutral server side of the authenticated shard stream state machine.

mod federation;
mod removal;

pub use federation::{FederatedShardAuthority, FederatedShardOutcome, FederatedWriteEvidence};

use meshspan_contracts::{
    BoundedBytes, ContractError, PutShardRequest, RequestContext, ReservationClass,
    ReserveStorageRequest, ShardIdentity, ShardReadPermit, ShardReceipt, StoragePermitMacKey,
    StorageProvider, verify_write_permit_mac,
};
use meshspan_domain::{MeshId, NodeId, TargetId, UnixMicros};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::data_control_envelope::Message;
use meshspan_protocol::v1::{
    DataControlEnvelope, DataFrame, GetShardHeader, GetShardRequest, GetShardResult, PutShardBegin,
    PutShardReady, PutShardResult,
};
use meshspan_transport::{
    AcceptedStream, AuthenticatedPeer, StreamKind, receive_data_control, receive_data_frame,
    send_data_control, send_data_frame,
};

use crate::DataPlaneError;
use crate::capability::{decode_read_permit, decode_write_permit, encode_reservation};
use crate::wire::{
    durable_result, receipt_payload, rejected_result, request_context, shard, wire_error,
    wire_shard,
};

/// One authenticated remote shard-service adapter over any conforming storage provider.
pub struct RemoteShardService<Provider> {
    provider: Provider,
    write_key: StoragePermitMacKey,
    mesh_id: MeshId,
    node_id: NodeId,
    target_id: TargetId,
    target_generation: u64,
    maximum_shard_bytes: usize,
}

impl<Provider: StorageProvider> RemoteShardService<Provider> {
    /// Binds one provider instance and write-capability verifier to one exact target incarnation.
    ///
    /// # Errors
    ///
    /// Rejects a zero target generation or zero shard-byte bound.
    pub fn new(
        provider: Provider,
        write_key: StoragePermitMacKey,
        mesh_id: MeshId,
        node_id: NodeId,
        target_id: TargetId,
        target_generation: u64,
        maximum_shard_bytes: usize,
    ) -> Result<Self, DataPlaneError> {
        if target_generation == 0 || maximum_shard_bytes == 0 {
            return Err(DataPlaneError::InvalidConfiguration);
        }
        Ok(Self {
            provider,
            write_key,
            mesh_id,
            node_id,
            target_id,
            target_generation,
            maximum_shard_bytes,
        })
    }

    /// Serves exactly one already-mTLS-authenticated data stream.
    ///
    /// # Errors
    ///
    /// Rejects non-data streams, malformed sequence transitions, invalid capabilities, excessive
    /// bytes, transport failure and provider contract failures.
    pub async fn serve_stream(
        &mut self,
        mut stream: AcceptedStream,
        peer: AuthenticatedPeer,
        limits: WireLimits,
        observed_at: UnixMicros,
    ) -> Result<(), DataPlaneError> {
        if stream.kind != StreamKind::Data {
            return Err(DataPlaneError::InvalidMessage);
        }
        let first = receive_data_control(&mut stream.receive, limits)
            .await?
            .into_inner();
        self.serve_message(
            stream,
            peer,
            limits,
            observed_at,
            first.message.ok_or(DataPlaneError::InvalidMessage)?,
        )
        .await
    }

    pub(crate) const fn route(&self) -> (TargetId, u64) {
        (self.target_id, self.target_generation)
    }

    pub(crate) async fn serve_message(
        &mut self,
        mut stream: AcceptedStream,
        peer: AuthenticatedPeer,
        limits: WireLimits,
        observed_at: UnixMicros,
        message: Message,
    ) -> Result<(), DataPlaneError> {
        validate_authenticated_sender(&message, peer)?;
        match message {
            Message::PutShardBegin(begin) => {
                self.serve_put(&mut stream, limits, observed_at, begin)
                    .await
            }
            Message::GetShardRequest(request) => {
                self.serve_get(&mut stream, limits, observed_at, request)
                    .await
            }
            Message::DeleteShardRequest(request) => {
                self.serve_delete(&mut stream, limits, observed_at, request)
                    .await
            }
            Message::ReclaimShardRequest(request) => {
                self.serve_reclaim(&mut stream, limits, observed_at, request)
                    .await
            }
            _ => Err(DataPlaneError::InvalidMessage),
        }
    }

    /// Returns the provider after its service adapter is shut down.
    #[must_use]
    pub fn into_provider(self) -> Provider {
        self.provider
    }

    async fn serve_put(
        &mut self,
        stream: &mut AcceptedStream,
        limits: WireLimits,
        observed_at: UnixMicros,
        begin: PutShardBegin,
    ) -> Result<(), DataPlaneError> {
        let prepared = match self.authorise_put(&begin, observed_at) {
            Ok(value) => value,
            Err(error) => return reject_put(stream, limits, error).await,
        };
        self.serve_prepared_put(stream, limits, observed_at, begin, prepared, Ok)
            .await?;
        Ok(())
    }

    async fn serve_prepared_put<Complete>(
        &mut self,
        stream: &mut AcceptedStream,
        limits: WireLimits,
        observed_at: UnixMicros,
        begin: PutShardBegin,
        prepared: PreparedPut,
        complete: Complete,
    ) -> Result<Option<ShardReceipt>, DataPlaneError>
    where
        Complete: FnOnce(ShardReceipt) -> Result<ShardReceipt, ContractError>,
    {
        let reservation = match self.provider.reserve(ReserveStorageRequest {
            context: prepared.context,
            target_id: self.target_id,
            target_generation: self.target_generation,
            class: prepared.reservation_class,
            bytes: begin.declared_length,
            observed_at,
        }) {
            Ok(value) => value,
            Err(error) => {
                reject_put(stream, limits, error).await?;
                return Ok(None);
            }
        };
        send_data_control(
            &mut stream.send,
            &DataControlEnvelope {
                message: Some(Message::PutShardReady(PutShardReady {
                    reservation: encode_reservation(reservation),
                    maximum_frame_bytes: limits.maximum_data_frame_bytes() as u64,
                    rejection: None,
                })),
            },
            limits,
        )
        .await?;

        let bytes = receive_put_bytes(&mut stream.receive, begin.declared_length, limits).await?;
        let finish = receive_data_control(&mut stream.receive, limits)
            .await?
            .into_inner();
        let Message::PutShardFinish(finish) =
            finish.message.ok_or(DataPlaneError::InvalidMessage)?
        else {
            return Err(DataPlaneError::InvalidMessage);
        };
        let digest: [u8; 32] = begin
            .declared_digest
            .as_slice()
            .try_into()
            .map_err(|_| DataPlaneError::InvalidMessage)?;
        if finish.final_length != begin.declared_length
            || finish.final_digest.as_slice() != digest
            || blake3::hash(&bytes).as_bytes() != &digest
        {
            return Err(DataPlaneError::InvalidMessage);
        }
        let bounded = BoundedBytes::copy_from(&bytes, self.maximum_shard_bytes)
            .map_err(|_| DataPlaneError::InvalidMessage)?;
        let request = PutShardRequest {
            context: prepared.context,
            reservation,
            shard: prepared.shard,
            expected_length: begin.declared_length,
            expected_digest: digest,
            bytes: bounded,
        };
        let result = self
            .provider
            .put_exact(request, observed_at)
            .and_then(complete);
        send_put_result(stream, limits, result).await
    }

    async fn serve_get(
        &self,
        stream: &mut AcceptedStream,
        limits: WireLimits,
        observed_at: UnixMicros,
        request: GetShardRequest,
    ) -> Result<(), DataPlaneError> {
        let Ok(permit) = decode_read_permit(&request.read_capability) else {
            return reject_get(stream, limits, ContractError::Unauthorized).await;
        };
        let header = request
            .header
            .as_ref()
            .ok_or(DataPlaneError::InvalidMessage)?;
        let context = request_context(header, permit.authorization_revision)?;
        let requested_shard = shard(
            request
                .shard
                .as_ref()
                .ok_or(DataPlaneError::InvalidMessage)?,
        )?;
        let authorised = permit.operation_id == context.operation_id
            && permit.mesh_id == self.mesh_id
            && header.mesh_id.as_slice() == self.mesh_id.as_bytes()
            && permit.target_id == self.target_id
            && request.target_id.as_slice() == self.target_id.as_bytes()
            && permit.target_generation == self.target_generation
            && request.target_generation == self.target_generation
            && permit.shard == requested_shard
            && permit.expires_at > observed_at
            && context.deadline > observed_at;
        if !authorised {
            return reject_get(stream, limits, ContractError::Unauthorized).await;
        }
        self.serve_authorised_get(
            stream,
            limits,
            observed_at,
            context,
            permit,
            self.maximum_shard_bytes,
        )
        .await?;
        Ok(())
    }

    async fn serve_authorised_get(
        &self,
        stream: &mut AcceptedStream,
        limits: WireLimits,
        observed_at: UnixMicros,
        context: RequestContext,
        permit: ShardReadPermit,
        maximum_bytes: usize,
    ) -> Result<Option<ReadEvidence>, DataPlaneError> {
        let bytes = match self.provider.get_exact(context, permit, observed_at) {
            Ok(value) => value,
            Err(error) => {
                reject_get(stream, limits, error).await?;
                return Ok(None);
            }
        };
        if bytes.len() > maximum_bytes {
            reject_get(stream, limits, ContractError::ResourceExhausted).await?;
            return Ok(None);
        }
        let digest: [u8; 32] = blake3::hash(bytes.as_slice()).into();
        send_data_control(
            &mut stream.send,
            &DataControlEnvelope {
                message: Some(Message::GetShardHeader(GetShardHeader {
                    shard: Some(wire_shard(permit.shard)),
                    length: bytes.len() as u64,
                    digest: digest.to_vec(),
                    maximum_frame_bytes: limits.maximum_data_frame_bytes() as u64,
                    rejection: None,
                })),
            },
            limits,
        )
        .await?;
        send_bytes(&mut stream.send, bytes.as_slice(), limits).await?;
        send_data_control(
            &mut stream.send,
            &DataControlEnvelope {
                message: Some(Message::GetShardResult(GetShardResult {
                    result: Some(durable_result()),
                })),
            },
            limits,
        )
        .await?;
        stream
            .send
            .finish()
            .map_err(meshspan_transport::TransportError::from)?;
        Ok(Some(ReadEvidence {
            affected_bytes: bytes.len() as u64,
            content_digest: digest,
        }))
    }

    fn authorise_put(
        &self,
        begin: &PutShardBegin,
        observed_at: UnixMicros,
    ) -> Result<PreparedPut, ContractError> {
        let permit = decode_write_permit(&begin.write_capability)
            .map_err(|_| ContractError::Unauthorized)?;
        let header = begin.header.as_ref().ok_or(ContractError::InvalidInput)?;
        let context = request_context(header, permit.authorization_revision)
            .map_err(|_| ContractError::InvalidInput)?;
        let requested_shard = begin
            .shard
            .as_ref()
            .ok_or(ContractError::InvalidInput)
            .and_then(|value| shard(value).map_err(|_| ContractError::InvalidInput))?;
        let valid = verify_write_permit_mac(&self.write_key, permit)
            && permit.operation_id == context.operation_id
            && permit.mesh_id == self.mesh_id
            && header.mesh_id.as_slice() == self.mesh_id.as_bytes()
            && permit.target_id == self.target_id
            && begin.target_id.as_slice() == self.target_id.as_bytes()
            && permit.target_generation == self.target_generation
            && begin.target_generation == self.target_generation
            && permit.shard == requested_shard
            && begin.declared_length <= permit.maximum_bytes
            && begin.declared_length <= self.maximum_shard_bytes as u64
            && permit.expires_at > observed_at
            && context.deadline > observed_at;
        if valid {
            Ok(PreparedPut {
                context,
                shard: permit.shard,
                reservation_class: permit.reservation_class,
            })
        } else {
            Err(ContractError::Unauthorized)
        }
    }
}

#[derive(Clone, Copy)]
struct PreparedPut {
    context: RequestContext,
    shard: ShardIdentity,
    reservation_class: ReservationClass,
}

#[derive(Clone, Copy)]
struct ReadEvidence {
    pub(super) affected_bytes: u64,
    pub(super) content_digest: [u8; 32],
}

fn validate_authenticated_sender(
    message: &Message,
    peer: AuthenticatedPeer,
) -> Result<(), DataPlaneError> {
    let header = match message {
        Message::PutShardBegin(value) => value.header.as_ref(),
        Message::GetShardRequest(value) => value.header.as_ref(),
        Message::DeleteShardRequest(value) => value.header.as_ref(),
        Message::ReclaimShardRequest(value) => value.header.as_ref(),
        _ => return Err(DataPlaneError::InvalidMessage),
    }
    .ok_or(DataPlaneError::InvalidMessage)?;
    if header.sender_node_id.as_slice() == peer.node_id().as_bytes()
        && header.sender_incarnation == peer.incarnation()
    {
        Ok(())
    } else {
        Err(DataPlaneError::InvalidMessage)
    }
}

async fn receive_put_bytes(
    receive: &mut quinn::RecvStream,
    declared_length: u64,
    limits: WireLimits,
) -> Result<Vec<u8>, DataPlaneError> {
    let capacity = usize::try_from(declared_length).map_err(|_| DataPlaneError::InvalidMessage)?;
    let mut bytes = Vec::with_capacity(capacity);
    while bytes.len() < capacity {
        let frame = receive_data_frame(receive, limits).await?.into_inner();
        if frame.offset != bytes.len() as u64 {
            return Err(DataPlaneError::InvalidMessage);
        }
        let new_length = bytes
            .len()
            .checked_add(frame.bytes.len())
            .ok_or(DataPlaneError::InvalidMessage)?;
        if new_length > capacity {
            return Err(DataPlaneError::InvalidMessage);
        }
        bytes.extend_from_slice(&frame.bytes);
    }
    Ok(bytes)
}

async fn send_bytes(
    send: &mut quinn::SendStream,
    bytes: &[u8],
    limits: WireLimits,
) -> Result<(), DataPlaneError> {
    let frame_bytes = limits.maximum_data_frame_bytes();
    for (index, chunk) in bytes.chunks(frame_bytes).enumerate() {
        let offset = index
            .checked_mul(frame_bytes)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(DataPlaneError::InvalidMessage)?;
        send_data_frame(
            send,
            &DataFrame {
                offset,
                bytes: chunk.to_vec(),
            },
            limits,
        )
        .await?;
    }
    Ok(())
}

async fn reject_put(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    error: ContractError,
) -> Result<(), DataPlaneError> {
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::PutShardReady(PutShardReady {
                reservation: Vec::new(),
                maximum_frame_bytes: limits.maximum_data_frame_bytes() as u64,
                rejection: Some(wire_error(error)),
            })),
        },
        limits,
    )
    .await?;
    stream
        .send
        .finish()
        .map_err(meshspan_transport::TransportError::from)?;
    Ok(())
}

async fn reject_get(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    error: ContractError,
) -> Result<(), DataPlaneError> {
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::GetShardHeader(GetShardHeader {
                shard: None,
                length: 0,
                digest: Vec::new(),
                maximum_frame_bytes: limits.maximum_data_frame_bytes() as u64,
                rejection: Some(wire_error(error)),
            })),
        },
        limits,
    )
    .await?;
    stream
        .send
        .finish()
        .map_err(meshspan_transport::TransportError::from)?;
    Ok(())
}

async fn send_put_result(
    stream: &mut AcceptedStream,
    limits: WireLimits,
    result: Result<ShardReceipt, ContractError>,
) -> Result<Option<ShardReceipt>, DataPlaneError> {
    let (operation, receipt) = match result {
        Ok(receipt) => (durable_result(), Some(receipt)),
        Err(error) => (rejected_result(error), None),
    };
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::PutShardResult(PutShardResult {
                result: Some(operation),
                receipt: receipt.map(receipt_payload),
            })),
        },
        limits,
    )
    .await?;
    stream
        .send
        .finish()
        .map_err(meshspan_transport::TransportError::from)?;
    Ok(receipt)
}
