// SPDX-License-Identifier: GPL-2.0-only

//! Oversized consensus bodies retain an owned allocation lease from queueing through dispatch.

use meshspan_protocol::v1::consensus_bulk_start::Metadata;
use meshspan_protocol::v1::data_control_envelope::Message as DataMessage;
use meshspan_protocol::v1::{
    ConsensusBulkEntries, ConsensusBulkReceipt, ConsensusBulkStart, DataControlEnvelope, DataFrame,
};
use meshspan_protocol::{
    MAXIMUM_CONSENSUS_BULK_BODY_BYTES, MAXIMUM_CONSENSUS_COMMAND_BYTES, consensus_transfer_support,
    decode_consensus_bulk, encode_consensus_bulk_entries,
};
use meshspan_transport::{
    AcceptedStream, receive_data_control, receive_data_frame, send_data_control, send_data_frame,
};
use sha2::{Digest as _, Sha256};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::bulk_budget::ConsensusByteReservation;
use super::{
    Arc, AuthenticatedStreamIngress, ConsensusNetwork, ConsensusNetworkError, CoreMessage,
    Duration, MAXIMUM_CONTROL_BYTES, MAXIMUM_DATA_BYTES, Message, NodeId, OperationId, Ordering,
    PEER_OPERATION_TIMEOUT, PeerConsensusMessage, RequestHeader, StreamKind, WireLimits,
    encode_consensus_message, mpsc, open_stream, request_identifier,
};

const BULK_TIMEOUT: Duration = Duration::from_secs(30);
const ENTRY_ENCODING_OVERHEAD: usize = 128;
const ENVELOPE_ENCODING_OVERHEAD: usize = 1024;

pub(super) struct OutboundConsensusMessage {
    message: CoreMessage,
    allocation: Option<Arc<ConsensusByteReservation>>,
}

impl OutboundConsensusMessage {
    pub(super) fn prepare(
        network: &ConsensusNetwork,
        peer: NodeId,
        message: CoreMessage,
    ) -> Result<Self, ConsensusNetworkError> {
        let body_bound = bulk_body_bound(&message)?;
        let allocation = body_bound
            .map(|length| network.bulk_budgets.reserve(peer, length))
            .transpose()
            .map_err(|_| ConsensusNetworkError::InvalidTraffic)?;
        Ok(Self {
            message,
            allocation,
        })
    }
}

struct PreparedConsensusBulk {
    start: ConsensusBulkStart,
    bytes: Vec<u8>,
    _allocation: Arc<ConsensusByteReservation>,
}

impl ConsensusNetwork {
    pub(super) async fn run_outbound_worker(
        &self,
        peer: NodeId,
        mut messages: mpsc::Receiver<OutboundConsensusMessage>,
    ) {
        let mut connection = None;
        let mut bulk = JoinSet::new();
        loop {
            tokio::select! {
                outcome = bulk.join_next(), if !bulk.is_empty() => {
                    // Failure is not an acknowledgement; the consensus core retries its probe.
                    if outcome.is_some_and(|outcome| !matches!(outcome, Ok(Ok(())))) {
                        connection = None;
                    }
                }
                message = messages.recv() => {
                    let Some(message) = message else { break; };
                    if let Some(allocation) = message.allocation {
                        // One independently deadline-bounded transfer per peer. Additional stale
                        // probes are dropped before encoding; current probes are retried by core.
                        if bulk.is_empty() {
                            let network = self.clone();
                            bulk.spawn(async move { network.send_bulk(peer, message.message, allocation).await });
                        }
                    } else {
                        let result = tokio::time::timeout(PEER_OPERATION_TIMEOUT,
                            self.send_with_connection(peer, &mut connection, message.message)).await;
                        if !matches!(result, Ok(Ok(()))) { connection = None; }
                    }
                }
            }
        }
        // Do not detach blocking codecs or cancel a transfer after it has entered a peer queue.
        while let Some(outcome) = bulk.join_next().await {
            if !matches!(outcome, Ok(Ok(()))) {
                connection = None;
            }
        }
        drop(connection);
    }

    async fn send_bulk(
        &self,
        peer: NodeId,
        message: CoreMessage,
        allocation: Arc<ConsensusByteReservation>,
    ) -> Result<(), ConsensusNetworkError> {
        self.send_bulk_until(
            peer,
            message,
            allocation,
            tokio::time::Instant::now() + BULK_TIMEOUT,
        )
        .await
    }

    pub(super) async fn send_bulk_until(
        &self,
        peer: NodeId,
        message: CoreMessage,
        allocation: Arc<ConsensusByteReservation>,
        deadline: tokio::time::Instant,
    ) -> Result<(), ConsensusNetworkError> {
        let header = self.request_header(
            OperationId::from_bytes(request_identifier(
                self.next_request.fetch_add(1, Ordering::Relaxed).max(1),
            ))?,
            bulk_deadline()?,
        );
        let worker = self.acquire_bulk_codec(deadline).await?;
        let prepared = tokio::task::spawn_blocking(move || {
            let _worker = worker;
            prepare_body(header, message, allocation)
        })
        .await
        .map_err(|_| ConsensusNetworkError::InvalidTraffic)??;
        // A started blocking codec remains owned through completion. If it finishes late,
        // discard its result without starting a new remote operation or deadline.
        check_bulk_deadline(deadline)?;
        tokio::time::timeout_at(deadline, self.send_prepared_bulk(peer, prepared))
            .await
            .map_err(|_| ConsensusNetworkError::BulkTransferUnconfirmed)?
    }

    async fn send_prepared_bulk(
        &self,
        peer: NodeId,
        prepared: PreparedConsensusBulk,
    ) -> Result<(), ConsensusNetworkError> {
        let (connection, support) = self.connect_peer_support(peer).await?;
        if !support.as_ref().is_some_and(|support| {
            let local = consensus_transfer_support();
            support.format_version == local.format_version
                && support.maximum_command_bytes >= local.maximum_command_bytes
                && support.maximum_body_bytes >= local.maximum_body_bytes
                && support.maximum_entries >= local.maximum_entries
        }) {
            return Err(ConsensusNetworkError::InvalidTraffic);
        }
        let (mut send, mut receive) = open_stream(&connection, StreamKind::ConsensusBulk).await?;
        send_data_control(
            &mut send,
            &DataControlEnvelope {
                message: Some(DataMessage::ConsensusBulkStart(prepared.start.clone())),
            },
            self.wire_limits,
        )
        .await?;
        for (index, bytes) in prepared.bytes.chunks(MAXIMUM_DATA_BYTES).enumerate() {
            send_data_frame(
                &mut send,
                &DataFrame {
                    offset: (index * MAXIMUM_DATA_BYTES) as u64,
                    bytes: bytes.to_vec(),
                },
                self.wire_limits,
            )
            .await?;
        }
        send.finish()?;
        let receipt = receive_data_control(&mut receive, self.wire_limits)
            .await?
            .into_inner();
        let Some(DataMessage::ConsensusBulkReceipt(receipt)) = receipt.message else {
            return Err(ConsensusNetworkError::InvalidTraffic);
        };
        let header = prepared
            .start
            .header
            .as_ref()
            .ok_or(ConsensusNetworkError::InvalidTraffic)?;
        if receipt.request_id != header.request_id
            || receipt.body_digest != prepared.start.body_digest
        {
            return Err(ConsensusNetworkError::InvalidTraffic);
        }
        receive
            .read_to_end(0)
            .await
            .map_err(|_| ConsensusNetworkError::InvalidTraffic)?;
        Ok(())
    }

    pub(super) async fn receive_bulk(
        &self,
        mut stream: AcceptedStream,
        ingress: AuthenticatedStreamIngress,
    ) -> Result<(), ConsensusNetworkError> {
        let deadline = tokio::time::Instant::now() + BULK_TIMEOUT;
        let (start, bytes, allocation) =
            tokio::time::timeout_at(deadline, self.receive_bulk_bytes(&mut stream, ingress.peer))
                .await
                .map_err(|_| ConsensusNetworkError::BulkTransferUnconfirmed)??;
        let receipt = ConsensusBulkReceipt {
            request_id: start
                .header
                .as_ref()
                .ok_or(ConsensusNetworkError::InvalidTraffic)?
                .request_id
                .clone(),
            body_digest: start.body_digest.clone(),
        };
        let worker = self.acquire_bulk_codec(deadline).await?;
        let message = tokio::task::spawn_blocking(move || {
            let _worker = worker;
            let decoded = decode_consensus_bulk(start, &bytes)
                .map_err(|_| ConsensusNetworkError::InvalidTraffic)?;
            let message = crate::wire::decode_bulk_message(&decoded)?;
            Ok::<_, ConsensusNetworkError>(PeerConsensusMessage::with_allocation(
                ingress.peer.node_id(),
                ingress.peer.incarnation(),
                message,
                allocation,
            ))
        })
        .await
        .map_err(|_| ConsensusNetworkError::InvalidTraffic)??;
        check_bulk_deadline(deadline)?;
        tokio::time::timeout_at(deadline, async {
            self.admit_peer_message(ingress.peer, &ingress.messages, message)
                .await?;
            send_data_control(
                &mut stream.send,
                &DataControlEnvelope {
                    message: Some(DataMessage::ConsensusBulkReceipt(receipt)),
                },
                self.wire_limits,
            )
            .await?;
            stream.send.finish()?;
            Ok::<_, ConsensusNetworkError>(())
        })
        .await
        .map_err(|_| ConsensusNetworkError::BulkTransferUnconfirmed)?
    }

    async fn acquire_bulk_codec(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, ConsensusNetworkError> {
        check_bulk_deadline(deadline)?;
        let permit =
            tokio::time::timeout_at(deadline, Arc::clone(&self.bulk_codecs).acquire_owned())
                .await
                .map_err(|_| ConsensusNetworkError::BulkTransferUnconfirmed)?
                .map_err(|_| ConsensusNetworkError::AuthorityStopped)?;
        check_bulk_deadline(deadline)?;
        Ok(permit)
    }

    async fn receive_bulk_bytes(
        &self,
        stream: &mut AcceptedStream,
        peer: meshspan_transport::AuthenticatedPeer,
    ) -> Result<(ConsensusBulkStart, Vec<u8>, Arc<ConsensusByteReservation>), ConsensusNetworkError>
    {
        let envelope = receive_data_control(&mut stream.receive, self.wire_limits)
            .await?
            .into_inner();
        let Some(DataMessage::ConsensusBulkStart(start)) = envelope.message else {
            return Err(ConsensusNetworkError::InvalidTraffic);
        };
        self.verify_current_peer(peer)?;
        self.verify_request_header(
            start
                .header
                .as_ref()
                .ok_or(ConsensusNetworkError::InvalidTraffic)?,
            peer.node_id(),
            peer.incarnation(),
        )?;
        let length = usize::try_from(start.byte_length)
            .map_err(|_| ConsensusNetworkError::InvalidTraffic)?;
        let allocation = self
            .bulk_budgets
            .reserve(peer.node_id(), length)
            .map_err(|_| ConsensusNetworkError::BulkTransferUnconfirmed)?;
        let bytes = receive_body(&mut stream.receive, length, self.wire_limits).await?;
        Ok((start, bytes, allocation))
    }
}

fn prepare_body(
    header: RequestHeader,
    mut message: CoreMessage,
    allocation: Arc<ConsensusByteReservation>,
) -> Result<PreparedConsensusBulk, ConsensusNetworkError> {
    let entries = match &mut message {
        CoreMessage::AppendRequest(value) => std::mem::take(&mut value.entries),
        CoreMessage::CommittedPrefix(value) => std::mem::take(&mut value.entries),
        CoreMessage::VoteRequest(_)
        | CoreMessage::VoteResponse(_)
        | CoreMessage::AppendResponse(_) => return Err(ConsensusNetworkError::InvalidTraffic),
    };
    let metadata = match encode_consensus_message(&message) {
        Message::AppendRequest(value) => Metadata::Append(value),
        Message::CommittedPrefix(value) => Metadata::Prefix(value),
        _ => return Err(ConsensusNetworkError::InvalidTraffic),
    };
    let body = ConsensusBulkEntries {
        format_version: 1,
        request_id: header.request_id.clone(),
        entries: entries.iter().map(crate::wire::wire_entry).collect(),
    };
    let bytes =
        encode_consensus_bulk_entries(&body).map_err(|_| ConsensusNetworkError::InvalidTraffic)?;
    let start = ConsensusBulkStart {
        header: Some(header),
        format_version: 1,
        byte_length: bytes.len() as u64,
        body_digest: Sha256::digest(&bytes).to_vec(),
        entry_count: u32::try_from(entries.len())
            .map_err(|_| ConsensusNetworkError::InvalidTraffic)?,
        metadata: Some(metadata),
    };
    Ok(PreparedConsensusBulk {
        start,
        bytes,
        _allocation: allocation,
    })
}

fn bulk_body_bound(message: &CoreMessage) -> Result<Option<usize>, ConsensusNetworkError> {
    let entries = match message {
        CoreMessage::AppendRequest(value) => &value.entries,
        CoreMessage::CommittedPrefix(value) => &value.entries,
        CoreMessage::VoteRequest(_)
        | CoreMessage::VoteResponse(_)
        | CoreMessage::AppendResponse(_) => return Ok(None),
    };
    let command_bytes = entries
        .iter()
        .try_fold(0_usize, |sum, entry| sum.checked_add(entry.command.len()))
        .ok_or(ConsensusNetworkError::InvalidTraffic)?;
    if command_bytes > MAXIMUM_CONSENSUS_COMMAND_BYTES || entries.len() > 64 {
        return Err(ConsensusNetworkError::InvalidTraffic);
    }
    let upper_bound =
        command_bytes + entries.len() * ENTRY_ENCODING_OVERHEAD + ENVELOPE_ENCODING_OVERHEAD;
    Ok((upper_bound > MAXIMUM_CONTROL_BYTES)
        .then_some((command_bytes + 16 * 1024).min(MAXIMUM_CONSENSUS_BULK_BODY_BYTES)))
}

async fn receive_body(
    receive: &mut quinn::RecvStream,
    length: usize,
    limits: WireLimits,
) -> Result<Vec<u8>, ConsensusNetworkError> {
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        let frame = receive_data_frame(receive, limits).await?.into_inner();
        if frame.offset != bytes.len() as u64 || frame.bytes.len() > length - bytes.len() {
            return Err(ConsensusNetworkError::InvalidTraffic);
        }
        bytes.extend_from_slice(&frame.bytes);
    }
    receive
        .read_to_end(0)
        .await
        .map_err(|_| ConsensusNetworkError::InvalidTraffic)?;
    Ok(bytes)
}

fn check_bulk_deadline(deadline: tokio::time::Instant) -> Result<(), ConsensusNetworkError> {
    if tokio::time::Instant::now() >= deadline {
        return Err(ConsensusNetworkError::BulkTransferUnconfirmed);
    }
    Ok(())
}

fn bulk_deadline() -> Result<i64, ConsensusNetworkError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ConsensusNetworkError::InvalidTraffic)?;
    i64::try_from(now.saturating_add(BULK_TIMEOUT).as_micros())
        .map_err(|_| ConsensusNetworkError::InvalidTraffic)
}

pub(super) fn codec_workers() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(2))
}
