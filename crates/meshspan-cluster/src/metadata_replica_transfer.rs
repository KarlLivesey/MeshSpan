// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated same-swarm history pages carried on bounded bulk QUIC streams.

use std::time::Duration;

use meshspan_domain::{NodeId, OperationId, UnixMicros};
use meshspan_metadata::AuthoritativeRepository;
use meshspan_protocol::v1::{
    DataControlEnvelope, DataFrame, ErrorCode, FetchMetadataReplicaPage, MetadataReplicaPageHeader,
    WireError, data_control_envelope::Message,
};
use meshspan_protocol::{
    MAXIMUM_METADATA_REPLICA_BODY_BYTES, WireContractError, WireLimits, encode_data_control_frame,
};
use meshspan_transport::{
    AcceptedStream, AuthenticatedPeer, StreamKind, TransportError, open_stream,
    receive_data_control, receive_data_frame, send_data_control, send_data_frame,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::metadata_replica_wire::{core_cursor, decode_page, encode_page, wire_cursor};
use crate::{ConsensusNetwork, ConsensusNetworkError, MetadataReplicaCursor, MetadataReplicaPage};

/// Maximum network IO duration of one authenticated history transfer.
pub const MAXIMUM_METADATA_REPLICA_TRANSFER_TIME: Duration = Duration::from_secs(30);

/// One historical fetch; request correlation is allocated separately by the network.
pub struct MetadataReplicaFetch {
    /// Voter selected from the consumer's installed membership phase.
    pub source: NodeId,
    /// Exact durable frontier to extend.
    pub after: MetadataReplicaCursor,
    /// Logical read identity, not a mutation or grant.
    pub operation: OperationId,
    /// Current mesh time used for the request deadline.
    pub now: UnixMicros,
}

/// Complete transport result; the application still verifies phase/source and command semantics.
pub struct MetadataReplicaTransfer {
    /// Same-swarm certificate-bound source, revalidated after the transfer.
    pub source: AuthenticatedPeer,
    /// Digest-checked history with its exact requested cursor.
    pub page: MetadataReplicaPage,
}

struct ReceivedReplicaBytes {
    connection: quinn::Connection,
    binding: AuthenticatedPeer,
    bytes: Vec<u8>,
    digest: Vec<u8>,
}

impl ConsensusNetwork {
    /// Fetches historical metadata without granting the supplier election/read authority.
    ///
    /// The caller must own and drain this future on shutdown: bounded parsing is performed on
    /// a blocking worker after network IO and is not cancelled by the network deadline.
    ///
    /// # Errors
    /// Rejects wrong sources, stale route bindings, response substitution, malformed/trailing
    /// frames, excessive bodies and deadlines. No partial page is returned on interruption.
    pub async fn fetch_metadata_replica_page(
        &self,
        source: NodeId,
        after: MetadataReplicaCursor,
        operation: OperationId,
        now: UnixMicros,
    ) -> Result<MetadataReplicaTransfer, MetadataReplicaTransferError> {
        self.fetch_replica_until(
            MetadataReplicaFetch {
                source,
                after,
                operation,
                now,
            },
            std::future::pending(),
        )
        .await
    }

    /// Fetches one page with cooperative shutdown during network IO.
    ///
    /// The caller must still drain this future: a parser already running on a blocking worker
    /// is observed before returning. Cancellation never returns partial history.
    ///
    /// # Errors
    /// Includes normal transfer failures and cancellation/closure of the stop channel.
    pub async fn fetch_metadata_replica_page_until(
        &self,
        request: MetadataReplicaFetch,
        stop: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<MetadataReplicaTransfer, MetadataReplicaTransferError> {
        let cancelled = async {
            while !*stop.borrow() {
                if stop.changed().await.is_err() {
                    break;
                }
            }
        };
        self.fetch_replica_until(request, cancelled).await
    }

    async fn fetch_replica_until(
        &self,
        request: MetadataReplicaFetch,
        cancelled: impl std::future::Future<Output = ()>,
    ) -> Result<MetadataReplicaTransfer, MetadataReplicaTransferError> {
        let MetadataReplicaFetch {
            source,
            after,
            operation,
            now,
        } = request;
        let deadline = now
            .get()
            .checked_add(30_000_000)
            .ok_or(MetadataReplicaTransferError::Rejected)?;
        let request = FetchMetadataReplicaPage {
            header: Some(self.control_header(operation, deadline)?),
            after: Some(wire_cursor(after)),
        };
        let ReceivedReplicaBytes {
            connection,
            binding,
            bytes,
            digest,
        } = tokio::select! {
            biased;
            () = cancelled => return Err(MetadataReplicaTransferError::Cancelled),
            result = tokio::time::timeout(
            MAXIMUM_METADATA_REPLICA_TRANSFER_TIME,
            self.fetch_replica(source, request, after),
            ) => result.map_err(|_| MetadataReplicaTransferError::Deadline)??,
        };
        // Observe the bounded parser even when the IO deadline expires; dropping a join handle
        // would leave unowned CPU work behind. Callers likewise drain this operation on stop.
        let page = tokio::task::spawn_blocking(move || {
            if Sha256::digest(&bytes).as_slice() != digest {
                return Err(MetadataReplicaTransferError::Rejected);
            }
            decode_page(&bytes)
        })
        .await
        .map_err(|_| MetadataReplicaTransferError::Worker)??;
        let source = self.authenticate_data_peer(&connection, source)?;
        if source != binding || page.after != after {
            return Err(MetadataReplicaTransferError::Rejected);
        }
        Ok(MetadataReplicaTransfer { source, page })
    }

    async fn fetch_replica(
        &self,
        source: NodeId,
        request: FetchMetadataReplicaPage,
        after: MetadataReplicaCursor,
    ) -> Result<ReceivedReplicaBytes, MetadataReplicaTransferError> {
        let request_id = request
            .header
            .as_ref()
            .ok_or(MetadataReplicaTransferError::Rejected)?
            .request_id
            .clone();
        let connection = self.connect_data_peer(source).await?;
        let binding = self.authenticate_data_peer(&connection, source)?;
        let (mut send, mut receive) = open_stream(&connection, StreamKind::Data).await?;
        send_data_control(
            &mut send,
            &DataControlEnvelope {
                message: Some(Message::FetchMetadataReplicaPage(request)),
            },
            self.wire_limits(),
        )
        .await?;
        send.finish().map_err(TransportError::from)?;
        let response = receive_data_control(&mut receive, self.wire_limits()).await?;
        let Some(Message::MetadataReplicaPageHeader(header)) = response.into_inner().message else {
            return Err(MetadataReplicaTransferError::Rejected);
        };
        if header.request_id != request_id {
            return Err(MetadataReplicaTransferError::Rejected);
        }
        if let Some(error) = header.rejection {
            require_eof(&mut receive).await?;
            return Err(MetadataReplicaTransferError::Remote(error.code));
        }
        if core_cursor(header.after.as_ref())? != after {
            return Err(MetadataReplicaTransferError::Rejected);
        }
        let bytes = receive_body(&mut receive, &header, self.wire_limits()).await?;
        require_eof(&mut receive).await?;
        Ok(ReceivedReplicaBytes {
            connection,
            binding,
            bytes,
            digest: header.digest,
        })
    }
}

/// Rechecks current same-swarm node/certificate binding before a historical source lookup.
///
/// Run on a blocking worker. Recovery-installed nodes use normal active certificate records;
/// no fabricated legacy activation row or gateway role is required. This authorises replication
/// only, not a user operation or destructive permit.
///
/// # Errors
/// Rejects wrong mesh/partition/route, retired or stale identity, expired certificate/deadline,
/// unknown roles and malformed headers before reading or serialising historical commands.
pub fn admit_metadata_replica_request(
    repository: &AuthoritativeRepository,
    peer: AuthenticatedPeer,
    routing_epoch: u64,
    request: &FetchMetadataReplicaPage,
    now: UnixMicros,
) -> Result<MetadataReplicaCursor, MetadataReplicaTransferError> {
    // Use the same strict validation for direct callers as the network dispatcher.
    encode_data_control_frame(
        &DataControlEnvelope {
            message: Some(Message::FetchMetadataReplicaPage(request.clone())),
        },
        WireLimits::new(64 * 1024, 64 * 1024, 64, 1024)?,
    )?;
    let header = request
        .header
        .as_ref()
        .ok_or(MetadataReplicaTransferError::Rejected)?;
    let mesh = repository
        .local_mesh_id()?
        .ok_or(MetadataReplicaTransferError::Rejected)?;
    let certificate = repository
        .active_node_certificate(peer.node_id())?
        .ok_or(MetadataReplicaTransferError::Rejected)?;
    let remaining = header
        .deadline_unix_micros
        .checked_sub(now.get())
        .ok_or(MetadataReplicaTransferError::Rejected)?;
    if header.mesh_id.as_slice() != mesh.as_bytes()
        || header.partition_id.as_slice() != repository.partition_id().as_bytes()
        || header.routing_epoch != routing_epoch
        || header.sender_node_id.as_slice() != peer.node_id().as_bytes()
        || header.sender_incarnation != peer.incarnation()
        || certificate.incarnation != peer.incarnation()
        || certificate.certificate_fingerprint != peer.certificate_fingerprint()
        || certificate.valid_until <= now
        || !(1..=30_000_000).contains(&remaining)
    {
        return Err(MetadataReplicaTransferError::Rejected);
    }
    core_cursor(request.after.as_ref())
}

/// Encoded historical response prepared on the caller's owned blocking worker.
pub struct PreparedMetadataReplicaPage {
    header: MetadataReplicaPageHeader,
    bytes: Vec<u8>,
}

impl PreparedMetadataReplicaPage {
    /// Validates and encodes an authorised page without performing network IO.
    ///
    /// # Errors
    /// Rejects a substituted cursor, malformed page or excessive encoded body.
    pub fn new(
        request: FetchMetadataReplicaPage,
        page: &MetadataReplicaPage,
        limits: WireLimits,
    ) -> Result<Self, MetadataReplicaTransferError> {
        encode_data_control_frame(
            &DataControlEnvelope {
                message: Some(Message::FetchMetadataReplicaPage(request.clone())),
            },
            limits,
        )?;
        if page.after != core_cursor(request.after.as_ref())? {
            return Err(MetadataReplicaTransferError::Rejected);
        }
        let bytes = encode_page(page)?;
        let header = MetadataReplicaPageHeader {
            request_id: request
                .header
                .ok_or(MetadataReplicaTransferError::Rejected)?
                .request_id,
            after: request.after,
            byte_length: u64::try_from(bytes.len())
                .map_err(|_| MetadataReplicaTransferError::Rejected)?,
            digest: Sha256::digest(&bytes).to_vec(),
            maximum_frame_bytes: limits.maximum_data_frame_bytes().min(64 * 1024) as u64,
            rejection: None,
        };
        Ok(Self { header, bytes })
    }
}

/// Sends an already authorised historical page in independently bounded frames, followed by EOF.
///
/// The caller owns admission, a concurrency permit and cancellation/deadline for the stream.
///
/// # Errors
/// Rejects wrong stream/cursor, invalid page structure, encoding limits or interrupted transport.
pub async fn send_metadata_replica_page(
    mut stream: AcceptedStream,
    prepared: PreparedMetadataReplicaPage,
    limits: WireLimits,
) -> Result<(), MetadataReplicaTransferError> {
    if stream.kind != StreamKind::Data {
        return Err(MetadataReplicaTransferError::Rejected);
    }
    let PreparedMetadataReplicaPage { header, bytes } = prepared;
    let maximum_frame_bytes = usize::try_from(header.maximum_frame_bytes)
        .map_err(|_| MetadataReplicaTransferError::Rejected)?;
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::MetadataReplicaPageHeader(header)),
        },
        limits,
    )
    .await?;
    for (index, chunk) in bytes.chunks(maximum_frame_bytes).enumerate() {
        send_data_frame(
            &mut stream.send,
            &DataFrame {
                offset: (index * maximum_frame_bytes) as u64,
                bytes: chunk.to_vec(),
            },
            limits,
        )
        .await?;
    }
    stream.send.finish().map_err(TransportError::from)?;
    Ok(())
}

/// Sends a bounded rejection with no historical data attached.
///
/// # Errors
/// Rejects an invalid correlation/error code or interrupted transport.
pub async fn reject_metadata_replica_page(
    mut stream: AcceptedStream,
    request_id: Vec<u8>,
    code: ErrorCode,
    limits: WireLimits,
) -> Result<(), MetadataReplicaTransferError> {
    if stream.kind != StreamKind::Data {
        return Err(MetadataReplicaTransferError::Rejected);
    }
    send_data_control(
        &mut stream.send,
        &DataControlEnvelope {
            message: Some(Message::MetadataReplicaPageHeader(
                MetadataReplicaPageHeader {
                    request_id,
                    after: None,
                    byte_length: 0,
                    digest: vec![],
                    maximum_frame_bytes: 0,
                    rejection: Some(WireError {
                        code: code.into(),
                        diagnostic_code: 1,
                        retry_after_micros: None,
                    }),
                },
            )),
        },
        limits,
    )
    .await?;
    stream.send.finish().map_err(TransportError::from)?;
    Ok(())
}

async fn receive_body(
    receive: &mut quinn::RecvStream,
    header: &MetadataReplicaPageHeader,
    limits: WireLimits,
) -> Result<Vec<u8>, MetadataReplicaTransferError> {
    let length =
        usize::try_from(header.byte_length).map_err(|_| MetadataReplicaTransferError::Rejected)?;
    if length == 0 || length > MAXIMUM_METADATA_REPLICA_BODY_BYTES {
        return Err(MetadataReplicaTransferError::Rejected);
    }
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        let frame = receive_data_frame(receive, limits).await?.into_inner();
        if frame.offset != bytes.len() as u64
            || frame.bytes.len() as u64 > header.maximum_frame_bytes
            || frame.bytes.len() > length - bytes.len()
        {
            return Err(MetadataReplicaTransferError::Rejected);
        }
        bytes.extend_from_slice(&frame.bytes);
    }
    Ok(bytes)
}

/// Requires request/response end markers before admitting work or returning a page.
pub(crate) async fn require_eof(
    receive: &mut quinn::RecvStream,
) -> Result<(), MetadataReplicaTransferError> {
    receive
        .read_to_end(0)
        .await
        .map_err(|_| MetadataReplicaTransferError::Rejected)?;
    Ok(())
}

/// Closed non-secret transfer errors; no partial history is exposed on failure.
#[derive(Debug, Error)]
pub enum MetadataReplicaTransferError {
    /// Owning cycle stopped or its stop channel closed before a complete transfer.
    #[error("metadata replica transfer cancelled")]
    Cancelled,
    /// Invalid authority, request, response, body or framing.
    #[error("metadata replica transfer rejected")]
    Rejected,
    /// Peer returned a bounded protocol error code without a body.
    #[error("metadata replica source rejected the request with code {0}")]
    Remote(i32),
    /// Whole-transfer deadline expired.
    #[error("metadata replica transfer deadline expired")]
    Deadline,
    /// Owned parser/encoder worker stopped unexpectedly.
    #[error("metadata replica transfer worker failed")]
    Worker,
    /// Private connection/routing failed.
    #[error("metadata replica connection failed")]
    Network(#[from] ConsensusNetworkError),
    /// Framing rejected untrusted bytes.
    #[error("metadata replica wire contract failed")]
    Wire(#[from] WireContractError),
    /// QUIC transfer was interrupted or malformed.
    #[error("metadata replica transport failed")]
    Transport(#[from] TransportError),
    /// Current certificate/identity metadata was unavailable.
    #[error("metadata replica authority lookup failed")]
    Repository(#[from] meshspan_metadata::RepositoryError),
}
