// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated Quinn peer connections and mandatory hello negotiation.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use meshspan_consensus::CoreMessage;
use meshspan_domain::{MeshId, NodeId, OperationId, PartitionId};
use meshspan_metadata::PartitionSnapshotManifest;
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{
    ComponentSupport, ControlEnvelope, LogPosition, NodeHello, NodeRole, Pong, ProtocolVersion,
    RequestHeader, SnapshotBegin, SnapshotChunk, SnapshotFinish, SnapshotResult,
};
use meshspan_transport::{
    NegotiationConfig, NodeCredentials, PeerBinding, PeerRegistry, SnapshotStager, StreamKind,
    TransportLimits, VerifiedSnapshot, accept_stream, certificate_fingerprint, client_endpoint,
    connect, open_stream, receive_control, send_control, server_endpoint,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, oneshot};

use super::NodeRuntimeError;
use super::config::{NodeConfig, PeerConfig};
use crate::{decode_consensus_message, encode_consensus_message};

const CERTIFICATE_NAME: &str = "meshspan.internal";
const MAXIMUM_CONTROL_BYTES: usize = 64 * 1_024;
const MAXIMUM_DATA_BYTES: usize = 64 * 1_024;
const MAXIMUM_ITEMS: usize = 256;
const MAXIMUM_ITEMS_U32: u32 = 256;
const MAXIMUM_TEXT_BYTES: usize = 4_096;
const MAXIMUM_STREAMS: u32 = 128;
const STREAM_WINDOW: u32 = 64 * 1_024;
const CONNECTION_WINDOW: u32 = 4 * 1_024 * 1_024;
const INCARNATION: u64 = 1;
const OUTBOUND_QUEUE_CAPACITY: usize = 8;
const PEER_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const SNAPSHOT_OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
const RECONNECT_BACKOFF: Duration = Duration::from_millis(100);
const MAXIMUM_SNAPSHOT_BYTES: u64 = 512 * 1_024 * 1_024;
const SNAPSHOT_CHUNK_BYTES: usize = 48 * 1_024;

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub(super) struct PeerMessage {
    pub from: NodeId,
    pub sender_incarnation: u64,
    pub message: CoreMessage,
}

pub(super) struct OutboundSnapshot {
    pub path: PathBuf,
    pub manifest: PartitionSnapshotManifest,
    pub quorum_plan: Vec<u8>,
}

pub(super) struct ReceivedSnapshot {
    pub from: NodeId,
    pub snapshot: VerifiedSnapshot,
    pub installed: oneshot::Sender<()>,
}

#[derive(Clone)]
pub(super) struct PeerNetwork {
    client: quinn::Endpoint,
    registry: Arc<PeerRegistry>,
    peers: Arc<BTreeMap<NodeId, PeerConfig>>,
    local_node_id: NodeId,
    mesh_id: MeshId,
    partition_id: PartitionId,
    wire_limits: WireLimits,
    outbound: Arc<BTreeMap<NodeId, mpsc::Sender<CoreMessage>>>,
    outbound_snapshots: Arc<BTreeMap<NodeId, mpsc::Sender<OutboundSnapshot>>>,
}

impl PeerNetwork {
    pub fn start(
        config: &NodeConfig,
        messages: mpsc::Sender<PeerMessage>,
        snapshots: mpsc::Sender<ReceivedSnapshot>,
    ) -> Result<Self, NodeRuntimeError> {
        let wire_limits = wire_limits()?;
        let limits = TransportLimits::new(
            wire_limits,
            MAXIMUM_STREAMS,
            STREAM_WINDOW,
            CONNECTION_WINDOW,
        )?;
        let authority = certificate(&config.authority_path)?;
        let roots = roots(&authority)?;
        let registry = Arc::new(peer_registry(&config.peers)?);
        let server = server_endpoint(
            config.listen_address,
            credentials(config)?,
            roots.clone(),
            limits,
        )?;
        let client = client_endpoint(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            credentials(config)?,
            roots,
            limits,
        )?;
        let mesh_id = MeshId::from_bytes([9; 16])?;
        let partition_id = PartitionId::from_bytes([8; 16])?;
        let mut network = Self {
            client,
            registry,
            peers: Arc::new(config.peers.clone()),
            local_node_id: config.node_id,
            mesh_id,
            partition_id,
            wire_limits,
            outbound: Arc::new(BTreeMap::new()),
            outbound_snapshots: Arc::new(BTreeMap::new()),
        };
        let mut outbound = BTreeMap::new();
        let mut outbound_snapshots = BTreeMap::new();
        for peer in config.peers.keys().copied() {
            let (sender, receiver) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
            network.spawn_outbound_worker(peer, receiver);
            outbound.insert(peer, sender);
            let (snapshot_sender, snapshot_receiver) = mpsc::channel(1);
            network.spawn_snapshot_worker(peer, snapshot_receiver);
            outbound_snapshots.insert(peer, snapshot_sender);
        }
        network.outbound = Arc::new(outbound);
        network.outbound_snapshots = Arc::new(outbound_snapshots);
        network.spawn_accept_loop(server, messages, snapshots, config.state_path.clone());
        Ok(network)
    }

    /// Enqueues one lossy consensus datagram for its peer worker.
    ///
    /// A full/disconnected queue drops the message. Consensus heartbeats and election retries
    /// repair that loss without allowing an unreachable peer to block the single-owner core.
    pub fn send(&self, to: NodeId, message: CoreMessage) {
        if let Some(sender) = self.outbound.get(&to) {
            let _full_or_closed = sender.try_send(message);
        }
    }

    pub fn send_snapshot(&self, to: NodeId, snapshot: OutboundSnapshot) {
        if let Some(sender) = self.outbound_snapshots.get(&to) {
            let _full_or_closed = sender.try_send(snapshot);
        }
    }

    fn spawn_outbound_worker(&self, peer: NodeId, mut messages: mpsc::Receiver<CoreMessage>) {
        let network = self.clone();
        tokio::spawn(async move {
            let mut connection = None;
            while let Some(message) = messages.recv().await {
                let result = tokio::time::timeout(
                    PEER_OPERATION_TIMEOUT,
                    network.send_with_connection(peer, &mut connection, message),
                )
                .await;
                if !matches!(result, Ok(Ok(()))) {
                    connection = None;
                    tokio::time::sleep(RECONNECT_BACKOFF).await;
                }
            }
        });
    }

    fn spawn_snapshot_worker(&self, peer: NodeId, mut snapshots: mpsc::Receiver<OutboundSnapshot>) {
        let network = self.clone();
        tokio::spawn(async move {
            while let Some(snapshot) = snapshots.recv().await {
                let result = tokio::time::timeout(
                    SNAPSHOT_OPERATION_TIMEOUT,
                    network.send_snapshot_to_peer(peer, &snapshot),
                )
                .await;
                if matches!(result, Ok(Ok(()))) {
                    let _cleanup = tokio::fs::remove_file(&snapshot.path).await;
                }
            }
        });
    }

    fn spawn_accept_loop(
        &self,
        server: quinn::Endpoint,
        messages: mpsc::Sender<PeerMessage>,
        snapshots: mpsc::Sender<ReceivedSnapshot>,
        state_path: PathBuf,
    ) {
        let network = self.clone();
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                let Ok(connection) = incoming.await else {
                    continue;
                };
                let Ok(peer) = network.registry.authenticate_connection(&connection) else {
                    connection.close(1_u32.into(), b"unknown peer");
                    continue;
                };
                let connection_network = network.clone();
                let connection_messages = messages.clone();
                let connection_snapshots = snapshots.clone();
                let connection_state_path = state_path.clone();
                tokio::spawn(async move {
                    let result = connection_network
                        .receive_connection(
                            connection.clone(),
                            peer,
                            connection_messages,
                            connection_snapshots,
                            connection_state_path,
                        )
                        .await;
                    if result.is_err() {
                        connection.close(2_u32.into(), b"invalid peer traffic");
                    }
                });
            }
        });
    }

    async fn receive_connection(
        &self,
        connection: quinn::Connection,
        peer: meshspan_transport::AuthenticatedPeer,
        messages: mpsc::Sender<PeerMessage>,
        snapshots: mpsc::Sender<ReceivedSnapshot>,
        state_path: PathBuf,
    ) -> Result<(), NodeRuntimeError> {
        let mut negotiation = accept_stream(&connection).await?;
        if negotiation.kind != StreamKind::Metadata {
            return Err(NodeRuntimeError::InvalidConfiguration);
        }
        let hello = receive_control(&mut negotiation.receive, self.wire_limits).await?;
        let Message::NodeHello(hello) = hello
            .as_inner()
            .message
            .as_ref()
            .ok_or(NodeRuntimeError::InvalidConfiguration)?
        else {
            return Err(NodeRuntimeError::InvalidConfiguration);
        };
        let welcome = peer.negotiate(self.mesh_id, hello, &self.negotiation_config())?;
        send_control(
            &mut negotiation.send,
            &ControlEnvelope {
                header: None,
                message: Some(Message::NodeWelcome(welcome)),
            },
            self.wire_limits,
        )
        .await?;
        negotiation
            .send
            .finish()
            .map_err(meshspan_transport::TransportError::from)?;

        loop {
            let mut accepted = accept_stream(&connection).await?;
            match accepted.kind {
                StreamKind::Consensus => {
                    let envelope = receive_control(&mut accepted.receive, self.wire_limits).await?;
                    self.verify_header(&envelope, peer.node_id(), peer.incarnation())?;
                    let message = decode_consensus_message(&envelope)
                        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
                    messages
                        .send(PeerMessage {
                            from: peer.node_id(),
                            sender_incarnation: peer.incarnation(),
                            message,
                        })
                        .await
                        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
                    send_receipt(&mut accepted.send, self.wire_limits).await?;
                }
                StreamKind::Snapshot => {
                    self.receive_snapshot(peer.node_id(), &state_path, &mut accepted, &snapshots)
                        .await?;
                }
                StreamKind::Metadata | StreamKind::Data => {
                    return Err(NodeRuntimeError::InvalidConfiguration);
                }
            }
        }
    }

    async fn send_with_connection(
        &self,
        to: NodeId,
        connection: &mut Option<quinn::Connection>,
        message: CoreMessage,
    ) -> Result<(), NodeRuntimeError> {
        if connection.is_none() {
            *connection = Some(self.connect_peer(to).await?);
        }
        let active = connection
            .as_ref()
            .ok_or(NodeRuntimeError::InvalidConfiguration)?;
        self.send_message(active, message).await
    }

    async fn send_snapshot_to_peer(
        &self,
        to: NodeId,
        snapshot: &OutboundSnapshot,
    ) -> Result<(), NodeRuntimeError> {
        let connection = self.connect_peer(to).await?;
        let (mut send, mut receive) = open_stream(&connection, StreamKind::Snapshot).await?;
        let manifest = snapshot.manifest;
        let begin = SnapshotBegin {
            snapshot_id: manifest.snapshot_id.as_bytes().to_vec(),
            included_position: Some(LogPosition {
                term: manifest.backup.applied_position.term,
                index: manifest.backup.applied_position.index,
            }),
            state_revision: manifest.backup.state_revision.get(),
            total_bytes: manifest.backup.byte_length,
            digest: manifest.backup.digest.to_vec(),
            format_version: manifest.backup.schema_version,
            membership_epoch: manifest.membership_epoch,
            quorum_plan_digest: manifest.quorum_plan_digest.to_vec(),
            quorum_plan: snapshot.quorum_plan.clone(),
        };
        self.send_snapshot_envelope(&mut send, Message::SnapshotBegin(begin))
            .await?;
        let mut file = tokio::fs::File::open(&snapshot.path).await?;
        let mut buffer = vec![0_u8; SNAPSHOT_CHUNK_BYTES];
        let mut offset = 0_u64;
        loop {
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            let bytes = buffer[..read].to_vec();
            self.send_snapshot_envelope(
                &mut send,
                Message::SnapshotChunk(SnapshotChunk {
                    snapshot_id: manifest.snapshot_id.as_bytes().to_vec(),
                    offset,
                    chunk_digest: Sha256::digest(&bytes).to_vec(),
                    bytes,
                }),
            )
            .await?;
            offset = offset
                .checked_add(
                    u64::try_from(read).map_err(|_| NodeRuntimeError::InvalidConfiguration)?,
                )
                .ok_or(NodeRuntimeError::InvalidConfiguration)?;
        }
        self.send_snapshot_envelope(
            &mut send,
            Message::SnapshotFinish(SnapshotFinish {
                snapshot_id: manifest.snapshot_id.as_bytes().to_vec(),
                total_bytes: manifest.backup.byte_length,
                digest: manifest.backup.digest.to_vec(),
            }),
        )
        .await?;
        send.finish()
            .map_err(meshspan_transport::TransportError::from)?;
        let result = receive_control(&mut receive, self.wire_limits).await?;
        let Message::SnapshotResult(result) = result
            .as_inner()
            .message
            .as_ref()
            .ok_or(NodeRuntimeError::InvalidConfiguration)?
        else {
            return Err(NodeRuntimeError::InvalidConfiguration);
        };
        if result.installed
            && result.snapshot_id.as_slice() == manifest.snapshot_id.as_bytes()
            && result.included_position.as_ref()
                == Some(&LogPosition {
                    term: manifest.backup.applied_position.term,
                    index: manifest.backup.applied_position.index,
                })
        {
            Ok(())
        } else {
            Err(NodeRuntimeError::InvalidConfiguration)
        }
    }

    async fn send_snapshot_envelope(
        &self,
        send: &mut quinn::SendStream,
        message: Message,
    ) -> Result<(), NodeRuntimeError> {
        send_control(
            send,
            &ControlEnvelope {
                header: Some(self.request_header()?),
                message: Some(message),
            },
            self.wire_limits,
        )
        .await?;
        Ok(())
    }

    async fn receive_snapshot(
        &self,
        peer: NodeId,
        state_path: &std::path::Path,
        stream: &mut meshspan_transport::AcceptedStream,
        snapshots: &mpsc::Sender<ReceivedSnapshot>,
    ) -> Result<(), NodeRuntimeError> {
        let first = receive_control(&mut stream.receive, self.wire_limits).await?;
        self.verify_header(&first, peer, INCARNATION)?;
        let Message::SnapshotBegin(begin) = first
            .as_inner()
            .message
            .as_ref()
            .ok_or(NodeRuntimeError::InvalidConfiguration)?
        else {
            return Err(NodeRuntimeError::InvalidConfiguration);
        };
        let staging_path = snapshot_staging_path(state_path, &begin.snapshot_id)?;
        remove_stale_stage(&staging_path)?;
        let mut stager = SnapshotStager::begin(
            &staging_path,
            begin,
            MAXIMUM_SNAPSHOT_BYTES,
            SNAPSHOT_CHUNK_BYTES,
        )?;
        let verified = loop {
            let envelope = receive_control(&mut stream.receive, self.wire_limits).await?;
            self.verify_header(&envelope, peer, INCARNATION)?;
            match envelope
                .as_inner()
                .message
                .as_ref()
                .ok_or(NodeRuntimeError::InvalidConfiguration)?
            {
                Message::SnapshotChunk(chunk) => stager.append_chunk(chunk)?,
                Message::SnapshotFinish(finish) => break stager.finish(finish)?,
                _ => return Err(NodeRuntimeError::InvalidConfiguration),
            }
        };
        let included_position = verified.included_position;
        let snapshot_id = verified.snapshot_id;
        let (installed, receive_installed) = oneshot::channel();
        snapshots
            .send(ReceivedSnapshot {
                from: peer,
                snapshot: verified,
                installed,
            })
            .await
            .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
        receive_installed
            .await
            .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
        send_control(
            &mut stream.send,
            &ControlEnvelope {
                header: Some(self.request_header()?),
                message: Some(Message::SnapshotResult(SnapshotResult {
                    snapshot_id: snapshot_id.to_vec(),
                    installed: true,
                    included_position: Some(included_position),
                    error: None,
                })),
            },
            self.wire_limits,
        )
        .await?;
        stream
            .send
            .finish()
            .map_err(meshspan_transport::TransportError::from)?;
        Ok(())
    }

    async fn connect_peer(&self, to: NodeId) -> Result<quinn::Connection, NodeRuntimeError> {
        let peer = self
            .peers
            .get(&to)
            .ok_or(NodeRuntimeError::InvalidConfiguration)?;
        let connection = connect(&self.client, peer.address, CERTIFICATE_NAME).await?;
        let authenticated = self.registry.authenticate_connection(&connection)?;
        if authenticated.node_id() != to {
            return Err(NodeRuntimeError::InvalidConfiguration);
        }
        self.negotiate_outgoing(&connection).await?;
        Ok(connection)
    }

    async fn send_message(
        &self,
        connection: &quinn::Connection,
        message: CoreMessage,
    ) -> Result<(), NodeRuntimeError> {
        let (mut send, mut receive) = open_stream(connection, StreamKind::Consensus).await?;
        let request_number = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed).max(1);
        let identifier = request_identifier(request_number);
        let envelope = ControlEnvelope {
            header: Some(self.request_header_for(identifier)?),
            message: Some(encode_consensus_message(&message)),
        };
        send_control(&mut send, &envelope, self.wire_limits).await?;
        send.finish()
            .map_err(meshspan_transport::TransportError::from)?;
        receive_receipt(&mut receive, self.wire_limits).await?;
        Ok(())
    }

    fn request_header(&self) -> Result<RequestHeader, NodeRuntimeError> {
        let request_number = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed).max(1);
        self.request_header_for(request_identifier(request_number))
    }

    fn request_header_for(&self, identifier: [u8; 16]) -> Result<RequestHeader, NodeRuntimeError> {
        Ok(RequestHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            mesh_id: self.mesh_id.as_bytes().to_vec(),
            partition_id: self.partition_id.as_bytes().to_vec(),
            routing_epoch: 1,
            sender_node_id: self.local_node_id.as_bytes().to_vec(),
            sender_incarnation: INCARNATION,
            request_id: identifier.to_vec(),
            operation_id: OperationId::from_bytes(identifier)?.as_bytes().to_vec(),
            deadline_unix_micros: i64::MAX,
            trace_id: identifier.to_vec(),
        })
    }

    async fn negotiate_outgoing(
        &self,
        connection: &quinn::Connection,
    ) -> Result<(), NodeRuntimeError> {
        let (mut send, mut receive) = open_stream(connection, StreamKind::Metadata).await?;
        let hello = self.hello();
        send_control(
            &mut send,
            &ControlEnvelope {
                header: None,
                message: Some(Message::NodeHello(hello)),
            },
            self.wire_limits,
        )
        .await?;
        let welcome = receive_control(&mut receive, self.wire_limits).await?;
        let Message::NodeWelcome(welcome) = welcome
            .as_inner()
            .message
            .as_ref()
            .ok_or(NodeRuntimeError::InvalidConfiguration)?
        else {
            return Err(NodeRuntimeError::InvalidConfiguration);
        };
        if welcome.peer_node_id.as_slice() != self.local_node_id.as_bytes()
            || welcome.peer_incarnation != INCARNATION
            || welcome.selected_version.as_ref() != Some(&ProtocolVersion { major: 1, minor: 0 })
        {
            return Err(NodeRuntimeError::InvalidConfiguration);
        }
        Ok(())
    }

    fn verify_header(
        &self,
        envelope: &meshspan_protocol::ValidatedControlEnvelope,
        peer: NodeId,
        incarnation: u64,
    ) -> Result<(), NodeRuntimeError> {
        let header = envelope
            .as_inner()
            .header
            .as_ref()
            .ok_or(NodeRuntimeError::InvalidConfiguration)?;
        if header.mesh_id.as_slice() == self.mesh_id.as_bytes()
            && header.partition_id.as_slice() == self.partition_id.as_bytes()
            && header.sender_node_id.as_slice() == peer.as_bytes()
            && header.sender_incarnation == incarnation
            && header.routing_epoch == 1
        {
            Ok(())
        } else {
            Err(NodeRuntimeError::InvalidConfiguration)
        }
    }

    fn hello(&self) -> NodeHello {
        NodeHello {
            versions: vec![ProtocolVersion { major: 1, minor: 0 }],
            mesh_id: self.mesh_id.as_bytes().to_vec(),
            node_id: self.local_node_id.as_bytes().to_vec(),
            incarnation: INCARNATION,
            roles: vec![NodeRole::MetadataVoter.into()],
            components: vec![ComponentSupport {
                contract_kind: 1,
                implementation_id: "meshspan-stage3".to_owned(),
                versions: vec![ProtocolVersion { major: 1, minor: 0 }],
                maximum_control_bytes: MAXIMUM_CONTROL_BYTES as u64,
                maximum_items: MAXIMUM_ITEMS_U32,
                maximum_concurrency: MAXIMUM_STREAMS,
            }],
            feature_bits: Vec::new(),
            maximum_control_bytes: MAXIMUM_CONTROL_BYTES as u64,
            maximum_data_frame_bytes: MAXIMUM_DATA_BYTES as u64,
            maximum_streams: MAXIMUM_STREAMS,
        }
    }

    fn negotiation_config(&self) -> NegotiationConfig {
        NegotiationConfig {
            versions: vec![ProtocolVersion { major: 1, minor: 0 }],
            partition_ids: vec![self.partition_id.as_bytes()],
            leader_node_id: None,
            routing_epoch: 1,
            maximum_control_bytes: MAXIMUM_CONTROL_BYTES as u64,
            maximum_data_frame_bytes: MAXIMUM_DATA_BYTES as u64,
            maximum_streams: MAXIMUM_STREAMS,
        }
    }
}

async fn send_receipt(
    send: &mut quinn::SendStream,
    limits: WireLimits,
) -> Result<(), NodeRuntimeError> {
    send_control(
        send,
        &ControlEnvelope {
            header: None,
            message: Some(Message::Pong(Pong {
                nonce: 1,
                sent_monotonic_micros: 1,
                received_monotonic_micros: 1,
            })),
        },
        limits,
    )
    .await?;
    send.finish()
        .map_err(meshspan_transport::TransportError::from)?;
    Ok(())
}

async fn receive_receipt(
    receive: &mut quinn::RecvStream,
    limits: WireLimits,
) -> Result<(), NodeRuntimeError> {
    let receipt = receive_control(receive, limits).await?;
    if matches!(receipt.as_inner().message, Some(Message::Pong(_))) {
        Ok(())
    } else {
        Err(NodeRuntimeError::InvalidConfiguration)
    }
}

fn credentials(config: &NodeConfig) -> Result<NodeCredentials, NodeRuntimeError> {
    let certificate = certificate(&config.certificate_path)?;
    let private_key = std::fs::read(&config.private_key_path)?;
    NodeCredentials::new(
        vec![certificate],
        PrivatePkcs8KeyDer::from(private_key).into(),
    )
    .map_err(Into::into)
}

fn peer_registry(peers: &BTreeMap<NodeId, PeerConfig>) -> Result<PeerRegistry, NodeRuntimeError> {
    let mut bindings = Vec::with_capacity(peers.len());
    for peer in peers.values() {
        let certificate = certificate(&peer.certificate_path)?;
        bindings.push(PeerBinding {
            node_id: peer.node_id,
            incarnation: INCARNATION,
            certificate_fingerprint: certificate_fingerprint(&certificate),
        });
    }
    PeerRegistry::new(bindings).map_err(Into::into)
}

fn certificate(path: &std::path::Path) -> Result<CertificateDer<'static>, NodeRuntimeError> {
    Ok(CertificateDer::from(std::fs::read(path)?))
}

fn roots(certificate: &CertificateDer<'static>) -> Result<RootCertStore, NodeRuntimeError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(certificate.clone())
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    Ok(roots)
}

fn wire_limits() -> Result<WireLimits, NodeRuntimeError> {
    WireLimits::new(
        MAXIMUM_CONTROL_BYTES,
        MAXIMUM_DATA_BYTES,
        MAXIMUM_ITEMS,
        MAXIMUM_TEXT_BYTES,
    )
    .map_err(Into::into)
}

fn request_identifier(value: u64) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    bytes[8..].copy_from_slice(&value.rotate_left(17).to_be_bytes());
    if bytes == [0; 16] {
        bytes[15] = 1;
    }
    bytes
}

fn snapshot_staging_path(
    state_path: &std::path::Path,
    snapshot_id: &[u8],
) -> Result<PathBuf, NodeRuntimeError> {
    let exact: [u8; 16] = snapshot_id
        .try_into()
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    let mut suffix = String::with_capacity(32);
    for byte in exact {
        write!(&mut suffix, "{byte:02x}").map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    }
    Ok(state_path.with_extension(format!("snapshot-{suffix}.stage")))
}

fn remove_stale_stage(staging_path: &std::path::Path) -> Result<(), NodeRuntimeError> {
    match std::fs::symlink_metadata(staging_path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            std::fs::remove_file(staging_path).map_err(Into::into)
        }
        Ok(_) => Err(NodeRuntimeError::InvalidConfiguration),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
