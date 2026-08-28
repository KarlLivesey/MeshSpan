// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated Quinn peer connections and mandatory hello negotiation.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use meshspan_consensus::CoreMessage;
use meshspan_domain::{MeshId, NodeId, OperationId, PartitionId};
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{
    ComponentSupport, ControlEnvelope, NodeHello, NodeRole, Pong, ProtocolVersion, RequestHeader,
};
use meshspan_transport::{
    NegotiationConfig, NodeCredentials, PeerBinding, PeerRegistry, StreamKind, TransportLimits,
    accept_stream, certificate_fingerprint, client_endpoint, connect, open_stream, receive_control,
    send_control, server_endpoint,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::sync::mpsc;

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
const RECONNECT_BACKOFF: Duration = Duration::from_millis(100);

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub(super) struct PeerMessage {
    pub from: NodeId,
    pub sender_incarnation: u64,
    pub message: CoreMessage,
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
}

impl PeerNetwork {
    pub fn start(
        config: &NodeConfig,
        messages: mpsc::Sender<PeerMessage>,
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
        };
        let mut outbound = BTreeMap::new();
        for peer in config.peers.keys().copied() {
            let (sender, receiver) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
            network.spawn_outbound_worker(peer, receiver);
            outbound.insert(peer, sender);
        }
        network.outbound = Arc::new(outbound);
        network.spawn_accept_loop(server, messages);
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

    fn spawn_accept_loop(&self, server: quinn::Endpoint, messages: mpsc::Sender<PeerMessage>) {
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
                tokio::spawn(async move {
                    let result = connection_network
                        .receive_connection(connection.clone(), peer, connection_messages)
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
            if accepted.kind != StreamKind::Consensus {
                return Err(NodeRuntimeError::InvalidConfiguration);
            }
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
            header: Some(RequestHeader {
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
            }),
            message: Some(encode_consensus_message(&message)),
        };
        send_control(&mut send, &envelope, self.wire_limits).await?;
        send.finish()
            .map_err(meshspan_transport::TransportError::from)?;
        receive_receipt(&mut receive, self.wire_limits).await?;
        Ok(())
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
