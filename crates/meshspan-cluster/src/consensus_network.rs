// SPDX-License-Identifier: GPL-2.0-only

//! Production-configurable authenticated QUIC transport for consensus messages.

use std::collections::BTreeMap;
use std::net::SocketAddr;
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
use thiserror::Error;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::{
    ConsensusMessageTransport, PeerConsensusMessage, decode_consensus_message,
    encode_consensus_message,
};

const MAXIMUM_CONTROL_BYTES: usize = 64 * 1_024;
const MAXIMUM_DATA_BYTES: usize = 64 * 1_024;
const MAXIMUM_ITEMS: usize = 256;
const MAXIMUM_ITEMS_U32: u32 = 256;
const MAXIMUM_TEXT_BYTES: usize = 4_096;
const MAXIMUM_STREAMS: u32 = 128;
const STREAM_WINDOW: u32 = 64 * 1_024;
const CONNECTION_WINDOW: u32 = 4 * 1_024 * 1_024;
const OUTBOUND_QUEUE_CAPACITY: usize = 32;
const PEER_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const RECONNECT_BACKOFF: Duration = Duration::from_millis(100);

/// One exact enrolled peer route and leaf-certificate binding.
#[derive(Clone)]
pub struct ConsensusPeerConfig {
    /// Permanent enrolled node identity.
    pub node_id: NodeId,
    /// Current process incarnation accepted by consensus.
    pub incarnation: u64,
    /// Private QUIC socket address.
    pub address: SocketAddr,
    /// Current enrolled leaf certificate in DER form.
    pub certificate_der: Vec<u8>,
}

/// Complete private-network input consumed when starting one node transport.
pub struct ConsensusNetworkConfig {
    /// Local permanent node identity.
    pub local_node_id: NodeId,
    /// Local current non-zero process incarnation.
    pub local_incarnation: u64,
    /// Mesh carried by negotiation and every request header.
    pub mesh_id: MeshId,
    /// Metadata partition carried by every request header.
    pub partition_id: PartitionId,
    /// Current exact route epoch.
    pub routing_epoch: u64,
    /// Server socket for authenticated peer connections.
    pub listen_address: SocketAddr,
    /// Client socket, normally an ephemeral local address.
    pub client_address: SocketAddr,
    /// DNS name present in every enrolled peer leaf.
    pub certificate_name: String,
    /// Local enrolled leaf certificate DER.
    pub certificate_der: Vec<u8>,
    /// Local canonical PKCS#8 identity key, cleared when construction completes.
    pub private_key_pkcs8: Zeroizing<Vec<u8>>,
    /// Current CA roots accepted for both peer client and server certificates.
    pub trust_anchors: Vec<Vec<u8>>,
    /// Exact enrolled peers, excluding the local node.
    pub peers: Vec<ConsensusPeerConfig>,
}

/// Cloneable non-blocking consensus message network.
#[derive(Clone)]
pub struct ConsensusNetwork {
    client: quinn::Endpoint,
    registry: Arc<PeerRegistry>,
    peers: Arc<BTreeMap<NodeId, ConsensusPeerConfig>>,
    local_node_id: NodeId,
    local_incarnation: u64,
    mesh_id: MeshId,
    partition_id: PartitionId,
    routing_epoch: u64,
    certificate_name: Arc<str>,
    wire_limits: WireLimits,
    outbound: Arc<BTreeMap<NodeId, mpsc::Sender<CoreMessage>>>,
    next_request: Arc<AtomicU64>,
}

impl ConsensusNetwork {
    /// Starts client/server endpoints and bounded per-peer outbound workers.
    ///
    /// # Errors
    ///
    /// Rejects invalid identities, trust, duplicate routes, keys, limits or socket binding before
    /// any traffic can be accepted.
    pub fn start(
        config: ConsensusNetworkConfig,
        incoming_messages: mpsc::Sender<PeerConsensusMessage>,
    ) -> Result<Self, ConsensusNetworkError> {
        validate_config(&config)?;
        let wire_limits = wire_limits()?;
        let limits = TransportLimits::new(
            wire_limits,
            MAXIMUM_STREAMS,
            STREAM_WINDOW,
            CONNECTION_WINDOW,
        )?;
        let roots = roots(&config.trust_anchors)?;
        let server = server_endpoint(
            config.listen_address,
            credentials(&config)?,
            roots.clone(),
            limits,
        )?;
        let client = client_endpoint(config.client_address, credentials(&config)?, roots, limits)?;
        let peers = peer_map(config.peers)?;
        let registry = Arc::new(peer_registry(&peers)?);
        let mut network = Self {
            client,
            registry,
            peers: Arc::new(peers),
            local_node_id: config.local_node_id,
            local_incarnation: config.local_incarnation,
            mesh_id: config.mesh_id,
            partition_id: config.partition_id,
            routing_epoch: config.routing_epoch,
            certificate_name: Arc::from(config.certificate_name),
            wire_limits,
            outbound: Arc::new(BTreeMap::new()),
            next_request: Arc::new(AtomicU64::new(1)),
        };
        let mut outbound = BTreeMap::new();
        for peer in network.peers.keys().copied() {
            let (sender, receiver) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
            network.spawn_outbound_worker(peer, receiver);
            outbound.insert(peer, sender);
        }
        network.outbound = Arc::new(outbound);
        network.spawn_accept_loop(server, incoming_messages);
        Ok(network)
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

    fn spawn_accept_loop(
        &self,
        server: quinn::Endpoint,
        messages: mpsc::Sender<PeerConsensusMessage>,
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
                tokio::spawn(async move {
                    if connection_network
                        .receive_connection(connection.clone(), peer, connection_messages)
                        .await
                        .is_err()
                    {
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
        messages: mpsc::Sender<PeerConsensusMessage>,
    ) -> Result<(), ConsensusNetworkError> {
        let mut negotiation = accept_stream(&connection).await?;
        if negotiation.kind != StreamKind::Metadata {
            return Err(ConsensusNetworkError::InvalidTraffic);
        }
        let hello = receive_control(&mut negotiation.receive, self.wire_limits).await?;
        let Message::NodeHello(hello) = hello
            .as_inner()
            .message
            .as_ref()
            .ok_or(ConsensusNetworkError::InvalidTraffic)?
        else {
            return Err(ConsensusNetworkError::InvalidTraffic);
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
        negotiation.send.finish()?;

        loop {
            let mut accepted = accept_stream(&connection).await?;
            if accepted.kind != StreamKind::Consensus {
                return Err(ConsensusNetworkError::InvalidTraffic);
            }
            let envelope = receive_control(&mut accepted.receive, self.wire_limits).await?;
            self.verify_header(&envelope, peer.node_id(), peer.incarnation())?;
            let message = decode_consensus_message(&envelope)?;
            messages
                .send(PeerConsensusMessage {
                    from: peer.node_id(),
                    sender_incarnation: peer.incarnation(),
                    message,
                })
                .await
                .map_err(|_| ConsensusNetworkError::AuthorityStopped)?;
            send_receipt(&mut accepted.send, self.wire_limits).await?;
        }
    }

    async fn send_with_connection(
        &self,
        to: NodeId,
        connection: &mut Option<quinn::Connection>,
        message: CoreMessage,
    ) -> Result<(), ConsensusNetworkError> {
        if connection.is_none() {
            *connection = Some(self.connect_peer(to).await?);
        }
        let active = connection
            .as_ref()
            .ok_or(ConsensusNetworkError::InvalidConfiguration)?;
        let (mut send, mut receive) = open_stream(active, StreamKind::Consensus).await?;
        let envelope = ControlEnvelope {
            header: Some(self.request_header()?),
            message: Some(encode_consensus_message(&message)),
        };
        send_control(&mut send, &envelope, self.wire_limits).await?;
        send.finish()?;
        receive_receipt(&mut receive, self.wire_limits).await
    }

    async fn connect_peer(&self, to: NodeId) -> Result<quinn::Connection, ConsensusNetworkError> {
        let peer = self
            .peers
            .get(&to)
            .ok_or(ConsensusNetworkError::InvalidConfiguration)?;
        let connection = connect(&self.client, peer.address, &self.certificate_name).await?;
        let authenticated = self.registry.authenticate_connection(&connection)?;
        if authenticated.node_id() != to || authenticated.incarnation() != peer.incarnation {
            return Err(ConsensusNetworkError::InvalidTraffic);
        }
        self.negotiate_outgoing(&connection).await?;
        Ok(connection)
    }

    async fn negotiate_outgoing(
        &self,
        connection: &quinn::Connection,
    ) -> Result<(), ConsensusNetworkError> {
        let (mut send, mut receive) = open_stream(connection, StreamKind::Metadata).await?;
        send_control(
            &mut send,
            &ControlEnvelope {
                header: None,
                message: Some(Message::NodeHello(self.hello())),
            },
            self.wire_limits,
        )
        .await?;
        let welcome = receive_control(&mut receive, self.wire_limits).await?;
        let Message::NodeWelcome(welcome) = welcome
            .as_inner()
            .message
            .as_ref()
            .ok_or(ConsensusNetworkError::InvalidTraffic)?
        else {
            return Err(ConsensusNetworkError::InvalidTraffic);
        };
        if welcome.peer_node_id.as_slice() != self.local_node_id.as_bytes()
            || welcome.peer_incarnation != self.local_incarnation
            || welcome.selected_version.as_ref() != Some(&ProtocolVersion { major: 1, minor: 0 })
        {
            return Err(ConsensusNetworkError::InvalidTraffic);
        }
        Ok(())
    }

    fn request_header(&self) -> Result<RequestHeader, ConsensusNetworkError> {
        let request_number = self.next_request.fetch_add(1, Ordering::Relaxed).max(1);
        let identifier = request_identifier(request_number);
        Ok(RequestHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            mesh_id: self.mesh_id.as_bytes().to_vec(),
            partition_id: self.partition_id.as_bytes().to_vec(),
            routing_epoch: self.routing_epoch,
            sender_node_id: self.local_node_id.as_bytes().to_vec(),
            sender_incarnation: self.local_incarnation,
            request_id: identifier.to_vec(),
            operation_id: OperationId::from_bytes(identifier)?.as_bytes().to_vec(),
            deadline_unix_micros: i64::MAX,
            trace_id: identifier.to_vec(),
        })
    }

    fn verify_header(
        &self,
        envelope: &meshspan_protocol::ValidatedControlEnvelope,
        peer: NodeId,
        incarnation: u64,
    ) -> Result<(), ConsensusNetworkError> {
        let header = envelope
            .as_inner()
            .header
            .as_ref()
            .ok_or(ConsensusNetworkError::InvalidTraffic)?;
        if header.mesh_id.as_slice() == self.mesh_id.as_bytes()
            && header.partition_id.as_slice() == self.partition_id.as_bytes()
            && header.sender_node_id.as_slice() == peer.as_bytes()
            && header.sender_incarnation == incarnation
            && header.routing_epoch == self.routing_epoch
        {
            Ok(())
        } else {
            Err(ConsensusNetworkError::InvalidTraffic)
        }
    }

    fn hello(&self) -> NodeHello {
        NodeHello {
            versions: vec![ProtocolVersion { major: 1, minor: 0 }],
            mesh_id: self.mesh_id.as_bytes().to_vec(),
            node_id: self.local_node_id.as_bytes().to_vec(),
            incarnation: self.local_incarnation,
            roles: vec![NodeRole::MetadataVoter.into()],
            components: vec![ComponentSupport {
                contract_kind: 1,
                implementation_id: "meshspan-consensus".to_owned(),
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
            routing_epoch: self.routing_epoch,
            maximum_control_bytes: MAXIMUM_CONTROL_BYTES as u64,
            maximum_data_frame_bytes: MAXIMUM_DATA_BYTES as u64,
            maximum_streams: MAXIMUM_STREAMS,
        }
    }
}

impl ConsensusMessageTransport for ConsensusNetwork {
    fn send(&self, to: NodeId, message: CoreMessage) {
        if let Some(sender) = self.outbound.get(&to) {
            let _full_or_closed = sender.try_send(message);
        }
    }
}

fn validate_config(config: &ConsensusNetworkConfig) -> Result<(), ConsensusNetworkError> {
    if config.local_incarnation == 0
        || config.routing_epoch == 0
        || config.certificate_name.is_empty()
        || config.certificate_name.len() > 253
        || config.certificate_der.is_empty()
        || config.private_key_pkcs8.is_empty()
        || config.trust_anchors.is_empty()
        || config.peers.is_empty()
        || config
            .peers
            .iter()
            .any(|peer| peer.node_id == config.local_node_id || peer.incarnation == 0)
    {
        return Err(ConsensusNetworkError::InvalidConfiguration);
    }
    Ok(())
}

fn peer_map(
    peers: Vec<ConsensusPeerConfig>,
) -> Result<BTreeMap<NodeId, ConsensusPeerConfig>, ConsensusNetworkError> {
    let expected = peers.len();
    let peers: BTreeMap<_, _> = peers.into_iter().map(|peer| (peer.node_id, peer)).collect();
    if peers.len() != expected {
        return Err(ConsensusNetworkError::InvalidConfiguration);
    }
    Ok(peers)
}

fn credentials(config: &ConsensusNetworkConfig) -> Result<NodeCredentials, ConsensusNetworkError> {
    NodeCredentials::new(
        vec![CertificateDer::from(config.certificate_der.clone())],
        PrivatePkcs8KeyDer::from(config.private_key_pkcs8.to_vec()).into(),
    )
    .map_err(Into::into)
}

fn roots(certificates: &[Vec<u8>]) -> Result<RootCertStore, ConsensusNetworkError> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(CertificateDer::from(certificate.clone()))
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
    }
    Ok(roots)
}

fn peer_registry(
    peers: &BTreeMap<NodeId, ConsensusPeerConfig>,
) -> Result<PeerRegistry, ConsensusNetworkError> {
    PeerRegistry::new(peers.values().map(|peer| PeerBinding {
        node_id: peer.node_id,
        incarnation: peer.incarnation,
        certificate_fingerprint: certificate_fingerprint(&CertificateDer::from(
            peer.certificate_der.clone(),
        )),
    }))
    .map_err(Into::into)
}

fn wire_limits() -> Result<WireLimits, ConsensusNetworkError> {
    WireLimits::new(
        MAXIMUM_CONTROL_BYTES,
        MAXIMUM_DATA_BYTES,
        MAXIMUM_ITEMS,
        MAXIMUM_TEXT_BYTES,
    )
    .map_err(Into::into)
}

async fn send_receipt(
    send: &mut quinn::SendStream,
    limits: WireLimits,
) -> Result<(), ConsensusNetworkError> {
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
    send.finish()?;
    Ok(())
}

async fn receive_receipt(
    receive: &mut quinn::RecvStream,
    limits: WireLimits,
) -> Result<(), ConsensusNetworkError> {
    let receipt = receive_control(receive, limits).await?;
    if matches!(receipt.as_inner().message, Some(Message::Pong(_))) {
        Ok(())
    } else {
        Err(ConsensusNetworkError::InvalidTraffic)
    }
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

/// Closed private-network failures without certificate, key or command contents.
#[derive(Debug, Error)]
pub enum ConsensusNetworkError {
    /// Identities, routes, trust, bounds or socket configuration are unusable.
    #[error("consensus network configuration is invalid")]
    InvalidConfiguration,
    /// Authenticated peer traffic violated negotiation, header or stream contracts.
    #[error("consensus network traffic is invalid")]
    InvalidTraffic,
    /// The single-owner authority no longer accepts peer messages.
    #[error("consensus authority has stopped")]
    AuthorityStopped,
    /// QUIC or TLS construction/traffic failed.
    #[error("consensus private transport failed")]
    Transport(#[from] meshspan_transport::TransportError),
    /// Protobuf framing or semantic validation failed.
    #[error("consensus private protocol failed")]
    Protocol(#[from] meshspan_protocol::WireContractError),
    /// Consensus message conversion rejected inconsistent wire evidence.
    #[error("consensus message conversion failed")]
    ConsensusWire(#[from] crate::ConsensusWireError),
    /// A locally generated non-secret request identifier was invalid.
    #[error("consensus request identifier failed")]
    Identifier(#[from] meshspan_domain::IdentifierError),
    /// Quinn rejected a finished stream.
    #[error("consensus QUIC stream failed")]
    Quinn(#[from] quinn::ClosedStream),
}

#[cfg(test)]
mod tests;
