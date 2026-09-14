// SPDX-License-Identifier: GPL-2.0-only

//! Production-configurable authenticated QUIC transport for consensus messages.

mod bulk;
pub(crate) mod bulk_budget;
mod capability_cache;
mod control_connection_use;
pub use capability_cache::{ConsensusCapabilityCacheConfig, LocalNodeCapabilityPresentation};
mod owned;
mod snapshot;
pub use owned::ConsensusNetworkShutdownError;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use meshspan_consensus::CoreMessage;
use meshspan_domain::{MeshId, NodeId, OperationId, PartitionId};
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{
    ComponentSupport, ControlEnvelope, NodeHello, NodeRole, Pong, ProtocolVersion, RequestHeader,
};
use meshspan_protocol::{WireLimits, node_capability_digest};
use meshspan_transport::{
    InstalledNodeCertificate, NegotiationConfig, NodeCredentials, NodeTransportConfig, PeerBinding,
    PeerRegistry, RotatingNodeTransport, StreamKind, TransportLimits, accept_stream,
    certificate_fingerprint, open_stream, receive_control, send_control,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::{
    ConsensusMessageTransport, PeerConsensusMessage, decode_consensus_message,
    encode_consensus_message,
};
pub use snapshot::{OutboundConsensusSnapshot, ReceivedConsensusSnapshot};

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
const CONTROL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

/// One exact enrolled peer route and leaf-certificate binding.
#[derive(Clone, Eq, PartialEq)]
pub struct ConsensusPeerConfig {
    /// Permanent enrolled node identity.
    pub node_id: NodeId,
    /// Current process incarnation accepted by consensus.
    pub incarnation: u64,
    /// Private QUIC socket address.
    pub address: SocketAddr,
    /// Current enrolled leaf certificate in DER form.
    pub certificate_der: Vec<u8>,
    /// Exact DNS identity present in this peer's current leaf certificate.
    pub certificate_name: String,
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
    /// Exact local roles presented during private connection negotiation.
    pub roles: Vec<NodeRole>,
    /// Server socket for authenticated peer connections.
    pub listen_address: SocketAddr,
    /// Client socket, normally an ephemeral local address.
    pub client_address: SocketAddr,
    /// Local enrolled leaf followed by any required intermediate certificate DER.
    pub certificate_chain_der: Vec<Vec<u8>>,
    /// Exact committed local certificate generation, restored with the selected leaf.
    pub certificate_generation: u64,
    /// Exact enrolled local DNS identity certified by every replacement.
    pub certificate_name: String,
    /// Local canonical PKCS#8 identity key, cleared when construction completes.
    pub private_key_pkcs8: Zeroizing<Vec<u8>>,
    /// Current CA roots accepted for both peer client and server certificates.
    pub trust_anchors: Vec<Vec<u8>>,
    /// Exact enrolled peers, excluding the local node.
    pub peers: Vec<ConsensusPeerConfig>,
    /// Database path used only to derive owned temporary snapshot staging files.
    pub snapshot_staging_path: Option<PathBuf>,
    /// Strictly restored local Hello preimages, prepared off the async executor.
    pub capability_cache: Option<ConsensusCapabilityCacheConfig>,
}

/// One authenticated non-consensus control request delivered to the appliance authority.
pub struct PeerControlRequest {
    /// Certificate-bound sender identity.
    pub from: NodeId,
    /// Certificate-bound sender incarnation.
    pub sender_incarnation: u64,
    /// Exact staged leaf-certificate fingerprint established by mTLS routing.
    pub certificate_fingerprint: [u8; 32],
    /// Digest of the validated `NodeHello` on this exact connection.
    pub capability_digest: [u8; 32],
    /// Strictly framed and semantically validated request.
    pub envelope: meshspan_protocol::ValidatedControlEnvelope,
    /// Single bounded response returned on the same QUIC stream.
    pub respond: oneshot::Sender<ControlEnvelope>,
}

/// One authenticated shard-data stream delivered to daemon-local storage routing.
pub struct PeerDataStream {
    /// Certificate-bound sender identity and incarnation.
    pub peer: meshspan_transport::AuthenticatedPeer,
    /// Strictly framed data stream whose first message remains unread for the data-plane router.
    pub stream: meshspan_transport::AcceptedStream,
    /// Exact framing bounds negotiated for this private endpoint.
    pub limits: WireLimits,
    /// Locally configured routing epoch, never copied from the incoming request.
    pub routing_epoch: u64,
}

/// Cloneable non-blocking consensus message network.
#[derive(Clone)]
pub struct ConsensusNetwork {
    owner: Arc<owned::NetworkOwner>,
    transport: RotatingNodeTransport,
    peers: Arc<RwLock<ConsensusPeers>>,
    control_connections: Arc<Mutex<BTreeMap<NodeId, quinn::Connection>>>,
    local_node_id: NodeId,
    local_incarnation: u64,
    mesh_id: MeshId,
    partition_id: PartitionId,
    routing_epoch: u64,
    roles: Arc<RwLock<Vec<i32>>>,
    wire_limits: WireLimits,
    next_request: Arc<AtomicU64>,
    snapshot_staging_path: Option<Arc<PathBuf>>,
    bulk_budgets: Arc<bulk_budget::ConsensusByteBudgets>,
    bulk_codecs: Arc<tokio::sync::Semaphore>,
    capability_cache_path: Option<Arc<PathBuf>>,
    capability_cache_updates: Arc<tokio::sync::Mutex<()>>,
}

/// One authenticated hello's exact transfer presentation; durable membership remains its authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedConsensusTransferSupport {
    /// Digest of the complete validated hello, for comparison with enrolled capability metadata.
    pub capability_digest: [u8; 32],
    /// Explicit optional support. Absence here means that this known presentation lacks bulk support.
    pub support: Option<meshspan_protocol::v1::ConsensusTransferSupport>,
}

#[derive(Clone)]
struct CachedConsensusTransferSupport {
    mesh_id: MeshId,
    binding: PeerBinding,
    observed: ObservedConsensusTransferSupport,
}

struct ConsensusPeers {
    routes: BTreeMap<NodeId, ConsensusPeerConfig>,
    overlapping_fingerprints: BTreeMap<NodeId, [u8; 32]>,
    registry: PeerRegistry,
    outbound: BTreeMap<NodeId, mpsc::Sender<bulk::OutboundConsensusMessage>>,
    transfer_support: BTreeMap<NodeId, CachedConsensusTransferSupport>,
    transfer_preimages: BTreeMap<(NodeId, u64, [u8; 32]), CachedConsensusTransferSupport>,
}

#[derive(Clone)]
struct AuthenticatedStreamIngress {
    peer: meshspan_transport::AuthenticatedPeer,
    capability_digest: [u8; 32],
    messages: mpsc::Sender<PeerConsensusMessage>,
    controls: Option<mpsc::Sender<PeerControlRequest>>,
    snapshots: Option<mpsc::Sender<ReceivedConsensusSnapshot>>,
    data: Option<mpsc::Sender<PeerDataStream>>,
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
        Self::start_inner(config, incoming_messages, None, None, None)
    }

    /// Starts the network with an additional authenticated metadata-control ingress.
    ///
    /// # Errors
    ///
    /// Applies the same fail-closed configuration and transport validation as [`Self::start`].
    pub fn start_with_control(
        config: ConsensusNetworkConfig,
        incoming_messages: mpsc::Sender<PeerConsensusMessage>,
        incoming_control: mpsc::Sender<PeerControlRequest>,
    ) -> Result<Self, ConsensusNetworkError> {
        Self::start_inner(
            config,
            incoming_messages,
            Some(incoming_control),
            None,
            None,
        )
    }

    /// Starts consensus and metadata control with authenticated shard-data ingress.
    ///
    /// # Errors
    ///
    /// Applies the same fail-closed configuration and transport validation as [`Self::start`].
    pub fn start_with_control_and_data(
        config: ConsensusNetworkConfig,
        incoming_messages: mpsc::Sender<PeerConsensusMessage>,
        incoming_control: mpsc::Sender<PeerControlRequest>,
        incoming_data: mpsc::Sender<PeerDataStream>,
    ) -> Result<Self, ConsensusNetworkError> {
        Self::start_inner(
            config,
            incoming_messages,
            Some(incoming_control),
            None,
            Some(incoming_data),
        )
    }

    /// Starts the network with authenticated snapshot ingress for an admitted learner.
    ///
    /// # Errors
    ///
    /// Rejects absent staging configuration and applies every normal private-network check.
    pub fn start_with_snapshots(
        config: ConsensusNetworkConfig,
        incoming_messages: mpsc::Sender<PeerConsensusMessage>,
        incoming_snapshots: mpsc::Sender<ReceivedConsensusSnapshot>,
    ) -> Result<Self, ConsensusNetworkError> {
        if config.snapshot_staging_path.is_none() {
            return Err(ConsensusNetworkError::InvalidConfiguration);
        }
        Self::start_inner(
            config,
            incoming_messages,
            None,
            Some(incoming_snapshots),
            None,
        )
    }

    /// Starts the complete authenticated consensus, control and snapshot ingress.
    ///
    /// # Errors
    ///
    /// Rejects absent staging configuration and applies every normal private-network check.
    pub fn start_with_control_and_snapshots(
        config: ConsensusNetworkConfig,
        incoming_messages: mpsc::Sender<PeerConsensusMessage>,
        incoming_control: mpsc::Sender<PeerControlRequest>,
        incoming_snapshots: mpsc::Sender<ReceivedConsensusSnapshot>,
    ) -> Result<Self, ConsensusNetworkError> {
        if config.snapshot_staging_path.is_none() {
            return Err(ConsensusNetworkError::InvalidConfiguration);
        }
        Self::start_inner(
            config,
            incoming_messages,
            Some(incoming_control),
            Some(incoming_snapshots),
            None,
        )
    }

    /// Starts the complete authenticated consensus, control, snapshot and shard-data ingress.
    ///
    /// # Errors
    ///
    /// Rejects absent staging configuration and applies every normal private-network check.
    pub fn start_with_control_snapshots_and_data(
        config: ConsensusNetworkConfig,
        incoming_messages: mpsc::Sender<PeerConsensusMessage>,
        incoming_control: mpsc::Sender<PeerControlRequest>,
        incoming_snapshots: mpsc::Sender<ReceivedConsensusSnapshot>,
        incoming_data: mpsc::Sender<PeerDataStream>,
    ) -> Result<Self, ConsensusNetworkError> {
        if config.snapshot_staging_path.is_none() {
            return Err(ConsensusNetworkError::InvalidConfiguration);
        }
        Self::start_inner(
            config,
            incoming_messages,
            Some(incoming_control),
            Some(incoming_snapshots),
            Some(incoming_data),
        )
    }

    fn start_inner(
        config: ConsensusNetworkConfig,
        incoming_messages: mpsc::Sender<PeerConsensusMessage>,
        incoming_control: Option<mpsc::Sender<PeerControlRequest>>,
        incoming_snapshots: Option<mpsc::Sender<ReceivedConsensusSnapshot>>,
        incoming_data: Option<mpsc::Sender<PeerDataStream>>,
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
        let transport = RotatingNodeTransport::new(
            NodeTransportConfig {
                server_address: config.listen_address,
                client_address: config.client_address,
                certificate_name: config.certificate_name.clone(),
                certificate_generation: config.certificate_generation,
                peer_roots: roots,
                limits,
            },
            credentials(&config)?,
        )?;
        let server = transport.server_endpoint();
        let peers = peer_map(config.peers)?;
        let registry = peer_registry(&peers)?;
        let (capability_cache_path, transfer_support, transfer_preimages) =
            config.capability_cache.map_or_else(
                || (None, BTreeMap::new(), BTreeMap::new()),
                |cache| {
                    let restored = cache.into_parts();
                    (Some(restored.path), restored.latest, restored.preimages)
                },
            );
        let (owner, registrations) = owned::NetworkOwner::prepare();
        let network = Self {
            owner,
            transport,
            peers: Arc::new(RwLock::new(ConsensusPeers {
                routes: peers,
                overlapping_fingerprints: BTreeMap::new(),
                registry,
                outbound: BTreeMap::new(),
                transfer_support,
                transfer_preimages,
            })),
            control_connections: Arc::new(Mutex::new(BTreeMap::new())),
            local_node_id: config.local_node_id,
            local_incarnation: config.local_incarnation,
            mesh_id: config.mesh_id,
            partition_id: config.partition_id,
            routing_epoch: config.routing_epoch,
            roles: Arc::new(RwLock::new(
                config.roles.into_iter().map(i32::from).collect(),
            )),
            wire_limits,
            next_request: Arc::new(AtomicU64::new(1)),
            snapshot_staging_path: config.snapshot_staging_path.map(Arc::new),
            bulk_budgets: Arc::new(bulk_budget::ConsensusByteBudgets::new()),
            bulk_codecs: bulk::codec_workers(),
            capability_cache_path,
            capability_cache_updates: Arc::new(tokio::sync::Mutex::new(())),
        };
        let prepared = network.prepare_initial_workers(
            server,
            owned::IncomingChannels {
                messages: incoming_messages,
                controls: incoming_control,
                snapshots: incoming_snapshots,
                data: incoming_data,
            },
        );
        if let Err(error) = prepared {
            let closed = network.close();
            drop(registrations);
            closed?;
            return Err(error);
        }
        network
            .owner
            .start(&tokio::runtime::Handle::current(), registrations);
        Ok(network)
    }

    fn prepare_initial_workers(
        &self,
        server: quinn::Endpoint,
        channels: owned::IncomingChannels,
    ) -> Result<(), ConsensusNetworkError> {
        let peer_ids = self
            .peers
            .read()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
            .routes
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let mut workers = Vec::with_capacity(peer_ids.len());
        for peer in peer_ids {
            let (sender, receiver) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
            workers.push((peer, receiver));
            self.peers
                .write()
                .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
                .outbound
                .insert(peer, sender);
        }
        for (peer, receiver) in workers {
            self.spawn_outbound_worker(peer, receiver)?;
        }
        self.owner.register(owned::NetworkTask::Accept {
            network: self.clone(),
            server,
            channels,
        })?;
        Ok(())
    }

    /// Adds or atomically replaces one current enrolled peer route and certificate binding.
    ///
    /// Existing queued traffic is retained for an unchanged identity and replaced for a new
    /// incarnation or certificate. Subsequent ingress admission rechecks the new binding even
    /// on an already negotiated connection. Work admitted before replacement is not rolled back.
    /// The authoritative caller remains responsible for operation-specific fencing.
    ///
    /// # Errors
    ///
    /// Rejects the local node, invalid route/certificate binding, closed admission, exhausted
    /// worker capacity or poisoned peer state. Capacity rejection preserves the old route.
    pub fn upsert_peer(&self, peer: &ConsensusPeerConfig) -> Result<(), ConsensusNetworkError> {
        self.upsert_peer_with_overlap(peer, None)
    }

    /// Installs the committed peer route and its optional make-before-break certificate.
    ///
    /// Both leaves bind the same node and incarnation. The daemon owns generation,
    /// validity and installation-acknowledgement policy; this method neither invents
    /// overlap nor expires it from a local clock. Passing `None` retires prior trust.
    /// Other nodes' staged rotations are preserved.
    ///
    /// # Errors
    ///
    /// Rejects invalid/excessive certificates, identity collisions, closed admission, exhausted
    /// worker capacity and poisoned state. TLS validation precedes use of either fingerprint;
    /// worker-capacity rejection leaves the previous route and outbound queue intact.
    pub fn upsert_peer_with_overlap(
        &self,
        peer: &ConsensusPeerConfig,
        overlapping_certificate_der: Option<&[u8]>,
    ) -> Result<(), ConsensusNetworkError> {
        if peer.node_id == self.local_node_id
            || peer.incarnation == 0
            || peer.certificate_der.is_empty()
            || peer.certificate_der.len() > 65_536
            || overlapping_certificate_der.is_some_and(|der| der.is_empty() || der.len() > 65_536)
            || peer.certificate_name.is_empty()
            || peer.certificate_name.len() > 253
        {
            return Err(ConsensusNetworkError::InvalidConfiguration);
        }
        if self.owner.is_closing() {
            return Err(ConsensusNetworkError::AuthorityStopped);
        }
        let mut peers = self
            .peers
            .write()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
        let overlap = overlapping_certificate_der
            .map(|der| certificate_fingerprint(&CertificateDer::from(der)));
        if peers.routes.get(&peer.node_id) == Some(peer)
            && peers.overlapping_fingerprints.get(&peer.node_id).copied() == overlap
        {
            return Ok(());
        }
        let mut registry = peers.registry.clone();
        let current = PeerBinding {
            node_id: peer.node_id,
            incarnation: peer.incarnation,
            certificate_fingerprint: certificate_fingerprint(&CertificateDer::from(
                peer.certificate_der.as_slice(),
            )),
        };
        let mut bindings = vec![current];
        if let Some(der) = overlapping_certificate_der {
            bindings.push(PeerBinding {
                certificate_fingerprint: certificate_fingerprint(&CertificateDer::from(der)),
                ..current
            });
        }
        registry.replace_node_bindings(peer.node_id, &bindings)?;
        let (sender, receiver) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
        self.spawn_outbound_worker(peer.node_id, receiver)?;
        peers.routes.insert(peer.node_id, peer.clone());
        match overlap {
            Some(fingerprint) => {
                peers
                    .overlapping_fingerprints
                    .insert(peer.node_id, fingerprint);
            }
            None => {
                peers.overlapping_fingerprints.remove(&peer.node_id);
            }
        }
        if peers
            .transfer_support
            .get(&peer.node_id)
            .is_some_and(|cached| !registry.matches_binding(cached.binding))
        {
            peers.transfer_support.remove(&peer.node_id);
        }
        peers.transfer_preimages.retain(|(node, _, _), cached| {
            *node != peer.node_id || registry.matches_binding(cached.binding)
        });
        peers.registry = registry;
        peers.outbound.insert(peer.node_id, sender);
        drop(peers);
        self.control_connections
            .lock()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
            .remove(&peer.node_id);
        Ok(())
    }

    /// Returns the exact local certificate generation selected for fresh private handshakes.
    ///
    /// # Errors
    ///
    /// Fails closed when the live identity state cannot be read safely.
    pub fn local_certificate(&self) -> Result<InstalledNodeCertificate, ConsensusNetworkError> {
        self.transport.current().map_err(Into::into)
    }

    /// Installs a committed newer certificate for the same local node-owned key without restart.
    ///
    /// The caller must first stage required peer trust and durably acknowledge the returned
    /// exact selection afterwards. Existing connections keep their old identity until retired;
    /// selecting credentials does not retry unknown operations or change peer authority.
    ///
    /// # Errors
    ///
    /// Rejects invalid chains/keys/names/lifetimes, identity substitution, stale or conflicting
    /// generations and poisoned state. Rejected replacements leave live configurations intact.
    pub fn install_local_certificate(
        &self,
        generation: u64,
        credentials: NodeCredentials,
    ) -> Result<InstalledNodeCertificate, ConsensusNetworkError> {
        // Lock order is control cache then transport selection, also used when caching a
        // completed handshake. Eviction leaves existing callers' connection clones alive.
        let mut cache = self
            .control_connections
            .lock()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
        let previous = self.transport.current()?;
        let installed = self.transport.install(generation, credentials)?;
        if installed != previous {
            cache.clear();
        }
        Ok(installed)
    }

    /// Sends one validated metadata-control request to an exact enrolled peer.
    ///
    /// # Errors
    ///
    /// Rejects an unknown route, failed mTLS/hello binding, invalid local request, timeout or a
    /// response whose header does not identify the configured peer and incarnation.
    pub async fn request_control(
        &self,
        to: NodeId,
        request: &ControlEnvelope,
    ) -> Result<meshspan_protocol::ValidatedControlEnvelope, ConsensusNetworkError> {
        let connection = self.control_connection(to).await?;
        let mut usage = control_connection_use::ControlConnectionUse::new(
            &self.control_connections,
            to,
            connection.stable_id(),
        );
        let result = self
            .request_control_on_connection(to, request, &connection)
            .await;
        if result.is_ok() {
            usage.confirm_response();
        }
        result
    }

    async fn request_control_on_connection(
        &self,
        to: NodeId,
        request: &ControlEnvelope,
        connection: &quinn::Connection,
    ) -> Result<meshspan_protocol::ValidatedControlEnvelope, ConsensusNetworkError> {
        let (send, mut receive) = tokio::time::timeout(PEER_OPERATION_TIMEOUT, async {
            let (mut send, receive) = open_stream(connection, StreamKind::Metadata).await?;
            send_control(&mut send, request, self.wire_limits).await?;
            send.finish()?;
            Ok::<_, ConsensusNetworkError>((send, receive))
        })
        .await
        .map_err(|_| ConsensusNetworkError::ControlDeliveryUnconfirmed)??;
        let response = tokio::time::timeout(
            CONTROL_RESPONSE_TIMEOUT,
            self.receive_control_response(&send, &mut receive),
        )
        .await
        .map_err(|_| ConsensusNetworkError::AuthorityStopped)??;
        let incarnation = self
            .peers
            .read()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
            .routes
            .get(&to)
            .map(|peer| peer.incarnation)
            .ok_or(ConsensusNetworkError::InvalidConfiguration)?;
        self.verify_header(&response, to, incarnation)?;
        Ok(response)
    }

    async fn receive_control_response(
        &self,
        send: &quinn::SendStream,
        receive: &mut quinn::RecvStream,
    ) -> Result<meshspan_protocol::ValidatedControlEnvelope, ConsensusNetworkError> {
        let response = receive_control(receive, self.wire_limits);
        tokio::pin!(response);
        // finish() queues bytes; it does not prove that a cached connection still
        // reaches the peer. ACK loss leaves the operation unknown, never undone.
        // Race the actual response so successful operations need not wait for a
        // delayed transport ACK. Delivery alone still permits slow authority work.
        tokio::select! {
            response = &mut response => Ok(response?),
            delivery = tokio::time::timeout(PEER_OPERATION_TIMEOUT, send.stopped()) => {
                if !matches!(delivery, Ok(Ok(None))) {
                    return Err(ConsensusNetworkError::ControlDeliveryUnconfirmed);
                }
                Ok(response.await?)
            }
        }
    }

    async fn control_connection(
        &self,
        to: NodeId,
    ) -> Result<quinn::Connection, ConsensusNetworkError> {
        if let Some(connection) = self
            .control_connections
            .lock()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
            .get(&to)
            .filter(|connection| connection.close_reason().is_none())
            .cloned()
        {
            return Ok(connection);
        }
        let selected = self.local_certificate()?;
        let selected_presentation = self.local_capability_digest()?;
        let connection = tokio::time::timeout(PEER_OPERATION_TIMEOUT, self.connect_peer(to))
            .await
            .map_err(|_| ConsensusNetworkError::AuthorityStopped)??;
        let mut cache = self
            .control_connections
            .lock()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
        // Rotation during an in-flight handshake must not repopulate the cache with the
        // retired selection. This request retains its connection; later requests reconnect.
        if self.local_certificate()? == selected
            && self.local_capability_digest()? == selected_presentation
        {
            cache.insert(to, connection.clone());
        }
        Ok(connection)
    }

    /// Proves that one configured peer accepts an mTLS connection and exact hello negotiation.
    ///
    /// # Errors
    ///
    /// Rejects an unknown peer or a failed, timed-out or misbound mTLS connection.
    pub async fn probe_peer(&self, to: NodeId) -> Result<(), ConsensusNetworkError> {
        let connection = tokio::time::timeout(PEER_OPERATION_TIMEOUT, self.connect_peer(to))
            .await
            .map_err(|_| ConsensusNetworkError::AuthorityStopped)??;
        connection.close(0_u32.into(), b"probe complete");
        Ok(())
    }

    /// Opens one mTLS-authenticated, hello-negotiated connection for shard-data RPCs.
    ///
    /// # Errors
    ///
    /// Rejects unknown routes, certificate/identity substitution and negotiation failure.
    pub async fn connect_data_peer(
        &self,
        to: NodeId,
    ) -> Result<quinn::Connection, ConsensusNetworkError> {
        tokio::time::timeout(PEER_OPERATION_TIMEOUT, self.connect_peer(to))
            .await
            .map_err(|_| ConsensusNetworkError::AuthorityStopped)?
    }

    pub(crate) fn authenticate_data_peer(
        &self,
        connection: &quinn::Connection,
        expected_node: NodeId,
    ) -> Result<meshspan_transport::AuthenticatedPeer, ConsensusNetworkError> {
        let peers = self
            .peers
            .read()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
        let peer = peers.registry.authenticate_connection(connection)?;
        if peer.node_id() != expected_node {
            return Err(ConsensusNetworkError::InvalidTraffic);
        }
        Ok(peer)
    }

    /// Returns the exact framing bounds negotiated by every private stream on this endpoint.
    #[must_use]
    pub const fn wire_limits(&self) -> WireLimits {
        self.wire_limits
    }

    /// Builds a fresh request/response header for one exact logical control operation.
    ///
    /// # Errors
    ///
    /// Rejects a non-positive deadline.
    pub fn control_header(
        &self,
        operation_id: OperationId,
        deadline_unix_micros: i64,
    ) -> Result<RequestHeader, ConsensusNetworkError> {
        if deadline_unix_micros <= 0 {
            return Err(ConsensusNetworkError::InvalidConfiguration);
        }
        Ok(self.request_header(operation_id, deadline_unix_micros))
    }

    /// Returns the exact digest of this network's current role/component presentation.
    ///
    /// # Errors
    /// Rejects unavailable current role state.
    pub fn local_capability_digest(&self) -> Result<[u8; 32], ConsensusNetworkError> {
        Ok(node_capability_digest(&self.hello()?))
    }

    /// Replaces roles derived from current admitted metadata and invalidates cached handshakes.
    /// Existing in-flight requests retain their original identity and unknown-outcome semantics.
    ///
    /// # Errors
    /// Rejects invalid, contradictory or oversized roles and unavailable local/cache state.
    pub fn replace_local_roles(&self, roles: &[NodeRole]) -> Result<bool, ConsensusNetworkError> {
        if roles.is_empty() || roles.len() > 4 {
            return Err(ConsensusNetworkError::InvalidConfiguration);
        }
        if (roles.contains(&NodeRole::MetadataVoter) && roles.contains(&NodeRole::MetadataLearner))
            || roles
                .iter()
                .copied()
                .map(i32::from)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != roles.len()
        {
            return Err(ConsensusNetworkError::InvalidConfiguration);
        }
        let roles: Vec<i32> = roles.iter().copied().map(i32::from).collect();
        let mut hello = self.hello()?;
        hello.roles.clone_from(&roles);
        meshspan_protocol::encode_control_frame(
            &ControlEnvelope {
                header: None,
                message: Some(Message::NodeHello(hello)),
            },
            self.wire_limits,
        )?;
        // Match control-connection insertion's lock order; neither guard crosses an await.
        let mut cache = self
            .control_connections
            .lock()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
        let mut current = self
            .roles
            .write()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
        if *current == roles {
            return Ok(false);
        }
        *current = roles;
        cache.clear();
        Ok(true)
    }

    /// Returns this transport's permanent local node identity.
    #[must_use]
    pub const fn local_node_id(&self) -> NodeId {
        self.local_node_id
    }

    /// Returns the partition bound to this transport's control messages.
    #[must_use]
    pub const fn partition_id(&self) -> PartitionId {
        self.partition_id
    }

    /// Stops listeners, connections and outbound queues shared by all clones of this network.
    ///
    /// Initiates shutdown without waiting for owned workers. Use [`Self::shutdown`] before
    /// replacing this generation or claiming its admitted work has finished.
    ///
    /// # Errors
    /// Reports a poisoned queue registry after closing the transport.
    pub fn close(&self) -> Result<(), ConsensusNetworkError> {
        let admission = self.owner.close();
        self.transport.close();
        let outbound = match self.peers.write() {
            Ok(mut peers) => {
                peers.outbound.clear();
                Ok(())
            }
            Err(poisoned) => {
                poisoned.into_inner().outbound.clear();
                Err(ConsensusNetworkError::InvalidConfiguration)
            }
        };
        let connections = match self.control_connections.lock() {
            Ok(mut connections) => {
                connections.clear();
                Ok(())
            }
            Err(poisoned) => {
                poisoned.into_inner().clear();
                Err(ConsensusNetworkError::InvalidConfiguration)
            }
        };
        admission.and(outbound).and(connections)
    }

    /// Stops new network admission and waits for every owned descendant to finish.
    ///
    /// All clones observe one cached terminal outcome. Canceling a waiter does not cancel
    /// drainage. Callers must first finish externally owned control/data handlers, then drop
    /// their network clones after this barrier to release the underlying endpoint sockets.
    ///
    /// # Errors
    /// Fails closed if an owned worker/supervisor failed or admission could not be closed.
    pub async fn shutdown(&self) -> Result<(), ConsensusNetworkShutdownError> {
        let closed = self.close();
        let drained = self.owner.join().await;
        if closed.is_err() {
            Err(ConsensusNetworkShutdownError::AdmissionFailed)
        } else {
            drained
        }
    }

    /// Returns the exact local incarnation carried by this process's private handshakes.
    #[must_use]
    pub const fn local_incarnation(&self) -> u64 {
        self.local_incarnation
    }

    /// Returns a consistent snapshot of every currently enrolled peer route.
    ///
    /// # Errors
    ///
    /// Fails closed if another thread poisoned the route registry lock.
    pub fn peer_routes(&self) -> Result<Vec<ConsensusPeerConfig>, ConsensusNetworkError> {
        Ok(self
            .peers
            .read()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
            .routes
            .values()
            .cloned()
            .collect())
    }

    /// Reads a cached presentation bound to the caller's exact enrolled certificate and incarnation.
    ///
    /// `None` means unknown, never compatible. A known presentation with absent `support` is
    /// explicitly unsupported. Callers must compare its digest with current durable enrollment.
    /// This performs no IO and does not require a fresh socket for each operation.
    ///
    /// # Errors
    /// Fails closed if the current peer registry cannot be read.
    pub fn peer_consensus_transfer_support(
        &self,
        expected: PeerBinding,
    ) -> Result<Option<ObservedConsensusTransferSupport>, ConsensusNetworkError> {
        let peers = self
            .peers
            .read()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
        let Some(cached) = peers.transfer_support.get(&expected.node_id) else {
            return Ok(None);
        };
        if cached.mesh_id != self.mesh_id
            || cached.binding != expected
            || !peers.registry.matches_binding(cached.binding)
        {
            return Ok(None);
        }
        Ok(Some(cached.observed.clone()))
    }

    fn spawn_outbound_worker(
        &self,
        peer: NodeId,
        messages: mpsc::Receiver<bulk::OutboundConsensusMessage>,
    ) -> Result<(), ConsensusNetworkError> {
        self.owner.register(owned::NetworkTask::Outbound {
            network: self.clone(),
            peer,
            messages,
        })
    }

    async fn run_accept_loop(&self, server: quinn::Endpoint, channels: owned::IncomingChannels) {
        while let Some(incoming) = server.accept().await {
            let result = self.owner.register(owned::NetworkTask::Connection {
                network: self.clone(),
                incoming: Box::new(incoming),
                channels: channels.clone(),
            });
            if result.is_err() && self.owner.is_closing() {
                break;
            }
            // Registration owns or explicitly refuses the incoming handshake, including
            // capacity rejection. No unbounded accepted-connection task is detached here.
        }
    }

    async fn run_incoming_connection(
        &self,
        incoming: quinn::Incoming,
        channels: owned::IncomingChannels,
    ) {
        let Ok(Ok(connection)) = tokio::time::timeout(PEER_OPERATION_TIMEOUT, incoming).await
        else {
            return;
        };
        let peer = self
            .peers
            .read()
            .ok()
            .and_then(|peers| peers.registry.authenticate_connection(&connection).ok());
        let Some(peer) = peer else {
            connection.close(1_u32.into(), b"unknown peer");
            return;
        };
        let Ok(_peer_slot) = self.owner.admit_peer(peer.node_id()) else {
            connection.close(3_u32.into(), b"peer capacity unavailable");
            return;
        };
        if self
            .receive_connection(
                connection.clone(),
                peer,
                channels.messages,
                channels.controls,
                channels.snapshots,
                channels.data,
            )
            .await
            .is_err()
        {
            connection.close(2_u32.into(), b"invalid peer traffic");
        }
    }

    async fn receive_connection(
        &self,
        connection: quinn::Connection,
        peer: meshspan_transport::AuthenticatedPeer,
        messages: mpsc::Sender<PeerConsensusMessage>,
        controls: Option<mpsc::Sender<PeerControlRequest>>,
        snapshots: Option<mpsc::Sender<ReceivedConsensusSnapshot>>,
        data: Option<mpsc::Sender<PeerDataStream>>,
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
        self.verify_current_peer(peer)?;
        let mut welcome = peer.negotiate(self.mesh_id, hello, &self.negotiation_config())?;
        welcome.consensus_transfer = Some(meshspan_protocol::consensus_transfer_support());
        let capability_digest = node_capability_digest(hello);
        self.record_transfer_support(peer, hello).await?;
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

        let ingress = AuthenticatedStreamIngress {
            peer,
            capability_digest,
            messages,
            controls,
            snapshots,
            data,
        };

        let mut streams = tokio::task::JoinSet::new();
        let result = loop {
            tokio::select! {
                outcome = streams.join_next(), if !streams.is_empty() => {
                    if let Some(Err(_)) = outcome { break Err(ConsensusNetworkError::InvalidTraffic); }
                }
                accepted = accept_stream(&connection), if streams.len() < MAXIMUM_STREAMS as usize => {
                    let accepted = match accepted { Ok(stream) => stream, Err(error) => break Err(error.into()) };
                    let network = self.clone();
                    let connection = connection.clone();
                    let ingress = ingress.clone();
                    streams.spawn(async move {
                        if let Err(error) = network.receive_authenticated_stream(accepted, ingress).await
                            && !error.is_stream_cancellation() {
                            connection.close(2_u32.into(), b"invalid peer traffic");
                        }
                    });
                }
            }
        };
        // Codec workers retain their reservations until their result has been observed.
        while let Some(outcome) = streams.join_next().await {
            if outcome.is_err() {
                connection.close(2_u32.into(), b"peer worker failed");
            }
        }
        result
    }

    async fn receive_authenticated_stream(
        &self,
        mut accepted: meshspan_transport::AcceptedStream,
        ingress: AuthenticatedStreamIngress,
    ) -> Result<(), ConsensusNetworkError> {
        self.verify_current_peer(ingress.peer)?;
        match accepted.kind {
            StreamKind::Consensus => {
                let envelope = receive_control(&mut accepted.receive, self.wire_limits).await?;
                self.verify_peer_header(&envelope, ingress.peer)?;
                let message = decode_consensus_message(&envelope)?;
                self.admit_peer_message(
                    ingress.peer,
                    &ingress.messages,
                    PeerConsensusMessage::new(
                        ingress.peer.node_id(),
                        ingress.peer.incarnation(),
                        message,
                    ),
                )
                .await?;
                send_receipt(&mut accepted.send, self.wire_limits).await
            }
            StreamKind::ConsensusBulk => self.receive_bulk(accepted, ingress).await,
            StreamKind::Metadata => self.receive_metadata_control(accepted, ingress).await,
            StreamKind::Snapshot => {
                let snapshots = ingress
                    .snapshots
                    .ok_or(ConsensusNetworkError::InvalidTraffic)?;
                let staging_path = self
                    .snapshot_staging_path
                    .as_ref()
                    .ok_or(ConsensusNetworkError::InvalidTraffic)?;
                self.receive_snapshot(ingress.peer, staging_path, &mut accepted, &snapshots)
                    .await
            }
            StreamKind::Data => {
                self.admit_peer_message(
                    ingress.peer,
                    &ingress.data.ok_or(ConsensusNetworkError::InvalidTraffic)?,
                    PeerDataStream {
                        peer: ingress.peer,
                        stream: accepted,
                        limits: self.wire_limits,
                        routing_epoch: self.routing_epoch,
                    },
                )
                .await
            }
            StreamKind::Federation => Err(ConsensusNetworkError::InvalidTraffic),
        }
    }

    async fn receive_metadata_control(
        &self,
        mut accepted: meshspan_transport::AcceptedStream,
        ingress: AuthenticatedStreamIngress,
    ) -> Result<(), ConsensusNetworkError> {
        let controls = ingress
            .controls
            .ok_or(ConsensusNetworkError::InvalidTraffic)?;
        let envelope = receive_control(&mut accepted.receive, self.wire_limits).await?;
        self.verify_peer_header(&envelope, ingress.peer)?;
        // One control stream carries one complete request. Consume FIN before
        // admission, rejecting trailing bytes and avoiding a spurious STOP_SENDING
        // when a normally completed receive stream is dropped after the response.
        let mut trailing = [0_u8; 1];
        match tokio::time::timeout(PEER_OPERATION_TIMEOUT, accepted.receive.read(&mut trailing))
            .await
        {
            Ok(Ok(None)) => {}
            Ok(Ok(Some(_))) => return Err(ConsensusNetworkError::InvalidTraffic),
            Ok(Err(error)) => {
                return Err(meshspan_transport::TransportError::Read(
                    quinn::ReadExactError::ReadError(error),
                )
                .into());
            }
            Err(_) => {
                accepted.send.reset(3_u32.into())?;
                return Ok(());
            }
        }
        let (respond, response) = oneshot::channel();
        self.admit_peer_message(
            ingress.peer,
            &controls,
            PeerControlRequest {
                from: ingress.peer.node_id(),
                sender_incarnation: ingress.peer.incarnation(),
                envelope,
                certificate_fingerprint: ingress.peer.certificate_fingerprint(),
                capability_digest: ingress.capability_digest,
                respond,
            },
        )
        .await?;
        let Ok(Ok(response)) = tokio::time::timeout(CONTROL_RESPONSE_TIMEOUT, response).await
        else {
            // An unavailable handler is not evidence against the peer's
            // other authenticated requests on this connection.
            accepted.send.reset(3_u32.into())?;
            return Ok(());
        };
        send_control(&mut accepted.send, &response, self.wire_limits).await?;
        accepted.send.finish()?;
        Ok(())
    }

    fn verify_current_peer(
        &self,
        peer: meshspan_transport::AuthenticatedPeer,
    ) -> Result<(), ConsensusNetworkError> {
        self.peers
            .read()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
            .registry
            .revalidate(peer)?;
        Ok(())
    }

    fn verify_peer_header(
        &self,
        envelope: &meshspan_protocol::ValidatedControlEnvelope,
        peer: meshspan_transport::AuthenticatedPeer,
    ) -> Result<(), ConsensusNetworkError> {
        self.verify_current_peer(peer)?;
        self.verify_header(envelope, peer.node_id(), peer.incarnation())
    }

    async fn admit_peer_message<T>(
        &self,
        peer: meshspan_transport::AuthenticatedPeer,
        sender: &mpsc::Sender<T>,
        message: T,
    ) -> Result<(), ConsensusNetworkError> {
        // Wait for capacity without a registry lock, then linearise admission with peer updates.
        // A request blocked on backpressure must not keep authority withdrawn while it waited.
        let mut closing = self.owner.closing();
        if *closing.borrow() {
            return Err(ConsensusNetworkError::AuthorityStopped);
        }
        let permit = tokio::select! {
            biased;
            _ = closing.changed() => return Err(ConsensusNetworkError::AuthorityStopped),
            permit = sender.reserve() => permit.map_err(|_| ConsensusNetworkError::AuthorityStopped)?,
        };
        let peers = self
            .peers
            .read()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?;
        peers.registry.revalidate(peer)?;
        if self.owner.is_closing() {
            return Err(ConsensusNetworkError::AuthorityStopped);
        }
        permit.send(message);
        Ok(())
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
            header: Some(self.request_header(
                OperationId::from_bytes(request_identifier(
                    self.next_request.fetch_add(1, Ordering::Relaxed).max(1),
                ))?,
                i64::MAX,
            )),
            message: Some(encode_consensus_message(&message)),
        };
        send_control(&mut send, &envelope, self.wire_limits).await?;
        send.finish()?;
        receive_receipt(&mut receive, self.wire_limits).await
    }

    async fn connect_peer(&self, to: NodeId) -> Result<quinn::Connection, ConsensusNetworkError> {
        self.connect_peer_support(to)
            .await
            .map(|(connection, _)| connection)
    }

    async fn connect_peer_support(
        &self,
        to: NodeId,
    ) -> Result<
        (
            quinn::Connection,
            Option<meshspan_protocol::v1::ConsensusTransferSupport>,
        ),
        ConsensusNetworkError,
    > {
        let peer = self
            .peers
            .read()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
            .routes
            .get(&to)
            .cloned()
            .ok_or(ConsensusNetworkError::InvalidConfiguration)?;
        let connection = self
            .transport
            .connect(peer.address, &peer.certificate_name)
            .await?;
        let authenticated = self
            .peers
            .read()
            .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
            .registry
            .authenticate_connection(&connection)?;
        if authenticated.node_id() != to || authenticated.incarnation() != peer.incarnation {
            return Err(ConsensusNetworkError::InvalidTraffic);
        }
        let support = self.negotiate_outgoing(&connection).await?;
        Ok((connection, support))
    }

    async fn negotiate_outgoing(
        &self,
        connection: &quinn::Connection,
    ) -> Result<Option<meshspan_protocol::v1::ConsensusTransferSupport>, ConsensusNetworkError>
    {
        let (mut send, mut receive) = open_stream(connection, StreamKind::Metadata).await?;
        send_control(
            &mut send,
            &ControlEnvelope {
                header: None,
                message: Some(Message::NodeHello(self.hello()?)),
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
        Ok(welcome.consensus_transfer)
    }

    fn request_header(
        &self,
        operation_id: OperationId,
        deadline_unix_micros: i64,
    ) -> RequestHeader {
        let request_number = self.next_request.fetch_add(1, Ordering::Relaxed).max(1);
        let identifier = request_identifier(request_number);
        RequestHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            mesh_id: self.mesh_id.as_bytes().to_vec(),
            partition_id: self.partition_id.as_bytes().to_vec(),
            routing_epoch: self.routing_epoch,
            sender_node_id: self.local_node_id.as_bytes().to_vec(),
            sender_incarnation: self.local_incarnation,
            request_id: identifier.to_vec(),
            operation_id: operation_id.as_bytes().to_vec(),
            deadline_unix_micros,
            trace_id: identifier.to_vec(),
        }
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
        self.verify_request_header(header, peer, incarnation)
    }

    fn verify_request_header(
        &self,
        header: &RequestHeader,
        peer: NodeId,
        incarnation: u64,
    ) -> Result<(), ConsensusNetworkError> {
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

    fn hello(&self) -> Result<NodeHello, ConsensusNetworkError> {
        Ok(NodeHello {
            consensus_transfer: Some(meshspan_protocol::consensus_transfer_support()),
            versions: vec![ProtocolVersion { major: 1, minor: 0 }],
            mesh_id: self.mesh_id.as_bytes().to_vec(),
            node_id: self.local_node_id.as_bytes().to_vec(),
            incarnation: self.local_incarnation,
            roles: self
                .roles
                .read()
                .map_err(|_| ConsensusNetworkError::InvalidConfiguration)?
                .clone(),
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
        })
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
    fn consensus_transfer_support_for(
        &self,
        expected: PeerBinding,
        capability_digest: [u8; 32],
    ) -> Result<Option<ObservedConsensusTransferSupport>, ConsensusNetworkError> {
        ConsensusNetwork::consensus_transfer_support_for(self, expected, capability_digest)
    }

    fn send(&self, to: NodeId, message: CoreMessage) {
        let sender = self
            .peers
            .read()
            .ok()
            .and_then(|peers| peers.outbound.get(&to).cloned());
        if let Some(sender) = sender
            && let Ok(message) = bulk::OutboundConsensusMessage::prepare(self, to, message)
        {
            // Queue rejection is not replication proof; the core retains and retries its log.
            let _full_or_closed = sender.try_send(message);
        }
    }
}

fn validate_config(config: &ConsensusNetworkConfig) -> Result<(), ConsensusNetworkError> {
    if config.peers.len() > owned::MAXIMUM_OUTBOUND_WORKERS {
        return Err(ConsensusNetworkError::NetworkBusy);
    }
    if config.local_incarnation == 0
        || config.routing_epoch == 0
        || config.roles.is_empty()
        || config.roles.len() > 4
        || config.roles.contains(&NodeRole::Unspecified)
        || config.certificate_chain_der.is_empty()
        || config.certificate_chain_der.len() > 8
        || config.certificate_chain_der.iter().any(Vec::is_empty)
        || config.private_key_pkcs8.is_empty()
        || config.trust_anchors.is_empty()
        || config.peers.iter().any(|peer| {
            peer.node_id == config.local_node_id
                || peer.incarnation == 0
                || peer.certificate_name.is_empty()
                || peer.certificate_name.len() > 253
        })
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
        config
            .certificate_chain_der
            .iter()
            .cloned()
            .map(CertificateDer::from)
            .collect(),
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
    if peers.is_empty() {
        return Ok(PeerRegistry::empty());
    }
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
    /// Bounded network worker admission is full; no operation was accepted or acknowledged.
    #[error("consensus network worker capacity is unavailable")]
    NetworkBusy,
    /// A bounded bulk transfer was cancelled, expired or could not reserve memory; no durable outcome is implied.
    #[error("consensus bulk transfer is unconfirmed")]
    BulkTransferUnconfirmed,
    /// Bounded control delivery was not acknowledged; the operation's outcome is unknown.
    #[error("consensus control delivery is unconfirmed")]
    ControlDeliveryUnconfirmed,
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
    /// Snapshot staging or streaming filesystem IO failed.
    #[error("consensus snapshot IO failed")]
    Io(#[from] std::io::Error),
}

impl ConsensusNetworkError {
    // QUIC permits each stream to be cancelled independently. Neither a peer's
    // STOP_SENDING/RESET_STREAM nor a late write to that closed stream invalidates
    // the connection's other authenticated requests. Malformed frames and stale
    // identities are deliberately not included in this classification.
    fn is_stream_cancellation(&self) -> bool {
        matches!(
            self,
            Self::BulkTransferUnconfirmed
                | Self::Quinn(_)
                | Self::Transport(
                    meshspan_transport::TransportError::Finish(_)
                        | meshspan_transport::TransportError::Write(
                            quinn::WriteError::Stopped(_) | quinn::WriteError::ClosedStream
                        )
                        | meshspan_transport::TransportError::Read(
                            quinn::ReadExactError::ReadError(
                                quinn::ReadError::Reset(_) | quinn::ReadError::ClosedStream
                            )
                        )
                )
        )
    }
}

#[cfg(test)]
mod tests;
