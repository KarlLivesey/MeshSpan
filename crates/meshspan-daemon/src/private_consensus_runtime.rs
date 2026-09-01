// SPDX-License-Identifier: GPL-2.0-only

//! Late-bound private consensus network and admitted-peer registration.

use std::net::ToSocketAddrs;
use std::sync::{Arc, RwLock};

use meshspan_api_contract::{EnrolNodeRequest, EnrolNodeResponse};
use meshspan_cluster::{ConsensusMessageTransport, ConsensusNetwork, ConsensusPeerConfig};
use meshspan_consensus::CoreMessage;
use meshspan_domain::{NodeId, UnixMicros};

use crate::create_mesh_setup::parse_uuid;
use crate::{NodeEnrolmentController, NodeEnrolmentError};

/// One install-once live network used by the already-running metadata authority.
#[derive(Default)]
pub(crate) struct PrivateConsensusRuntime {
    network: RwLock<Option<ConsensusNetwork>>,
}

impl PrivateConsensusRuntime {
    /// Installs the live authenticated network once first-mesh trust exists.
    pub(crate) fn install(&self, network: ConsensusNetwork) -> Result<(), ()> {
        let mut current = self.network.write().map_err(|_| ())?;
        if current.is_some() {
            return Err(());
        }
        current.replace(network);
        Ok(())
    }

    /// Returns the currently installed network.
    pub(crate) fn network(&self) -> Result<ConsensusNetwork, ()> {
        self.network.read().map_err(|_| ())?.clone().ok_or(())
    }

    /// Adds or replaces one newly admitted certificate-bound peer route.
    pub(crate) fn upsert_peer(&self, peer: ConsensusPeerConfig) -> Result<(), ()> {
        self.network()
            .and_then(|network| network.upsert_peer(peer).map_err(|_| ()))
    }
}

impl ConsensusMessageTransport for PrivateConsensusRuntime {
    fn send(&self, to: NodeId, message: CoreMessage) {
        if let Ok(network) = self.network() {
            network.send(to, message);
        }
    }
}

/// Registers the freshly committed staged certificate before returning HTTPS admission success.
pub(crate) struct NetworkRegisteringEnrolment<C> {
    inner: C,
    network: Arc<PrivateConsensusRuntime>,
}

impl<C> NetworkRegisteringEnrolment<C> {
    pub(crate) const fn new(inner: C, network: Arc<PrivateConsensusRuntime>) -> Self {
        Self { inner, network }
    }
}

impl<C> NodeEnrolmentController for NetworkRegisteringEnrolment<C>
where
    C: NodeEnrolmentController,
{
    fn enrol(
        &mut self,
        request: EnrolNodeRequest,
        now: UnixMicros,
    ) -> Result<EnrolNodeResponse, NodeEnrolmentError> {
        let private_endpoint = request.private_endpoint.clone();
        let response = self.inner.enrol(request, now)?;
        let node_id = node_id(&response.node_id)?;
        let certificate_der = decode_hex(&response.node_certificate_der_hex)?;
        let address = private_endpoint
            .to_socket_addrs()
            .map_err(|_| NodeEnrolmentError::Unavailable)?
            .next()
            .ok_or(NodeEnrolmentError::Unavailable)?;
        self.network
            .upsert_peer(ConsensusPeerConfig {
                node_id,
                incarnation: 1,
                address,
                certificate_der,
                certificate_name: certificate_name(node_id),
            })
            .map_err(|_| NodeEnrolmentError::Unavailable)?;
        Ok(response)
    }
}

pub(crate) fn certificate_name(node_id: NodeId) -> String {
    let compact = node_id.to_string().replace('-', "");
    format!("node-{compact}.meshspan.internal")
}

pub(crate) fn node_id(value: &str) -> Result<NodeId, NodeEnrolmentError> {
    NodeId::from_bytes(parse_uuid(value).map_err(|_| NodeEnrolmentError::Failed)?)
        .map_err(|_| NodeEnrolmentError::Failed)
}

pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, NodeEnrolmentError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(NodeEnrolmentError::Failed);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = nibble(pair[0]).ok_or(NodeEnrolmentError::Failed)?;
            let low = nibble(pair[1]).ok_or(NodeEnrolmentError::Failed)?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
