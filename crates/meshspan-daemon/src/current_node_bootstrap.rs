// SPDX-License-Identifier: GPL-2.0-only

//! Late-bound current-node bootstrap peer projection for anonymous enrolment.

use meshspan_api_contract::EnrolmentBootstrapPeer;
use meshspan_domain::NodeId;
use meshspan_metadata::ActiveNodeCertificate;

use crate::create_mesh_setup::format_uuid;
use crate::{NodeEnrolmentAuthorityError, NodeEnrolmentBootstrapSource};

/// Read boundary for one active node's current mesh-signed certificate.
pub trait ActiveNodeCertificateAuthority {
    /// Returns the newest active certificate for one active node.
    ///
    /// # Errors
    ///
    /// Fails closed when replicated certificate state is unavailable or malformed.
    fn active_node_certificate(
        &self,
        node_id: NodeId,
    ) -> Result<Option<ActiveNodeCertificate>, NodeEnrolmentAuthorityError>;
}

/// Projects the accepting gateway as a bootstrap peer using current replicated trust.
pub struct CurrentNodeBootstrapPeerSource<A> {
    authority: A,
    node_id: NodeId,
    private_endpoint: String,
}

impl<A> CurrentNodeBootstrapPeerSource<A> {
    /// Binds one current node and its configured private endpoint.
    #[must_use]
    pub fn new(authority: A, node_id: NodeId, private_endpoint: String) -> Self {
        Self {
            authority,
            node_id,
            private_endpoint,
        }
    }
}

impl<A> NodeEnrolmentBootstrapSource for CurrentNodeBootstrapPeerSource<A>
where
    A: ActiveNodeCertificateAuthority,
{
    fn bootstrap_peers(&self) -> Result<Vec<EnrolmentBootstrapPeer>, NodeEnrolmentAuthorityError> {
        let certificate = self
            .authority
            .active_node_certificate(self.node_id)?
            .ok_or(NodeEnrolmentAuthorityError::Unavailable)?;
        Ok(vec![EnrolmentBootstrapPeer {
            node_id: format_uuid(self.node_id.as_bytes()),
            private_endpoint: self.private_endpoint.clone(),
            certificate_der_hex: encode_hex(&certificate.certificate_der),
        }])
    }
}

fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
