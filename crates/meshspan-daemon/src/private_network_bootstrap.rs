// SPDX-License-Identifier: GPL-2.0-only

//! Private transport configuration from admitted identity, independent of consensus ownership.

use super::{DaemonProcessError, certificate_name, open_root_repository_at};
use meshspan_cluster::ConsensusNetworkConfig;
use meshspan_domain::{NodeId, UnixMicros};
use std::net::SocketAddr;
use zeroize::Zeroizing;

pub(super) fn configuration(
    directory: &std::path::Path,
    node: NodeId,
    private_key: &[u8],
    listen: SocketAddr,
    now: UnixMicros,
) -> Result<ConsensusNetworkConfig, DaemonProcessError> {
    let repository = open_root_repository_at(directory, now)?;
    let mesh_id = repository
        .local_mesh_id()?
        .ok_or(DaemonProcessError::PrivateNetworkState)?;
    let certificate = repository
        .active_node_certificate(node)?
        .ok_or(DaemonProcessError::PrivateNetworkState)?;
    let issuer = repository
        .online_certificate_authority(mesh_id)?
        .ok_or(DaemonProcessError::PrivateNetworkState)?;
    let recovery = repository
        .mesh_recovery_authority(mesh_id)?
        .ok_or(DaemonProcessError::PrivateNetworkState)?;
    let plan = repository
        .load_active_consensus_quorum_plan()?
        .ok_or(DaemonProcessError::PrivateNetworkState)?;
    Ok(ConsensusNetworkConfig {
        local_node_id: node,
        local_incarnation: certificate.incarnation,
        mesh_id,
        partition_id: repository.partition_id(),
        routing_epoch: 1,
        roles: crate::private_consensus_runtime::advertised_node_roles(
            node,
            certificate.roles,
            &plan,
        )
        .map_err(|()| DaemonProcessError::PrivateNetworkState)?,
        listen_address: listen,
        client_address: if listen.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0_u16; 8], 0))
        },
        certificate_chain_der: vec![certificate.certificate_der, issuer.certificate_der],
        certificate_generation: certificate.generation,
        certificate_name: certificate_name(node),
        private_key_pkcs8: Zeroizing::new(private_key.to_vec()),
        trust_anchors: vec![recovery.root_certificate_der],
        peers: Vec::new(),
        snapshot_staging_path: None,
    })
}
