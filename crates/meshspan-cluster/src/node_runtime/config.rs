// SPDX-License-Identifier: GPL-2.0-only

//! Strict bounded command-line configuration for one headless proof node.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use meshspan_domain::NodeId;

use super::NodeRuntimeError;

const MAXIMUM_ARGUMENTS: usize = 34;

#[derive(Clone)]
pub(super) struct PeerConfig {
    pub node_id: NodeId,
    pub address: SocketAddr,
    pub certificate_path: PathBuf,
}

pub(super) struct NodeConfig {
    pub node_id: NodeId,
    pub listen_address: SocketAddr,
    pub control_address: SocketAddr,
    pub certificate_path: PathBuf,
    pub private_key_path: PathBuf,
    pub authority_path: PathBuf,
    pub state_path: PathBuf,
    pub bootstrap: bool,
    pub peers: BTreeMap<NodeId, PeerConfig>,
}

impl NodeConfig {
    pub fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, NodeRuntimeError> {
        let values: Vec<String> = arguments.take(MAXIMUM_ARGUMENTS + 1).collect();
        if values.is_empty() || values.len() > MAXIMUM_ARGUMENTS || !values.len().is_multiple_of(2)
        {
            return Err(NodeRuntimeError::InvalidConfiguration);
        }
        let mut node_number = None;
        let mut listen_address = None;
        let mut control_address = None;
        let mut certificate_path = None;
        let mut private_key_path = None;
        let mut authority_path = None;
        let mut state_path = None;
        let mut bootstrap = None;
        let mut peers = BTreeMap::new();
        let mut index = 0;
        while index < values.len() {
            let flag = &values[index];
            let value = values
                .get(index + 1)
                .ok_or(NodeRuntimeError::InvalidConfiguration)?;
            match flag.as_str() {
                "--node" => set_once(&mut node_number, parse_node_number(value)?),
                "--listen" => set_once(&mut listen_address, parse_address(value)?),
                "--control" => set_once(&mut control_address, parse_address(value)?),
                "--certificate" => set_once(&mut certificate_path, PathBuf::from(value)),
                "--private-key" => set_once(&mut private_key_path, PathBuf::from(value)),
                "--authority" => set_once(&mut authority_path, PathBuf::from(value)),
                "--state" => set_once(&mut state_path, PathBuf::from(value)),
                "--bootstrap" => set_once(&mut bootstrap, parse_boolean(value)?),
                "--peer" => {
                    let peer = parse_peer(value)?;
                    if peers.insert(peer.node_id, peer).is_some() {
                        return Err(NodeRuntimeError::InvalidConfiguration);
                    }
                    Ok(())
                }
                _ => Err(NodeRuntimeError::InvalidConfiguration),
            }?;
            index += 2;
        }
        let node_number = node_number.ok_or(NodeRuntimeError::InvalidConfiguration)?;
        let node_id = node_id(node_number)?;
        if peers.len() != 2 || peers.contains_key(&node_id) {
            return Err(NodeRuntimeError::InvalidConfiguration);
        }
        Ok(Self {
            node_id,
            listen_address: listen_address.ok_or(NodeRuntimeError::InvalidConfiguration)?,
            control_address: control_address.ok_or(NodeRuntimeError::InvalidConfiguration)?,
            certificate_path: certificate_path.ok_or(NodeRuntimeError::InvalidConfiguration)?,
            private_key_path: private_key_path.ok_or(NodeRuntimeError::InvalidConfiguration)?,
            authority_path: authority_path.ok_or(NodeRuntimeError::InvalidConfiguration)?,
            state_path: state_path.ok_or(NodeRuntimeError::InvalidConfiguration)?,
            bootstrap: bootstrap.unwrap_or(false),
            peers,
        })
    }
}

fn parse_peer(value: &str) -> Result<PeerConfig, NodeRuntimeError> {
    let mut fields = value.splitn(3, ',');
    let node_number = parse_node_number(
        fields
            .next()
            .ok_or(NodeRuntimeError::InvalidConfiguration)?,
    )?;
    let address = parse_address(
        fields
            .next()
            .ok_or(NodeRuntimeError::InvalidConfiguration)?,
    )?;
    let certificate_path = PathBuf::from(
        fields
            .next()
            .filter(|field| !field.is_empty())
            .ok_or(NodeRuntimeError::InvalidConfiguration)?,
    );
    Ok(PeerConfig {
        node_id: node_id(node_number)?,
        address,
        certificate_path,
    })
}

fn parse_node_number(value: &str) -> Result<u8, NodeRuntimeError> {
    value
        .parse::<u8>()
        .ok()
        .filter(|value| (1..=3).contains(value))
        .ok_or(NodeRuntimeError::InvalidConfiguration)
}

fn parse_address(value: &str) -> Result<SocketAddr, NodeRuntimeError> {
    value
        .parse()
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)
}

fn parse_boolean(value: &str) -> Result<bool, NodeRuntimeError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(NodeRuntimeError::InvalidConfiguration),
    }
}

fn node_id(value: u8) -> Result<NodeId, NodeRuntimeError> {
    NodeId::from_bytes([value; 16]).map_err(Into::into)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), NodeRuntimeError> {
    if slot.replace(value).is_some() {
        Err(NodeRuntimeError::InvalidConfiguration)
    } else {
        Ok(())
    }
}
