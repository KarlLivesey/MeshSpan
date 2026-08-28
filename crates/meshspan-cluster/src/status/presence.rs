// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, authenticated presence soft state.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

use meshspan_domain::{NodeId, UnixMicros};
use meshspan_protocol::v1::{NodeRole, PublishPresence};
use thiserror::Error;

const MAXIMUM_PRESENCE_ADDRESSES: usize = 32;
const MAXIMUM_HEALTH_BYTES: usize = 64 * 1_024;
const MAXIMUM_LEASE_MICROS: i64 = 5 * 60 * 1_000_000;

/// Service capability advertised by one current node process.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PresenceRole {
    /// Stores immutable shards.
    Storage,
    /// Serves a public access protocol.
    Gateway,
    /// Replicates metadata without voting.
    MetadataLearner,
    /// Participates in metadata quorum decisions.
    MetadataVoter,
}

/// One authenticated, bounded and incarnation-fenced presence observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodePresence {
    /// Enrolled daemon identity.
    pub node_id: NodeId,
    /// Exact accepted process incarnation.
    pub incarnation: u64,
    /// Monotonic sequence within the incarnation.
    pub sequence: u64,
    /// Quorum-derived mesh time reported by the sender.
    pub observed_at: UnixMicros,
    /// Exclusive lease expiry.
    pub lease_expires_at: UnixMicros,
    /// Deduplicated advertised service roles.
    pub roles: BTreeSet<PresenceRole>,
    /// Deduplicated private service endpoints.
    pub private_addresses: BTreeSet<SocketAddr>,
    /// Version of the bounded health payload retained for status projection.
    pub health_format_version: u32,
    /// Bounded opaque health payload; it carries no authority.
    pub health: Vec<u8>,
}

impl NodePresence {
    /// Reports whether this observation remains live at the supplied mesh time.
    #[must_use]
    pub fn is_live_at(&self, now: UnixMicros) -> bool {
        self.lease_expires_at > now
    }
}

/// Result of applying one authenticated presence publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresenceUpdate {
    /// A newer observation replaced the previous state.
    Applied,
    /// An exact duplicate returned the already accepted result.
    Replay,
}

/// Rejection of malformed, stale or wrongly authenticated presence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PresenceError {
    /// Registry capacity or accepted-incarnation input is invalid.
    #[error("presence registry configuration is invalid")]
    InvalidConfiguration,
    /// The authenticated peer and message identity differ.
    #[error("presence identity does not match the authenticated peer")]
    IdentityMismatch,
    /// The process incarnation is not the authority-accepted incarnation.
    #[error("presence process incarnation is stale or unknown")]
    StaleIncarnation,
    /// The sequence is stale or conflicts with an accepted sequence.
    #[error("presence sequence is stale or conflicting")]
    StaleSequence,
    /// The observation or lease interval is invalid or excessive.
    #[error("presence lease is invalid")]
    InvalidLease,
    /// Roles are empty, duplicated or contain an unknown value.
    #[error("presence roles are invalid")]
    InvalidRole,
    /// An endpoint is malformed, duplicated or excessive.
    #[error("presence address set is invalid")]
    InvalidAddress,
    /// Health payload version or size is invalid.
    #[error("presence health payload is invalid")]
    InvalidHealth,
}

/// Bounded in-memory soft-state registry driven only by authenticated messages.
#[derive(Debug)]
pub struct PresenceRegistry {
    maximum_nodes: usize,
    accepted_incarnations: BTreeMap<NodeId, u64>,
    observations: BTreeMap<NodeId, NodePresence>,
}

impl PresenceRegistry {
    /// Constructs a registry from the current authoritative node incarnations.
    ///
    /// # Errors
    ///
    /// Rejects zero capacity, excessive membership or zero incarnations.
    pub fn new(
        accepted_incarnations: BTreeMap<NodeId, u64>,
        maximum_nodes: usize,
    ) -> Result<Self, PresenceError> {
        if maximum_nodes == 0
            || accepted_incarnations.len() > maximum_nodes
            || accepted_incarnations.values().any(|value| *value == 0)
        {
            return Err(PresenceError::InvalidConfiguration);
        }
        Ok(Self {
            maximum_nodes,
            accepted_incarnations,
            observations: BTreeMap::new(),
        })
    }

    /// Applies a committed incarnation change and fences the prior observation.
    ///
    /// # Errors
    ///
    /// Rejects zero, decreasing or capacity-exceeding incarnation state.
    pub fn accept_incarnation(
        &mut self,
        node_id: NodeId,
        incarnation: u64,
    ) -> Result<(), PresenceError> {
        if incarnation == 0
            || (self.accepted_incarnations.len() >= self.maximum_nodes
                && !self.accepted_incarnations.contains_key(&node_id))
        {
            return Err(PresenceError::InvalidConfiguration);
        }
        if let Some(current) = self.accepted_incarnations.get(&node_id) {
            if incarnation < *current {
                return Err(PresenceError::StaleIncarnation);
            }
            if incarnation == *current {
                return Ok(());
            }
        }
        self.accepted_incarnations.insert(node_id, incarnation);
        self.observations.remove(&node_id);
        Ok(())
    }

    /// Validates and applies one structurally decoded presence message.
    ///
    /// The authenticated identity is supplied separately so message fields can never choose their
    /// own authority. An exact replay is idempotent; a conflicting sequence fails closed.
    ///
    /// # Errors
    ///
    /// Rejects identity/incarnation mismatch, stale sequence, malformed endpoints, roles, health
    /// or an expired/excessive lease.
    pub fn publish_authenticated(
        &mut self,
        authenticated_node_id: NodeId,
        authenticated_incarnation: u64,
        received_at: UnixMicros,
        message: &PublishPresence,
    ) -> Result<PresenceUpdate, PresenceError> {
        let observation = decode_presence(message)?;
        if observation.node_id != authenticated_node_id
            || observation.incarnation != authenticated_incarnation
        {
            return Err(PresenceError::IdentityMismatch);
        }
        if self
            .accepted_incarnations
            .get(&authenticated_node_id)
            .copied()
            != Some(authenticated_incarnation)
        {
            return Err(PresenceError::StaleIncarnation);
        }
        validate_lease(&observation, received_at)?;
        if let Some(current) = self.observations.get(&authenticated_node_id) {
            if observation.sequence < current.sequence {
                return Err(PresenceError::StaleSequence);
            }
            if observation.sequence == current.sequence {
                return if observation == *current {
                    Ok(PresenceUpdate::Replay)
                } else {
                    Err(PresenceError::StaleSequence)
                };
            }
        }
        self.observations.insert(authenticated_node_id, observation);
        Ok(PresenceUpdate::Applied)
    }

    /// Returns live node identities advertising the requested role.
    #[must_use]
    pub fn live_nodes(&self, role: PresenceRole, now: UnixMicros) -> BTreeSet<NodeId> {
        self.observations
            .values()
            .filter(|observation| observation.is_live_at(now) && observation.roles.contains(&role))
            .map(|observation| observation.node_id)
            .collect()
    }

    /// Returns a current observation only while its lease and accepted incarnation remain valid.
    #[must_use]
    pub fn get_live(&self, node_id: NodeId, now: UnixMicros) -> Option<&NodePresence> {
        self.observations.get(&node_id).filter(|observation| {
            observation.is_live_at(now)
                && self.accepted_incarnations.get(&node_id).copied()
                    == Some(observation.incarnation)
        })
    }
}

fn decode_presence(message: &PublishPresence) -> Result<NodePresence, PresenceError> {
    let node_bytes: [u8; 16] = message
        .node_id
        .as_slice()
        .try_into()
        .map_err(|_| PresenceError::IdentityMismatch)?;
    let node_id = NodeId::from_bytes(node_bytes).map_err(|_| PresenceError::IdentityMismatch)?;
    let roles = decode_roles(&message.roles)?;
    let private_addresses = decode_addresses(&message.private_addresses)?;
    let health = message
        .health
        .as_ref()
        .ok_or(PresenceError::InvalidHealth)?;
    if health.format_version == 0 || health.canonical_bytes.len() > MAXIMUM_HEALTH_BYTES {
        return Err(PresenceError::InvalidHealth);
    }
    let lease = i64::try_from(message.lease_expires_unix_micros)
        .map_err(|_| PresenceError::InvalidLease)?;
    Ok(NodePresence {
        node_id,
        incarnation: message.incarnation,
        sequence: message.presence_sequence,
        observed_at: UnixMicros::new(message.observed_mesh_time),
        lease_expires_at: UnixMicros::new(lease),
        roles,
        private_addresses,
        health_format_version: health.format_version,
        health: health.canonical_bytes.clone(),
    })
}

fn decode_roles(values: &[i32]) -> Result<BTreeSet<PresenceRole>, PresenceError> {
    let roles: BTreeSet<PresenceRole> = values
        .iter()
        .map(|value| match NodeRole::try_from(*value) {
            Ok(NodeRole::Storage) => Ok(PresenceRole::Storage),
            Ok(NodeRole::Gateway) => Ok(PresenceRole::Gateway),
            Ok(NodeRole::MetadataLearner) => Ok(PresenceRole::MetadataLearner),
            Ok(NodeRole::MetadataVoter) => Ok(PresenceRole::MetadataVoter),
            Ok(NodeRole::Unspecified) | Err(_) => Err(PresenceError::InvalidRole),
        })
        .collect::<Result<_, _>>()?;
    if roles.is_empty() || roles.len() != values.len() {
        Err(PresenceError::InvalidRole)
    } else {
        Ok(roles)
    }
}

fn decode_addresses(values: &[String]) -> Result<BTreeSet<SocketAddr>, PresenceError> {
    if values.is_empty() || values.len() > MAXIMUM_PRESENCE_ADDRESSES {
        return Err(PresenceError::InvalidAddress);
    }
    let addresses: BTreeSet<SocketAddr> = values
        .iter()
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .ok()
                .filter(|address| address.port() != 0 && !address.ip().is_unspecified())
                .ok_or(PresenceError::InvalidAddress)
        })
        .collect::<Result<_, _>>()?;
    if addresses.len() == values.len() {
        Ok(addresses)
    } else {
        Err(PresenceError::InvalidAddress)
    }
}

fn validate_lease(
    observation: &NodePresence,
    received_at: UnixMicros,
) -> Result<(), PresenceError> {
    let lease_length = observation
        .lease_expires_at
        .get()
        .checked_sub(observation.observed_at.get())
        .ok_or(PresenceError::InvalidLease)?;
    if observation.incarnation == 0
        || observation.sequence == 0
        || observation.observed_at.get() <= 0
        || observation.lease_expires_at <= received_at
        || lease_length <= 0
        || lease_length > MAXIMUM_LEASE_MICROS
    {
        Err(PresenceError::InvalidLease)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshspan_protocol::v1::VersionedPayload;

    #[test]
    fn replay_flap_and_incarnation_fencing_are_deterministic()
    -> Result<(), Box<dyn std::error::Error>> {
        let node = node(1)?;
        let mut registry = PresenceRegistry::new(BTreeMap::from([(node, 1)]), 16)?;
        let first = presence(node, 1, 1, 1_000, 2_000);
        assert_eq!(
            registry.publish_authenticated(node, 1, UnixMicros::new(1_100), &first)?,
            PresenceUpdate::Applied
        );
        assert_eq!(
            registry.publish_authenticated(node, 1, UnixMicros::new(1_200), &first)?,
            PresenceUpdate::Replay
        );
        let mut conflicting = first.clone();
        conflicting.private_addresses = vec!["127.0.0.1:8000".to_owned()];
        assert_eq!(
            registry.publish_authenticated(node, 1, UnixMicros::new(1_200), &conflicting),
            Err(PresenceError::StaleSequence)
        );
        assert!(registry.get_live(node, UnixMicros::new(1_999)).is_some());
        assert!(registry.get_live(node, UnixMicros::new(2_000)).is_none());

        registry.accept_incarnation(node, 2)?;
        assert_eq!(
            registry.publish_authenticated(node, 1, UnixMicros::new(1_200), &first),
            Err(PresenceError::StaleIncarnation)
        );
        let returned = presence(node, 2, 1, 2_100, 3_100);
        assert_eq!(
            registry.publish_authenticated(node, 2, UnixMicros::new(2_200), &returned)?,
            PresenceUpdate::Applied
        );
        assert_eq!(
            registry.live_nodes(PresenceRole::MetadataVoter, UnixMicros::new(2_500)),
            BTreeSet::from([node])
        );
        Ok(())
    }

    #[test]
    fn malformed_or_excessive_input_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let node = node(1)?;
        let mut registry = PresenceRegistry::new(BTreeMap::from([(node, 1)]), 1)?;
        let mut invalid = presence(node, 1, 1, 1_000, 2_000);
        invalid.private_addresses = vec!["not-an-address".to_owned()];
        assert_eq!(
            registry.publish_authenticated(node, 1, UnixMicros::new(1_100), &invalid),
            Err(PresenceError::InvalidAddress)
        );
        let excessive = presence(node, 1, 1, 1_000, 1_000 + MAXIMUM_LEASE_MICROS + 1);
        assert_eq!(
            registry.publish_authenticated(node, 1, UnixMicros::new(1_100), &excessive),
            Err(PresenceError::InvalidLease)
        );
        Ok(())
    }

    fn node(value: u8) -> Result<NodeId, meshspan_domain::IdentifierError> {
        NodeId::from_bytes([value; 16])
    }

    fn presence(
        node_id: NodeId,
        incarnation: u64,
        sequence: u64,
        observed: i64,
        expires: i64,
    ) -> PublishPresence {
        PublishPresence {
            node_id: node_id.as_bytes().to_vec(),
            incarnation,
            roles: vec![NodeRole::MetadataVoter.into()],
            private_addresses: vec!["127.0.0.1:7443".to_owned()],
            lease_expires_unix_micros: u64::try_from(expires).unwrap_or_default(),
            health: Some(VersionedPayload {
                format_version: 1,
                canonical_bytes: Vec::new(),
            }),
            presence_sequence: sequence,
            observed_mesh_time: observed,
        }
    }
}
