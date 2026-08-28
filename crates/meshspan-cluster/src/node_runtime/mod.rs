// SPDX-License-Identifier: GPL-2.0-only

//! Minimal headless three-voter runtime used before public service adapters arrive.

mod config;
mod membership_runtime;
mod network;
mod proof_metadata;
mod service;
mod test_plan_exit;

use thiserror::Error;

pub use service::run_stage_three_node;

/// Closed headless node failures without secret, certificate or command contents.
#[derive(Debug, Error)]
pub enum NodeRuntimeError {
    /// Arguments, identities or endpoints violate the node contract.
    #[error("stage three node configuration is invalid")]
    InvalidConfiguration,
    /// Filesystem or control-socket IO failed.
    #[error("stage three node IO failed")]
    Io(#[from] std::io::Error),
    /// Private QUIC transport rejected setup or traffic.
    #[error("stage three node transport failed")]
    Transport(#[from] meshspan_transport::TransportError),
    /// Protocol framing rejected a locally constructed or received message.
    #[error("stage three node protocol failed")]
    Protocol(#[from] meshspan_protocol::WireContractError),
    /// Consensus/runtime processing failed safely.
    #[error("stage three node cluster driver failed")]
    Driver(#[from] crate::ClusterDriverError),
    /// Consensus configuration or durable restore failed.
    #[error("stage three node consensus state is invalid")]
    Consensus(#[from] meshspan_consensus::CoreError),
    /// A quorum plan was malformed or could not prove its safety properties.
    #[error("stage three node quorum plan is invalid")]
    Quorum(#[from] meshspan_consensus::QuorumPlanError),
    /// Metadata database could not be opened or migrated.
    #[error("stage three node metadata store failed")]
    Metadata(#[from] meshspan_metadata::MetadataStoreError),
    /// A committed metadata command failed closed.
    #[error("stage three node metadata command failed")]
    Repository(#[from] meshspan_metadata::RepositoryError),
    /// A proof command could not construct a validated metadata value.
    #[error("stage three node metadata value is invalid")]
    MetadataCommand(#[from] meshspan_metadata::RepositoryCommandError),
    /// A proof record name violated the metadata naming contract.
    #[error("stage three node metadata name is invalid")]
    RecordName(#[from] meshspan_metadata::RecordNameError),
    /// Durable consensus state could not be loaded.
    #[error("stage three node consensus store failed")]
    ConsensusStore(#[from] meshspan_metadata::ConsensusStoreError),
    /// Authoritative membership, transition shape or catch-up evidence was inconsistent.
    #[error("stage three node membership coordination failed")]
    Membership,
    /// Identity construction failed.
    #[error("stage three node identity is invalid")]
    Identity(#[from] meshspan_domain::IdentifierError),
    /// QUIC task ended unexpectedly.
    #[error("stage three node task ended unexpectedly")]
    Task(#[from] tokio::task::JoinError),
}

impl From<crate::membership::MembershipCoordinatorError> for NodeRuntimeError {
    fn from(_error: crate::membership::MembershipCoordinatorError) -> Self {
        Self::Membership
    }
}
