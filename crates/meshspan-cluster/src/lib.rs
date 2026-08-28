// SPDX-License-Identifier: GPL-2.0-only

//! Runtime composition boundary for deterministic consensus, metadata persistence and QUIC.

mod driver;
mod wire;

pub use driver::{ClusterDriverError, DriverEffect, PartitionConsensusDriver};
pub use wire::{ConsensusWireError, decode_consensus_message, encode_consensus_message};
