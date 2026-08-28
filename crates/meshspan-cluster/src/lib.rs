// SPDX-License-Identifier: GPL-2.0-only

//! Runtime composition boundary for deterministic consensus, metadata persistence and QUIC.

mod wire;

pub use wire::{ConsensusWireError, decode_consensus_message, encode_consensus_message};
