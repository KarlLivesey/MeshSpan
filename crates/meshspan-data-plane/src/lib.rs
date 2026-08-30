// SPDX-License-Identifier: GPL-2.0-only

//! Authentication, capability decoding and bounded private shard-stream orchestration.

mod capability;
mod client;
mod error;
mod router;
mod server;
mod wire;

pub use capability::{
    CapabilityCodecError, decode_federated_shard_permit, decode_read_permit, decode_removal_permit,
    decode_write_permit, encode_federated_shard_permit, encode_read_permit, encode_removal_permit,
    encode_write_permit,
};
pub use client::{
    get_federated_shard, get_shard, put_federated_shard, put_shard, reclaim_federated_shard,
    reclaim_shard, retire_federated_shard, tombstone_shard,
};
pub use error::DataPlaneError;
pub use router::RemoteShardRouter;
pub use server::{
    FederatedReclamationEvidence, FederatedRetirementEvidence, FederatedShardAuthority,
    FederatedShardOutcome, FederatedWriteEvidence, RemoteShardService,
};
