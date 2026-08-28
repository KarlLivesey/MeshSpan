// SPDX-License-Identifier: GPL-2.0-only

//! Authentication, capability decoding and bounded private shard-stream orchestration.

mod capability;
mod client;
mod error;
mod router;
mod server;
mod wire;

pub use capability::{
    CapabilityCodecError, decode_read_permit, decode_write_permit, encode_read_permit,
    encode_write_permit,
};
pub use client::{get_shard, put_shard};
pub use error::DataPlaneError;
pub use router::RemoteShardRouter;
pub use server::RemoteShardService;
