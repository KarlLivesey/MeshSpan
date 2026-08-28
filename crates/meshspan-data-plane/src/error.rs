// SPDX-License-Identifier: GPL-2.0-only

//! Stable data-plane failure categories.

use meshspan_contracts::ContractError;
use meshspan_protocol::v1::ErrorCode;
use meshspan_transport::TransportError;
use thiserror::Error;

use crate::CapabilityCodecError;

/// Failure while serving or invoking one private shard stream.
#[derive(Debug, Error)]
pub enum DataPlaneError {
    /// A service/router bound, target set or target incarnation is invalid.
    #[error("private shard service configuration is invalid")]
    InvalidConfiguration,
    /// Authenticated QUIC framing or stream IO failed.
    #[error("private shard transport failed")]
    Transport(#[from] TransportError),
    /// An opaque capability or provider receipt was not canonical.
    #[error("private shard capability was malformed")]
    Capability(#[from] CapabilityCodecError),
    /// A local storage provider rejected the exact operation.
    #[error("private shard provider rejected the operation")]
    Contract(#[from] ContractError),
    /// A semantically valid Protobuf message contradicted the stream state machine.
    #[error("private shard stream sequence or identity is invalid")]
    InvalidMessage,
    /// The authenticated remote provider returned a stable typed rejection.
    #[error("remote shard provider rejected the operation with {0:?}")]
    Remote(ErrorCode),
}
