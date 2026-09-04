// SPDX-License-Identifier: GPL-2.0-only

//! Stable remote metadata-backup data-plane failures.

use meshspan_protocol::v1::ErrorCode;
use meshspan_transport::TransportError;
use thiserror::Error;

/// Failure while serving or invoking one private backup-provider stream.
#[derive(Debug, Error)]
pub enum BackupPlaneError {
    /// A service binding or resource bound is invalid.
    #[error("private backup service configuration is invalid")]
    InvalidConfiguration,
    /// Authenticated QUIC framing or stream IO failed.
    #[error("private backup transport failed")]
    Transport(#[from] TransportError),
    /// The caller's local source or destination stream failed.
    #[error("local backup stream IO failed")]
    Io(#[from] std::io::Error),
    /// A provider or authority worker could not complete safely.
    #[error("private backup worker failed")]
    Worker,
    /// A semantically valid message contradicted the stream state machine.
    #[error("private backup stream sequence or identity is invalid")]
    InvalidMessage,
    /// The authenticated remote provider returned a stable typed rejection.
    #[error("remote backup provider rejected the operation with {0:?}")]
    Remote(ErrorCode),
}
