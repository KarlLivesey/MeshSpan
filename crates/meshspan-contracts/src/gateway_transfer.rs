// SPDX-License-Identifier: GPL-2.0-only

//! Transport evidence, deliberately separate from file publication and client delivery.

use crate::GatewayProtocol;

/// One successful IO byte count or failed IO poll, without request-derived labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayTransferMetric {
    /// Protocol bytes read: HTTPS after TLS decoding; SMB including Direct TCP framing.
    ReceivedBytes(u64),
    /// Protocol bytes accepted by the underlying writer, not peer application consumption.
    SentBytes(u64),
    /// Read polls returning an IO error; clean EOF is not an error.
    ReadErrors(u64),
    /// Write, flush or shutdown polls returning an IO error.
    WriteErrors(u64),
}

/// Best-effort transport observation; implementations must never wait or perform IO.
pub trait GatewayTransferObserver: Send + Sync {
    /// Records the increment, or counts observation loss without changing the IO result.
    fn observe_transfer(&self, protocol: GatewayProtocol, increment: GatewayTransferMetric);
}
