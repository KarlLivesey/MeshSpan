// SPDX-License-Identifier: GPL-2.0-only

//! Mutually authenticated QUIC connections with certificate-bound node identity and bounded,
//! independent protocol streams.

mod identity;
mod snapshot;
mod stream;
mod tls;

pub use identity::{AuthenticatedPeer, NegotiationConfig, PeerBinding, PeerRegistry};
pub use snapshot::{SnapshotStager, VerifiedSnapshot};
pub use stream::{
    AcceptedStream, StreamKind, accept_stream, open_stream, receive_control, send_control,
};
pub use tls::{
    NodeCredentials, TransportError, TransportLimits, client_endpoint, connect, server_endpoint,
};

#[cfg(test)]
mod tests;
