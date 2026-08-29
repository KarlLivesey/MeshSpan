// SPDX-License-Identifier: GPL-2.0-only

//! Mutually authenticated QUIC connections with certificate-bound node identity and bounded,
//! independent protocol streams.

mod federation;
mod identity;
mod snapshot;
mod stream;
mod tls;

pub use identity::{
    AuthenticatedPeer, NegotiationConfig, PeerBinding, PeerRegistry, certificate_fingerprint,
};
pub use snapshot::{SnapshotStager, VerifiedSnapshot};
pub use stream::{
    AcceptedStream, StreamKind, accept_stream, open_stream, receive_control, receive_data_control,
    receive_data_frame, receive_federation, send_control, send_data_control, send_data_frame,
    send_federation,
};
pub use tls::{
    NodeCredentials, TransportError, TransportLimits, client_endpoint, connect, server_endpoint,
};

#[cfg(test)]
mod tests;
pub use federation::{
    AuthenticatedFederationHello, FederationPeerBinding, FederationPeerRegistry,
    FederationReplayGuard,
};
