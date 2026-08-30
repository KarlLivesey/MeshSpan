// SPDX-License-Identifier: GPL-2.0-only

//! Mutually authenticated QUIC connections with certificate-bound node identity and bounded,
//! independent protocol streams.

mod federation;
mod federation_authority_page;
mod federation_branch_page;
mod federation_hello;
mod federation_history_object;
mod federation_negotiation;
mod federation_storage_capability;
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
pub use federation_authority_page::{
    AuthenticatedFederationAuthorityFetch, AuthenticatedFederationAuthorityPage,
    FederationAuthorityPageExpectation, FederationExchangeContext,
    OutboundFederationAuthorityFetch, OutboundFederationAuthorityPage,
    signed_federation_authority_fetch, signed_federation_authority_page,
};
pub use federation_branch_page::{
    AuthenticatedFederationBranchFetch, AuthenticatedFederationBranchPage,
    FederationBranchPageExpectation, OutboundFederationBranchFetch, OutboundFederationBranchPage,
    signed_federation_branch_fetch, signed_federation_branch_page,
};
pub use federation_hello::{
    FederationHelloConfig, FederationHelloContext, FederationLocalIdentity,
    FederationLocalIdentityBinding, OutboundFederationHello, signed_federation_hello,
};
pub use federation_history_object::{
    AuthenticatedFederationHistoryObjectFetch, AuthenticatedFederationHistoryObjectHeader,
    FederationHistoryObjectExpectation, OutboundFederationHistoryObjectFetch,
    OutboundFederationHistoryObjectHeader, signed_federation_history_object_fetch,
    signed_federation_history_object_header,
};
pub use federation_negotiation::{
    AcceptedFederationSession, AuthenticatedFederationSession, FederationHelloExpectation,
    FederationNegotiationConfig, FederationWelcomeNonces, OutboundFederationWelcome,
};
pub use federation_storage_capability::{
    AuthenticatedFederationStorageCapability, AuthenticatedFederationStorageCapabilityRequest,
    FederationStorageCapabilityExpectation, OutboundFederationStorageCapability,
    OutboundFederationStorageCapabilityRequest, signed_federation_storage_capability,
    signed_federation_storage_capability_request,
};
