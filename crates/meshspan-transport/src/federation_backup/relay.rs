// SPDX-License-Identifier: GPL-2.0-only

//! Original consumer authentication across a separately authenticated owner-node hop.

use super::{AuthenticatedFederationBackupRequest, authenticate_request};
use crate::{AuthenticatedPeer, FederationPeerRegistry, FederationReplayGuard, TransportError};
use meshspan_domain::UnixMicros;
use meshspan_protocol::{
    ValidatedDataControlEnvelope, WireLimits, decode_federation_frame, encode_data_control_frame,
    v1::{DataControlEnvelope, ForwardFederatedBackupRequest, data_control_envelope::Message},
};
use sha2::{Digest, Sha256};

/// Correlates an owner reply with the complete validated relay, including routing and byte bounds.
///
/// # Errors
/// Rejects malformed or oversized wrappers and invalid embedded consumer frames.
pub fn federation_backup_relay_digest(
    request: &ForwardFederatedBackupRequest,
    limits: WireLimits,
) -> Result<[u8; 32], TransportError> {
    let frame = encode_data_control_frame(
        &DataControlEnvelope {
            message: Some(Message::ForwardFederatedBackupRequest(request.clone())),
        },
        limits,
    )?;
    let mut digest = Sha256::new();
    digest.update(b"meshspan.federation.backup-owner-relay.v1\0");
    digest.update(frame);
    Ok(digest.finalize().into())
}

/// A signed consumer execution bound to the node which relayed it.
///
/// This is not storage admission. The owner must revalidate the relay's current enrolled
/// certificate and routing epoch, its own target ownership, and current bilateral authority.
/// In particular this proof does not claim that the owner's private key verified a gateway MAC.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedFederationBackupRelay {
    peer: AuthenticatedPeer,
    forwarded: ForwardFederatedBackupRequest,
    consumer: AuthenticatedFederationBackupRequest,
}

impl AuthenticatedFederationBackupRelay {
    /// Same-swarm mTLS identity to revalidate against current topology before IO.
    #[must_use]
    pub const fn peer(&self) -> AuthenticatedPeer {
        self.peer
    }

    /// Exact bounded routing wrapper, including the unchanged signed consumer envelope.
    #[must_use]
    pub const fn forwarded(&self) -> &ForwardFederatedBackupRequest {
        &self.forwarded
    }

    /// Original consumer signature, lifetime and replay proof against current federation metadata.
    #[must_use]
    pub const fn consumer(&self) -> &AuthenticatedFederationBackupRequest {
        &self.consumer
    }
}

impl FederationPeerRegistry {
    /// Verifies a forwarded execution without exporting or trusting a forwarded private key.
    ///
    /// The caller obtains `peer` from the same-swarm mTLS connection and supplies a registry
    /// derived from current federation metadata. This deliberately accepts execution only,
    /// never capability minting or a gateway's claim that it checked the consumer signature.
    ///
    /// # Errors
    /// Rejects wrong message family, substituted relay identity/incarnation, expired relay
    /// deadline, stale remote signer, invalid original signature and consumed replay nonces.
    pub fn authenticate_forwarded_backup_request(
        &self,
        peer: AuthenticatedPeer,
        envelope: &ValidatedDataControlEnvelope,
        limits: WireLimits,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationBackupRelay, TransportError> {
        let Some(Message::ForwardFederatedBackupRequest(forwarded)) =
            envelope.as_inner().message.as_ref()
        else {
            return Err(TransportError::UntrustedPeer);
        };
        let header = forwarded
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedPeer)?;
        if header.sender_node_id != peer.node_id().as_bytes().as_slice()
            || header.sender_incarnation != peer.incarnation()
        {
            return Err(TransportError::UntrustedPeer);
        }
        if header.deadline_unix_micros <= now.get() {
            return Err(TransportError::StaleFederationMessage);
        }
        let decoded = decode_federation_frame(&forwarded.request, limits)?;
        let original = decoded.as_inner();
        let binding = self.forwarded_backup_binding(
            original
                .header
                .as_ref()
                .ok_or(TransportError::UntrustedFederationPeer)?,
            now,
        )?;
        let consumer = authenticate_request(binding, original, now, replay)?;
        Ok(AuthenticatedFederationBackupRelay {
            peer,
            forwarded: forwarded.clone(),
            consumer,
        })
    }
}
