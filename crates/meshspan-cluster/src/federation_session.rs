// SPDX-License-Identifier: GPL-2.0-only

//! Metadata-authorised federation handshake composition over a dedicated Quinn stream.

use ed25519_dalek::SigningKey;
use meshspan_domain::{FederationRelationshipId, UnixMicros};
use meshspan_metadata::AuthoritativeRepository;
use meshspan_transport::{
    AcceptedFederationSession, AuthenticatedFederationSession, FederationHelloConfig,
    FederationHelloContext, FederationLocalIdentity, FederationNegotiationConfig,
    FederationPeerRegistry, FederationReplayGuard, FederationWelcomeNonces, StreamKind,
    TransportError, accept_stream, open_stream, receive_federation, send_federation,
    signed_federation_hello,
};
use std::sync::Mutex;
use thiserror::Error;

/// Shared bounded replay admission for concurrent handshakes. Locks cover only
/// synchronous authentication, never receiving a hello or sending a welcome.
pub struct FederationSessionReplay(Mutex<FederationReplayGuard>);

impl FederationSessionReplay {
    /// Authenticates an original consumer execution received through an enrolled node relay.
    /// Shares replay ownership with direct requests without holding the guard during IO.
    ///
    /// # Errors
    /// Rejects invalid relay/consumer identity, signature, lifetime or replay evidence.
    pub fn authenticate_forwarded_backup_request(
        &self,
        peers: &FederationPeerRegistry,
        peer: meshspan_transport::AuthenticatedPeer,
        envelope: &meshspan_protocol::ValidatedDataControlEnvelope,
        limits: meshspan_protocol::WireLimits,
        now: UnixMicros,
    ) -> Result<meshspan_transport::AuthenticatedFederationBackupRelay, FederationSessionError>
    {
        ReplayAdmission::Shared(self).authenticate(|guard| {
            peers.authenticate_forwarded_backup_request(peer, envelope, limits, now, guard)
        })
    }

    /// Owns one replay window shared across all connections of this runtime.
    #[must_use]
    pub const fn new(guard: FederationReplayGuard) -> Self {
        Self(Mutex::new(guard))
    }

    /// Authenticates one authority fetch using the same bounded replay window as handshakes.
    /// The guard covers only signature/replay verification, never database or network IO.
    ///
    /// # Errors
    /// Rejects untrusted, malformed or replayed requests and poisoned replay ownership.
    pub fn authenticate_authority_fetch(
        &self,
        peers: &FederationPeerRegistry,
        connection: &quinn::Connection,
        envelope: &meshspan_protocol::ValidatedFederationEnvelope,
        now: UnixMicros,
    ) -> Result<meshspan_transport::AuthenticatedFederationAuthorityFetch, FederationSessionError>
    {
        ReplayAdmission::Shared(self).authenticate(|guard| {
            peers.authenticate_authority_fetch(connection, envelope, now, guard)
        })
    }

    /// Authenticates backup requests in the same bounded replay window as handshakes.
    /// The lock covers only authentication, never capability issuance or provider IO.
    ///
    /// # Errors
    /// Rejects invalid identity, signature, lifetime or replay evidence.
    pub fn authenticate_backup_request(
        &self,
        peers: &FederationPeerRegistry,
        connection: &quinn::Connection,
        envelope: &meshspan_protocol::ValidatedFederationEnvelope,
        now: UnixMicros,
    ) -> Result<meshspan_transport::AuthenticatedFederationBackupRequest, FederationSessionError>
    {
        ReplayAdmission::Shared(self).authenticate(|guard| {
            peers.authenticate_backup_request(connection, envelope, now, guard)
        })
    }
}

enum ReplayAdmission<'a> {
    Exclusive(&'a mut FederationReplayGuard),
    Shared(&'a FederationSessionReplay),
}

impl ReplayAdmission<'_> {
    fn authenticate<T>(
        self,
        check: impl FnOnce(&mut FederationReplayGuard) -> Result<T, TransportError>,
    ) -> Result<T, FederationSessionError> {
        match self {
            Self::Exclusive(guard) => check(guard).map_err(Into::into),
            Self::Shared(shared) => {
                let mut guard = shared
                    .0
                    .lock()
                    .map_err(|_| FederationSessionError::AuthorityUnavailable)?;
                check(&mut guard).map_err(Into::into)
            }
        }
    }
}

use crate::{
    FederationAuthorityError, FederationConnectionAuthority, federation_connection_authority,
};

/// Read boundary through which every connection reloads current committed relationship authority.
pub trait FederationAuthoritySource {
    /// Returns current connection authority or `None` when the relationship is not admitted.
    ///
    /// # Errors
    ///
    /// Fails closed when authoritative state is corrupt or an identity is not current.
    fn connection_authority(
        &self,
        relationship_id: FederationRelationshipId,
        now: UnixMicros,
    ) -> Result<Option<FederationConnectionAuthority>, FederationAuthorityError>;
}

impl FederationAuthoritySource for AuthoritativeRepository {
    fn connection_authority(
        &self,
        relationship_id: FederationRelationshipId,
        now: UnixMicros,
    ) -> Result<Option<FederationConnectionAuthority>, FederationAuthorityError> {
        federation_connection_authority(self, relationship_id, now)
    }
}

/// Immutable process material and bounded negotiation policy shared by connection attempts.
pub struct FederationSessionRuntime<'a> {
    pub(crate) certificate_der: &'a [u8],
    pub(crate) signing_key: &'a SigningKey,
    pub(crate) hello_config: FederationHelloConfig,
    pub(crate) negotiation_config: FederationNegotiationConfig,
}

impl<'a> FederationSessionRuntime<'a> {
    /// Creates a runtime which cannot access local node membership or consensus authority.
    #[must_use]
    pub const fn new(
        certificate_der: &'a [u8],
        signing_key: &'a SigningKey,
        hello_config: FederationHelloConfig,
        negotiation_config: FederationNegotiationConfig,
    ) -> Self {
        Self {
            certificate_der,
            signing_key,
            hello_config,
            negotiation_config,
        }
    }

    /// Opens, signs and mutually authenticates one outbound federation session.
    ///
    /// # Errors
    ///
    /// Rejects unavailable/stale metadata authority, substituted local process identity, the wrong
    /// stream response, replay or any invalid signed welcome.
    pub async fn dial(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        request: FederationDialRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationSession, FederationSessionError> {
        self.dial_with_replay(
            connection,
            authority,
            request,
            ReplayAdmission::Exclusive(replay),
        )
        .await
    }

    /// Authenticates an outbound session using the runtime-wide bounded replay window.
    /// # Errors
    /// Rejects the same authority, identity, framing and replay failures as `dial`.
    pub async fn dial_shared(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        request: FederationDialRequest,
        replay: &FederationSessionReplay,
    ) -> Result<AuthenticatedFederationSession, FederationSessionError> {
        self.dial_with_replay(
            connection,
            authority,
            request,
            ReplayAdmission::Shared(replay),
        )
        .await
    }

    async fn dial_with_replay(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        request: FederationDialRequest,
        replay: ReplayAdmission<'_>,
    ) -> Result<AuthenticatedFederationSession, FederationSessionError> {
        let authority = load_authority(authority, request.relationship_id, request.now)?;
        let local_identity = self.local_identity(&authority, request.now)?;
        let peer_registry = FederationPeerRegistry::new([authority.peer])?;
        let outbound = signed_federation_hello(
            &local_identity,
            &self.hello_config,
            request.context,
            request.now,
        )?;
        let (mut send, mut receive) = open_stream(connection, StreamKind::Federation).await?;
        send_federation(
            &mut send,
            outbound.envelope(),
            self.hello_config.wire_limits(),
        )
        .await?;
        send.finish().map_err(TransportError::from)?;
        let welcome = receive_federation(&mut receive, self.hello_config.wire_limits()).await?;
        replay.authenticate(|guard| {
            peer_registry.authenticate_welcome(
                connection,
                &welcome,
                outbound.expectation(),
                request.now,
                guard,
            )
        })
    }

    /// Accepts one federation-only stream and answers a fully authenticated hello.
    ///
    /// # Errors
    ///
    /// Rejects other stream classes, unknown/revoked relationships, stale authority, replay,
    /// certificate/key substitution and malformed or incorrectly signed hellos.
    pub async fn accept(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        request: FederationAcceptRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<AcceptedFederationSession, FederationSessionError> {
        self.accept_with_replay(
            connection,
            authority,
            request,
            ReplayAdmission::Exclusive(replay),
        )
        .await
    }

    /// Accepts an inbound session without holding replay admission across network waits.
    /// # Errors
    /// Rejects the same authority, identity, framing and replay failures as `accept`.
    pub async fn accept_shared(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        request: FederationAcceptRequest,
        replay: &FederationSessionReplay,
    ) -> Result<AcceptedFederationSession, FederationSessionError> {
        self.accept_with_replay(
            connection,
            authority,
            request,
            ReplayAdmission::Shared(replay),
        )
        .await
    }

    async fn accept_with_replay(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        request: FederationAcceptRequest,
        replay: ReplayAdmission<'_>,
    ) -> Result<AcceptedFederationSession, FederationSessionError> {
        let mut stream = accept_stream(connection).await?;
        if stream.kind != StreamKind::Federation {
            return Err(FederationSessionError::WrongStream);
        }
        let hello =
            receive_federation(&mut stream.receive, self.negotiation_config.wire_limits()).await?;
        let relationship_id = envelope_relationship(&hello)?;
        let authority = load_authority(authority, relationship_id, request.now)?;
        let local_identity = self.local_identity(&authority, request.now)?;
        let peer_registry = FederationPeerRegistry::new([authority.peer])?;
        let authenticated = replay.authenticate(|guard| {
            peer_registry.authenticate_hello(connection, &hello, request.now, guard)
        })?;
        let welcome = authenticated.signed_welcome(
            &self.negotiation_config,
            request.nonces,
            &local_identity,
            authority.authority_revision.get(),
        )?;
        send_federation(
            &mut stream.send,
            welcome.envelope(),
            self.negotiation_config.wire_limits(),
        )
        .await?;
        stream.send.finish().map_err(TransportError::from)?;
        Ok(welcome.session())
    }

    /// Binds retained signing material to current metadata for an application service.
    /// The returned identity borrows the runtime; it never exports the private key.
    ///
    /// # Errors
    /// Rejects a stale, expired or mismatched local certificate/signing-key binding.
    pub fn local_identity(
        &self,
        authority: &FederationConnectionAuthority,
        now: UnixMicros,
    ) -> Result<FederationLocalIdentity<'_>, FederationSessionError> {
        FederationLocalIdentity::authenticate(
            authority.local_identity,
            self.certificate_der,
            self.signing_key,
            now,
        )
        .map_err(Into::into)
    }
}

/// Complete bounded inputs for one outbound federation negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationDialRequest {
    /// Relationship which must be active in current metadata.
    pub relationship_id: FederationRelationshipId,
    /// Fresh signed correlation, deadline and nonce values.
    pub context: FederationHelloContext,
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Complete fresh inputs for one inbound federation negotiation response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationAcceptRequest {
    /// Independent responder challenge and replay nonces.
    pub nonces: FederationWelcomeNonces,
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

pub(crate) fn load_authority(
    source: &(impl FederationAuthoritySource + ?Sized),
    relationship_id: FederationRelationshipId,
    now: UnixMicros,
) -> Result<FederationConnectionAuthority, FederationSessionError> {
    source
        .connection_authority(relationship_id, now)?
        .ok_or(FederationSessionError::AuthorityUnavailable)
}

pub(crate) fn envelope_relationship(
    envelope: &meshspan_protocol::ValidatedFederationEnvelope,
) -> Result<FederationRelationshipId, FederationSessionError> {
    let bytes: [u8; 16] = envelope
        .as_inner()
        .header
        .as_ref()
        .ok_or(FederationSessionError::InvalidEnvelope)?
        .relationship_id
        .as_slice()
        .try_into()
        .map_err(|_| FederationSessionError::InvalidEnvelope)?;
    FederationRelationshipId::from_bytes(bytes).map_err(|_| FederationSessionError::InvalidEnvelope)
}

/// Fail-closed federation session admission errors without remote-controlled details.
#[derive(Debug, Error)]
pub enum FederationSessionError {
    /// Current committed metadata does not admit this relationship.
    #[error("federation relationship is not available")]
    AuthorityUnavailable,
    /// Metadata authority could not be read or proved current.
    #[error("federation authority could not be established")]
    Authority(#[from] FederationAuthorityError),
    /// The bounded page source rejected or could not produce an exact stable-revision page.
    #[error("federation authority page could not be produced")]
    AuthorityPage(#[from] crate::FederationAuthorityPageSourceError),
    /// Current bilateral grant authority could not be established safely.
    #[error("federation branch authority could not be established")]
    BranchAuthority(#[from] crate::EffectiveFederationGrantAuthorityError),
    /// The bounded history source rejected or could not produce an exact page.
    #[error("federation branch page could not be produced")]
    BranchPage(#[from] crate::FederationBranchPageSourceError),
    /// Provider-side federated shard capability issuance failed closed.
    #[error("federation storage capability could not be issued")]
    StorageCapability(#[from] crate::FederationStorageCapabilityIssuerError),
    /// Federated shard provider state machine or durable accounting failed.
    #[error("federation shard data operation failed")]
    DataPlane(#[from] meshspan_data_plane::DataPlaneError),
    /// Durable capability-presentation evidence was missing, conflicting or corrupt.
    #[error("federation storage capability evidence failed")]
    StorageCapabilityLedger(#[from] meshspan_metadata::FederationStorageCapabilityLedgerError),
    /// Bounded remote provider inventory could not be authorised or reconciled safely.
    #[error("federation storage inventory exchange failed")]
    StorageInventory(#[from] crate::FederationStorageInventoryExchangeError),
    /// The advertised immutable history body could not be produced safely.
    #[error("federation history object could not be produced")]
    HistoryObject(#[from] crate::FederationHistoryObjectSourceError),
    /// The advertised portable encrypted-content layout could not be produced safely.
    #[error("federation content layout could not be produced")]
    ContentLayout(#[from] crate::FederationContentLayoutSourceError),
    /// Portable content-layout fields or connection-bound key material were invalid.
    #[error("federation content layout wire evidence failed")]
    ContentLayoutWire(#[from] crate::FederationContentLayoutWireError),
    /// The advertised encrypted content shard could not be produced safely.
    #[error("federation content shard could not be produced")]
    ContentShard(#[from] crate::FederationContentShardSourceError),
    /// The signed resource scope was not the exact canonical typed form.
    #[error("federation resource scope is invalid")]
    ResourceScope(#[from] crate::FederationResourceWireError),
    /// Quinn, framing, identity or signature validation failed.
    #[error("federation transport negotiation failed")]
    Transport(#[from] TransportError),
    /// The first stream was not the isolated federation stream class.
    #[error("federation negotiation used the wrong stream class")]
    WrongStream,
    /// A structurally validated envelope still lacked a usable relationship identity.
    #[error("federation negotiation envelope is invalid")]
    InvalidEnvelope,
}
