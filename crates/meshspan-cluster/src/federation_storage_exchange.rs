// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated remote-storage capability exchange over one dedicated Quinn stream.

use meshspan_contracts::{FederatedStoragePermitMacKey, StorageProvider};
use meshspan_data_plane::RemoteShardService;
use meshspan_domain::{FederationRelationshipId, FederationStorageAction, OperationId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, FederationStorageQuotaDisposition, LocalDatabase,
};
use meshspan_protocol::v1::RequestFederatedStorageCapability;
use meshspan_transport::{
    AuthenticatedFederationStorageCapability, FederationExchangeContext, FederationReplayGuard,
    StreamKind, TransportError, accept_stream, open_stream, receive_federation, send_federation,
    signed_federation_storage_capability_request,
};

use crate::federation_session::{envelope_relationship, load_authority};
use crate::{
    FederationAuthoritySource, FederationSessionError, FederationSessionRuntime,
    FederationStorageCapabilityIssueRequest, FederationStorageCapabilityIssuer,
    MetadataFederatedShardAuthority,
};

/// Complete consumer-side input for one exact remote-shard capability request.
#[derive(Clone, Debug, PartialEq)]
pub struct FederationStorageCapabilityRequest {
    /// Current bilateral relationship through which storage is requested.
    pub relationship_id: FederationRelationshipId,
    /// Signed request body containing exact allocation, target, shard, action and ceiling.
    pub capability: RequestFederatedStorageCapability,
    /// Fresh signed correlation, operation, deadline and replay values.
    pub context: FederationExchangeContext,
    /// Current quorum-derived mesh time.
    pub now: UnixMicros,
}

/// Fresh provider-side values for one accepted capability request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageCapabilityServeRequest {
    /// Fresh response-envelope replay nonce.
    pub response_replay_nonce: [u8; 32],
    /// Fresh opaque provider-only permit nonce.
    pub capability_nonce: [u8; 32],
    /// Exclusive short-lived permit expiry.
    pub valid_until: UnixMicros,
    /// Current quorum-derived mesh time.
    pub now: UnixMicros,
}

/// Current relationship and mesh time for one inbound federated data stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationShardServeRequest {
    /// Relationship established for the connection and reloaded before accepting provider IO.
    pub relationship_id: FederationRelationshipId,
    /// Current quorum-derived mesh time.
    pub now: UnixMicros,
}

/// Mutable provider resources required to issue one capacity-safe capability.
pub struct FederationStorageCapabilityProvider<'a> {
    repository: &'a AuthoritativeRepository,
    local_database: &'a mut LocalDatabase,
    permit_key: &'a FederatedStoragePermitMacKey,
}

impl<'a> FederationStorageCapabilityProvider<'a> {
    /// Composes current replicated authority, node-local quota and private permit material.
    #[must_use]
    pub const fn new(
        repository: &'a AuthoritativeRepository,
        local_database: &'a mut LocalDatabase,
        permit_key: &'a FederatedStoragePermitMacKey,
    ) -> Self {
        Self {
            repository,
            local_database,
            permit_key,
        }
    }
}

/// Non-secret outcome of one capability issuance attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServedFederationStorageCapability {
    /// Relationship whose certificate-authenticated peer requested storage.
    pub relationship_id: FederationRelationshipId,
    /// Idempotent operation identity carried by the signed request.
    pub operation_id: OperationId,
    /// Exact admitted shard action.
    pub action: FederationStorageAction,
    /// Exact maximum byte ceiling.
    pub maximum_bytes: u64,
    /// Local capacity transition, or `None` for actions which do not reserve bytes.
    pub quota_disposition: Option<FederationStorageQuotaDisposition>,
}

impl FederationSessionRuntime<'_> {
    /// Sends one locally authenticated request and authenticates its provider-signed response.
    ///
    /// # Errors
    ///
    /// Rejects unavailable relationship authority, substitution, replay, framing or Quinn IO.
    pub async fn request_storage_capability(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        request: FederationStorageCapabilityRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationStorageCapability, FederationSessionError> {
        let current = load_authority(authority, request.relationship_id, request.now)?;
        let local_identity = self.local_identity(&current, request.now)?;
        let peers = meshspan_transport::FederationPeerRegistry::new([current.peer])?;
        let outbound = signed_federation_storage_capability_request(
            &local_identity,
            request.context,
            request.capability,
            self.hello_config.wire_limits(),
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
        let response = receive_federation(&mut receive, self.hello_config.wire_limits()).await?;
        peers
            .authenticate_storage_capability(
                connection,
                &response,
                outbound.expectation(),
                request.now,
                replay,
            )
            .map_err(Into::into)
    }

    /// Authenticates one signed request, revalidates current authority and holds capacity before
    /// sending its exact provider-signed permit.
    ///
    /// # Errors
    ///
    /// Rejects wrong streams, unavailable/revoked authority, hostile requests, exhausted quota,
    /// response construction failure or Quinn IO. A send failure may leave the safe idempotent
    /// reservation held so an exact retry can recover the response without over-allocation.
    pub async fn serve_storage_capability(
        &self,
        connection: &quinn::Connection,
        provider: FederationStorageCapabilityProvider<'_>,
        request: FederationStorageCapabilityServeRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<ServedFederationStorageCapability, FederationSessionError> {
        let mut stream = accept_stream(connection).await?;
        if stream.kind != StreamKind::Federation {
            return Err(FederationSessionError::WrongStream);
        }
        let envelope =
            receive_federation(&mut stream.receive, self.negotiation_config.wire_limits()).await?;
        let relationship_id = envelope_relationship(&envelope)?;
        let current = load_authority(provider.repository, relationship_id, request.now)?;
        let local_identity = self.local_identity(&current, request.now)?;
        let peers = meshspan_transport::FederationPeerRegistry::new([current.peer])?;
        let authenticated = peers.authenticate_storage_capability_request(
            connection,
            &envelope,
            request.now,
            replay,
        )?;
        let issued = FederationStorageCapabilityIssuer::new(
            provider.repository,
            provider.local_database,
            &local_identity,
            provider.permit_key,
        )
        .issue(FederationStorageCapabilityIssueRequest {
            authenticated: &authenticated,
            response_replay_nonce: request.response_replay_nonce,
            capability_nonce: request.capability_nonce,
            valid_until: request.valid_until,
            observed_at: request.now,
            limits: self.negotiation_config.wire_limits(),
        })?;
        send_federation(
            &mut stream.send,
            issued.outbound().envelope(),
            self.negotiation_config.wire_limits(),
        )
        .await?;
        stream.send.finish().map_err(TransportError::from)?;
        Ok(ServedFederationStorageCapability {
            relationship_id,
            operation_id: issued.permit().operation_id,
            action: issued.permit().action,
            maximum_bytes: issued.permit().maximum_bytes,
            quota_disposition: issued.quota_disposition(),
        })
    }

    /// Reauthenticates a federation connection and serves one bounded provider data stream.
    ///
    /// # Errors
    ///
    /// Rejects unavailable current relationship authority, a substituted TLS peer, wrong stream
    /// class, invalid/stale permits, quota lifecycle failure and provider or transport failure.
    pub async fn serve_federated_shard_stream<Provider: StorageProvider>(
        &self,
        connection: &quinn::Connection,
        repository: &AuthoritativeRepository,
        local_database: &mut LocalDatabase,
        service: &mut RemoteShardService<Provider>,
        permit_key: &FederatedStoragePermitMacKey,
        request: FederationShardServeRequest,
    ) -> Result<(), FederationSessionError> {
        let current = load_authority(repository, request.relationship_id, request.now)?;
        let peers = meshspan_transport::FederationPeerRegistry::new([current.peer])?;
        let peer = peers.authenticate_connection(connection, request.now)?;
        let stream = accept_stream(connection).await?;
        let mut authority = MetadataFederatedShardAuthority::new(repository, local_database);
        service
            .serve_federated_stream(
                stream,
                peer,
                permit_key,
                &mut authority,
                self.negotiation_config.wire_limits(),
                request.now,
            )
            .await
            .map_err(Into::into)
    }
}
