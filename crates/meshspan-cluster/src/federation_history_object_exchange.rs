// SPDX-License-Identifier: GPL-2.0-only

//! Bilaterally authorised immutable-history bodies over signed, framed Quinn streams.

use meshspan_domain::{
    FederationGrantId, FederationRelationshipId, FederationResourceScope, UnixMicros,
};
use meshspan_filesystem::NamespaceHistoryImmutableRecord;
use meshspan_protocol::v1::{DataFrame, FederatedHistoryObjectHeader, FetchFederatedHistoryObject};
use meshspan_transport::{
    FederationExchangeContext, FederationReplayGuard, StreamKind, TransportError, accept_stream,
    open_stream, receive_data_frame, receive_federation, send_data_frame, send_federation,
    signed_federation_history_object_fetch, signed_federation_history_object_header,
};

use crate::federation_branch_exchange::admitted_history_grant;
use crate::federation_resource_wire::{
    decode_federation_resource_scope, version_federation_resource_scope,
};
use crate::federation_session::{envelope_relationship, load_authority};
use crate::{
    FederationAuthoritySource, FederationBranchAuthoritySource, FederationHistoryObjectQuery,
    FederationHistoryObjectSource, FederationSessionError, FederationSessionRuntime,
};

/// Complete client-side request for one object advertised by a signed history page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationHistoryObjectFetchRequest {
    /// Current approved relationship.
    pub relationship_id: FederationRelationshipId,
    /// Current bilateral namespace grant.
    pub grant_id: FederationGrantId,
    /// Exact shared namespace resource.
    pub resource: FederationResourceScope,
    /// Signed export identity returned by the branch page.
    pub export_token: [u8; 32],
    /// Exact advertised immutable object digest.
    pub object_digest: [u8; 32],
    /// Signed correlation, deadline and fresh nonce.
    pub context: FederationExchangeContext,
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Fresh response context for one authenticated inbound object request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationHistoryObjectServeRequest {
    /// Fresh nonce distinct from the request nonce.
    pub response_replay_nonce: [u8; 32],
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Three authority/source boundaries required by the inbound object service.
#[derive(Clone, Copy)]
pub struct FederationHistoryObjectServices<'a> {
    connection_authority: &'a dyn FederationAuthoritySource,
    grant_authority: &'a dyn FederationBranchAuthoritySource,
    history: &'a dyn FederationHistoryObjectSource,
}

impl<'a> FederationHistoryObjectServices<'a> {
    /// Composes current relationship authority, bilateral grant authority and immutable history.
    #[must_use]
    pub const fn new(
        connection_authority: &'a dyn FederationAuthoritySource,
        grant_authority: &'a dyn FederationBranchAuthoritySource,
        history: &'a dyn FederationHistoryObjectSource,
    ) -> Self {
        Self {
            connection_authority,
            grant_authority,
            history,
        }
    }
}

/// Non-sensitive successful service outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServedFederationHistoryObject {
    /// Relationship whose current authority admitted the request.
    pub relationship_id: FederationRelationshipId,
    /// Grant revalidated immediately before source lookup.
    pub grant_id: FederationGrantId,
    /// Exact canonical bytes sent.
    pub byte_count: usize,
    /// Number of independently bounded data frames sent.
    pub frame_count: usize,
}

impl FederationSessionRuntime<'_> {
    /// Fetches and independently revalidates one advertised immutable history body.
    ///
    /// # Errors
    ///
    /// Rejects unavailable authority, request/header substitution, offset/length excess, replay,
    /// malformed canonical bytes or digest mismatch.
    pub async fn fetch_history_object(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        grants: &impl FederationBranchAuthoritySource,
        request: FederationHistoryObjectFetchRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<NamespaceHistoryImmutableRecord, FederationSessionError> {
        let current = load_authority(authority, request.relationship_id, request.now)?;
        admitted_history_grant(
            grants,
            request.relationship_id,
            request.grant_id,
            request.resource,
            request.now,
        )?;
        let local_identity = self.local_identity(&current, request.now)?;
        let peers = meshspan_transport::FederationPeerRegistry::new([current.peer])?;
        let outbound = signed_federation_history_object_fetch(
            &local_identity,
            request.context,
            wire_request(request),
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
        let header = peers.authenticate_history_object_header(
            connection,
            &response,
            outbound.expectation(),
            request.now,
            replay,
        )?;
        receive_object_body(&mut receive, &header, self.hello_config.wire_limits()).await
    }

    /// Authenticates, reauthorises and serves one exact advertised immutable history body.
    ///
    /// # Errors
    ///
    /// Rejects hostile transport, unavailable authority, unadvertised objects, source corruption
    /// or a body outside negotiated bounds before returning success.
    pub async fn serve_history_object(
        &self,
        connection: &quinn::Connection,
        services: FederationHistoryObjectServices<'_>,
        request: FederationHistoryObjectServeRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<ServedFederationHistoryObject, FederationSessionError> {
        let mut stream = accept_stream(connection).await?;
        if stream.kind != StreamKind::Federation {
            return Err(FederationSessionError::WrongStream);
        }
        let envelope =
            receive_federation(&mut stream.receive, self.negotiation_config.wire_limits()).await?;
        let relationship_id = envelope_relationship(&envelope)?;
        let current = load_authority(services.connection_authority, relationship_id, request.now)?;
        let local_identity = self.local_identity(&current, request.now)?;
        let peers = meshspan_transport::FederationPeerRegistry::new([current.peer])?;
        let fetch =
            peers.authenticate_history_object_fetch(connection, &envelope, request.now, replay)?;
        let query = admitted_object_query(
            services.grant_authority,
            relationship_id,
            fetch.request(),
            request.now,
        )?;
        let grant_id = query.authority.grant.grant_id();
        let expected_digest = query.object_digest;
        let body = services.history.history_object(query).await?;
        let record = NamespaceHistoryImmutableRecord::from_expected_digest(
            expected_digest,
            body.canonical_bytes,
        )
        .map_err(|_| FederationSessionError::InvalidEnvelope)?;
        let bytes = record.canonical_bytes();
        let maximum_frame_bytes = bytes.len().min(
            self.negotiation_config
                .wire_limits()
                .maximum_data_frame_bytes(),
        );
        let header = signed_federation_history_object_header(
            &local_identity,
            fetch.response_context(request.response_replay_nonce)?,
            response_header(fetch.request(), bytes.len(), maximum_frame_bytes)?,
            self.negotiation_config.wire_limits(),
            request.now,
        )?;
        send_federation(
            &mut stream.send,
            header.envelope(),
            self.negotiation_config.wire_limits(),
        )
        .await?;
        let frame_count = send_object_body(
            &mut stream.send,
            bytes,
            maximum_frame_bytes,
            self.negotiation_config.wire_limits(),
        )
        .await?;
        stream.send.finish().map_err(TransportError::from)?;
        Ok(ServedFederationHistoryObject {
            relationship_id,
            grant_id,
            byte_count: bytes.len(),
            frame_count,
        })
    }
}

fn admitted_object_query(
    grants: &(impl FederationBranchAuthoritySource + ?Sized),
    relationship_id: FederationRelationshipId,
    request: &FetchFederatedHistoryObject,
    now: UnixMicros,
) -> Result<FederationHistoryObjectQuery, FederationSessionError> {
    let grant_id = parse_grant_id(&request.grant_id)?;
    let resource = decode_federation_resource_scope(
        request
            .resource_scope
            .as_ref()
            .ok_or(FederationSessionError::InvalidEnvelope)?,
    )?;
    let authority = admitted_history_grant(grants, relationship_id, grant_id, resource, now)?;
    Ok(FederationHistoryObjectQuery {
        authority,
        resource,
        export_token: exact_digest(&request.export_token)?,
        object_digest: exact_digest(&request.object_digest)?,
        now,
    })
}

fn wire_request(request: FederationHistoryObjectFetchRequest) -> FetchFederatedHistoryObject {
    FetchFederatedHistoryObject {
        grant_id: request.grant_id.as_bytes().to_vec(),
        resource_scope: Some(version_federation_resource_scope(request.resource)),
        export_token: request.export_token.to_vec(),
        object_digest: request.object_digest.to_vec(),
        signature: Vec::new(),
    }
}

fn response_header(
    request: &FetchFederatedHistoryObject,
    length: usize,
    maximum_frame_bytes: usize,
) -> Result<FederatedHistoryObjectHeader, FederationSessionError> {
    Ok(FederatedHistoryObjectHeader {
        grant_id: request.grant_id.clone(),
        resource_scope: request.resource_scope.clone(),
        export_token: request.export_token.clone(),
        object_digest: request.object_digest.clone(),
        declared_length: u64::try_from(length)
            .map_err(|_| FederationSessionError::InvalidEnvelope)?,
        maximum_frame_bytes: u64::try_from(maximum_frame_bytes)
            .map_err(|_| FederationSessionError::InvalidEnvelope)?,
        signature: Vec::new(),
    })
}

async fn send_object_body(
    send: &mut quinn::SendStream,
    bytes: &[u8],
    maximum_frame_bytes: usize,
    limits: meshspan_protocol::WireLimits,
) -> Result<usize, FederationSessionError> {
    if maximum_frame_bytes == 0 {
        return Err(FederationSessionError::InvalidEnvelope);
    }
    for (index, chunk) in bytes.chunks(maximum_frame_bytes).enumerate() {
        let offset = index
            .checked_mul(maximum_frame_bytes)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(FederationSessionError::InvalidEnvelope)?;
        send_data_frame(
            send,
            &DataFrame {
                offset,
                bytes: chunk.to_vec(),
            },
            limits,
        )
        .await?;
    }
    Ok(bytes.len().div_ceil(maximum_frame_bytes))
}

async fn receive_object_body(
    receive: &mut quinn::RecvStream,
    header: &meshspan_transport::AuthenticatedFederationHistoryObjectHeader,
    limits: meshspan_protocol::WireLimits,
) -> Result<NamespaceHistoryImmutableRecord, FederationSessionError> {
    let length = usize::try_from(header.declared_length())
        .map_err(|_| FederationSessionError::InvalidEnvelope)?;
    let maximum_frame_bytes = usize::try_from(header.maximum_frame_bytes())
        .map_err(|_| FederationSessionError::InvalidEnvelope)?;
    let expected_digest = exact_digest(header.object_digest())?;
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        let frame = receive_data_frame(receive, limits).await?.into_inner();
        let expected_offset =
            u64::try_from(bytes.len()).map_err(|_| FederationSessionError::InvalidEnvelope)?;
        let next = bytes
            .len()
            .checked_add(frame.bytes.len())
            .ok_or(FederationSessionError::InvalidEnvelope)?;
        if frame.offset != expected_offset
            || frame.bytes.is_empty()
            || frame.bytes.len() > maximum_frame_bytes
            || next > length
        {
            return Err(FederationSessionError::InvalidEnvelope);
        }
        bytes.extend_from_slice(&frame.bytes);
    }
    NamespaceHistoryImmutableRecord::from_expected_digest(expected_digest, bytes)
        .map_err(|_| FederationSessionError::InvalidEnvelope)
}

fn parse_grant_id(bytes: &[u8]) -> Result<FederationGrantId, FederationSessionError> {
    FederationGrantId::from_bytes(
        bytes
            .try_into()
            .map_err(|_| FederationSessionError::InvalidEnvelope)?,
    )
    .map_err(|_| FederationSessionError::InvalidEnvelope)
}

fn exact_digest(bytes: &[u8]) -> Result<[u8; 32], FederationSessionError> {
    bytes
        .try_into()
        .map_err(|_| FederationSessionError::InvalidEnvelope)
}
