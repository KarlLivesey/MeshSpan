// SPDX-License-Identifier: GPL-2.0-only

//! Bilaterally authorised encrypted content shards over signed, bounded Quinn streams.

use meshspan_contracts::{BoundedBytes, ShardIdentity};
use meshspan_domain::{
    ContentManifestId, FederationGrantId, FederationRelationshipId, FederationResourceScope,
    NodeId, TargetId, UnixMicros,
};
use meshspan_protocol::v1::{
    FederatedContentShardHeader, FetchFederatedContentShard, ShardIdentity as WireShardIdentity,
};
use meshspan_transport::{
    FederationExchangeContext, FederationReplayGuard, StreamKind, TransportError, accept_stream,
    open_stream, receive_federation, send_federation, signed_federation_content_shard_fetch,
    signed_federation_content_shard_header,
};

use crate::federation_body_exchange::{receive_exact_body, send_exact_body};
use crate::federation_branch_exchange::admitted_history_grant;
use crate::federation_resource_wire::{
    decode_federation_resource_scope, version_federation_resource_scope,
};
use crate::federation_session::{envelope_relationship, load_authority};
use crate::{
    FederationAuthoritySource, FederationBranchAuthoritySource, FederationContentShardQuery,
    FederationContentShardSource, FederationSessionError, FederationSessionRuntime,
};

/// Complete receiver-side input for one encrypted shard advertised by a content layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationContentShardFetchRequest {
    /// Current approved relationship.
    pub relationship_id: FederationRelationshipId,
    /// Current bilateral namespace-read grant.
    pub grant_id: FederationGrantId,
    /// Exact shared namespace resource which advertised the manifest.
    pub resource: FederationResourceScope,
    /// Exact immutable manifest to which the shard belongs.
    pub manifest_id: ContentManifestId,
    /// Live source export which advertised the manifest record.
    pub export_token: [u8; 32],
    /// Exact immutable manifest-record digest in that export.
    pub manifest_object_digest: [u8; 32],
    /// Exact source node advertised for the target incarnation.
    pub provider_node_id: NodeId,
    /// Exact source provider target.
    pub target_id: TargetId,
    /// Exact source target incarnation.
    pub target_generation: u64,
    /// Exact immutable encrypted shard generation.
    pub shard: ShardIdentity,
    /// Exact expected encrypted byte length.
    pub expected_length: u64,
    /// Exact expected encrypted byte digest.
    pub expected_digest: [u8; 32],
    /// Receiver allocation ceiling applied before reading any data frame.
    pub maximum_shard_bytes: usize,
    /// Signed request correlation, deadline and fresh nonce.
    pub context: FederationExchangeContext,
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Current receiver-side relationship and grant sources.
#[derive(Clone, Copy)]
pub struct FederationContentShardFetchServices<'a> {
    connection_authority: &'a dyn FederationAuthoritySource,
    grant_authority: &'a dyn FederationBranchAuthoritySource,
}

impl<'a> FederationContentShardFetchServices<'a> {
    /// Composes current relationship and bilateral namespace authority.
    #[must_use]
    pub const fn new(
        connection_authority: &'a dyn FederationAuthoritySource,
        grant_authority: &'a dyn FederationBranchAuthoritySource,
    ) -> Self {
        Self {
            connection_authority,
            grant_authority,
        }
    }
}

/// Fresh response material for one authenticated inbound shard fetch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationContentShardServeRequest {
    /// Fresh nonce distinct from the request nonce.
    pub response_replay_nonce: [u8; 32],
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Authority and source boundaries required by the inbound shard service.
#[derive(Clone, Copy)]
pub struct FederationContentShardServices<'a> {
    connection_authority: &'a dyn FederationAuthoritySource,
    grant_authority: &'a dyn FederationBranchAuthoritySource,
    content: &'a dyn FederationContentShardSource,
}

impl<'a> FederationContentShardServices<'a> {
    /// Composes current relationship/grant authority with exact encrypted shard access.
    #[must_use]
    pub const fn new(
        connection_authority: &'a dyn FederationAuthoritySource,
        grant_authority: &'a dyn FederationBranchAuthoritySource,
        content: &'a dyn FederationContentShardSource,
    ) -> Self {
        Self {
            connection_authority,
            grant_authority,
            content,
        }
    }
}

/// Authenticated provider receipt and independently verified encrypted bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedFederationContentShard {
    /// Exact bounded encrypted bytes.
    pub bytes: BoundedBytes,
    /// Provider's signed authoritative service instant.
    pub served_at: UnixMicros,
}

/// Non-sensitive outcome after the provider sent every exact byte frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServedFederationContentShard {
    /// Relationship whose current authority admitted the request.
    pub relationship_id: FederationRelationshipId,
    /// Grant revalidated immediately before provider IO.
    pub grant_id: FederationGrantId,
    /// Exact encrypted bytes sent.
    pub byte_count: usize,
    /// Number of independently bounded frames sent.
    pub frame_count: usize,
}

impl FederationSessionRuntime<'_> {
    /// Fetches and independently verifies one export-bound encrypted content shard.
    ///
    /// # Errors
    ///
    /// Rejects unavailable authority, substitution, replay, excess, framing or byte corruption.
    pub async fn fetch_content_shard(
        &self,
        connection: &quinn::Connection,
        services: FederationContentShardFetchServices<'_>,
        request: FederationContentShardFetchRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<ReceivedFederationContentShard, FederationSessionError> {
        validate_fetch_request(&request)?;
        let current = load_authority(
            services.connection_authority,
            request.relationship_id,
            request.now,
        )?;
        admitted_history_grant(
            services.grant_authority,
            request.relationship_id,
            request.grant_id,
            request.resource,
            request.now,
        )?;
        let local_identity = self.local_identity(&current, request.now)?;
        let peers = meshspan_transport::FederationPeerRegistry::new([current.peer])?;
        let outbound = signed_federation_content_shard_fetch(
            &local_identity,
            request.context,
            wire_request(&request),
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
        let header = peers.authenticate_content_shard_header(
            connection,
            &response,
            outbound.expectation(),
            request.now,
            replay,
        )?;
        let bytes = receive_exact_body(
            &mut receive,
            header.declared_length(),
            header.maximum_frame_bytes(),
            request.maximum_shard_bytes,
            exact_digest(header.content_digest())?,
            self.hello_config.wire_limits(),
        )
        .await?;
        Ok(ReceivedFederationContentShard {
            bytes,
            served_at: UnixMicros::new(header.as_inner().served_at_unix_micros),
        })
    }

    /// Authenticates, reauthorises and serves one exact encrypted content shard.
    ///
    /// # Errors
    ///
    /// Rejects hostile transport, revoked authority, unadvertised content, receipt disagreement,
    /// provider corruption or framing IO before returning success.
    pub async fn serve_content_shard(
        &self,
        connection: &quinn::Connection,
        services: FederationContentShardServices<'_>,
        request: FederationContentShardServeRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<ServedFederationContentShard, FederationSessionError> {
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
            peers.authenticate_content_shard_fetch(connection, &envelope, request.now, replay)?;
        let query = admitted_shard_query(
            services.grant_authority,
            relationship_id,
            fetch.operation_id()?,
            fetch.deadline(),
            fetch.request(),
            request.now,
        )?;
        let grant_id = query.authority.grant.grant_id();
        let shard = services.content.content_shard(query).await?;
        validate_source_bytes(fetch.request(), &shard.bytes)?;
        let maximum_frame_bytes = shard.bytes.len().min(
            self.negotiation_config
                .wire_limits()
                .maximum_data_frame_bytes(),
        );
        let header = signed_federation_content_shard_header(
            &local_identity,
            fetch.response_context(request.response_replay_nonce)?,
            response_header(fetch.request(), maximum_frame_bytes, request.now)?,
            self.negotiation_config.wire_limits(),
            request.now,
        )?;
        send_federation(
            &mut stream.send,
            header.envelope(),
            self.negotiation_config.wire_limits(),
        )
        .await?;
        let frame_count = send_exact_body(
            &mut stream.send,
            shard.bytes.as_slice(),
            maximum_frame_bytes,
            self.negotiation_config.wire_limits(),
        )
        .await?;
        stream.send.finish().map_err(TransportError::from)?;
        Ok(ServedFederationContentShard {
            relationship_id,
            grant_id,
            byte_count: shard.bytes.len(),
            frame_count,
        })
    }
}

fn validate_fetch_request(
    request: &FederationContentShardFetchRequest,
) -> Result<(), FederationSessionError> {
    let expected_length = usize::try_from(request.expected_length)
        .map_err(|_| FederationSessionError::InvalidEnvelope)?;
    if request.maximum_shard_bytes == 0
        || expected_length == 0
        || expected_length > request.maximum_shard_bytes
        || request.expected_digest == [0; 32]
    {
        Err(FederationSessionError::InvalidEnvelope)
    } else {
        Ok(())
    }
}

fn admitted_shard_query(
    grants: &(impl FederationBranchAuthoritySource + ?Sized),
    relationship_id: FederationRelationshipId,
    operation_id: meshspan_domain::OperationId,
    deadline: UnixMicros,
    request: &FetchFederatedContentShard,
    now: UnixMicros,
) -> Result<FederationContentShardQuery, FederationSessionError> {
    let grant_id = parse_grant_id(&request.grant_id)?;
    let resource = decode_federation_resource_scope(
        request
            .resource_scope
            .as_ref()
            .ok_or(FederationSessionError::InvalidEnvelope)?,
    )?;
    let authority = admitted_history_grant(grants, relationship_id, grant_id, resource, now)?;
    Ok(FederationContentShardQuery {
        authority,
        resource,
        manifest_id: parse_manifest_id(&request.manifest_id)?,
        export_token: exact_digest(&request.export_token)?,
        manifest_object_digest: exact_digest(&request.manifest_object_digest)?,
        provider_node_id: parse_node_id(&request.provider_node_id)?,
        target_id: parse_target_id(&request.target_id)?,
        target_generation: request.target_generation,
        shard: parse_shard(request.shard.as_ref())?,
        expected_length: request.expected_length,
        expected_digest: exact_digest(&request.expected_digest)?,
        operation_id,
        deadline,
        now,
    })
}

fn wire_request(request: &FederationContentShardFetchRequest) -> FetchFederatedContentShard {
    FetchFederatedContentShard {
        grant_id: request.grant_id.as_bytes().to_vec(),
        resource_scope: Some(version_federation_resource_scope(request.resource)),
        manifest_id: request.manifest_id.as_bytes().to_vec(),
        export_token: request.export_token.to_vec(),
        manifest_object_digest: request.manifest_object_digest.to_vec(),
        provider_node_id: request.provider_node_id.as_bytes().to_vec(),
        target_id: request.target_id.as_bytes().to_vec(),
        target_generation: request.target_generation,
        shard: Some(wire_shard(request.shard)),
        expected_length: request.expected_length,
        expected_digest: request.expected_digest.to_vec(),
        signature: Vec::new(),
    }
}

fn response_header(
    request: &FetchFederatedContentShard,
    maximum_frame_bytes: usize,
    served_at: UnixMicros,
) -> Result<FederatedContentShardHeader, FederationSessionError> {
    Ok(FederatedContentShardHeader {
        grant_id: request.grant_id.clone(),
        resource_scope: request.resource_scope.clone(),
        manifest_id: request.manifest_id.clone(),
        export_token: request.export_token.clone(),
        manifest_object_digest: request.manifest_object_digest.clone(),
        provider_node_id: request.provider_node_id.clone(),
        target_id: request.target_id.clone(),
        target_generation: request.target_generation,
        shard: request.shard.clone(),
        declared_length: request.expected_length,
        content_digest: request.expected_digest.clone(),
        maximum_frame_bytes: u64::try_from(maximum_frame_bytes)
            .map_err(|_| FederationSessionError::InvalidEnvelope)?,
        served_at_unix_micros: served_at.get(),
        signature: Vec::new(),
    })
}

fn validate_source_bytes(
    request: &FetchFederatedContentShard,
    bytes: &BoundedBytes,
) -> Result<(), FederationSessionError> {
    let valid = u64::try_from(bytes.len()).ok() == Some(request.expected_length)
        && blake3::hash(bytes.as_slice()).as_bytes() == request.expected_digest.as_slice();
    if valid {
        Ok(())
    } else {
        Err(FederationSessionError::InvalidEnvelope)
    }
}

fn parse_grant_id(bytes: &[u8]) -> Result<FederationGrantId, FederationSessionError> {
    FederationGrantId::from_bytes(exact_identifier(bytes)?)
        .map_err(|_| FederationSessionError::InvalidEnvelope)
}

fn parse_manifest_id(bytes: &[u8]) -> Result<ContentManifestId, FederationSessionError> {
    ContentManifestId::from_bytes(exact_identifier(bytes)?)
        .map_err(|_| FederationSessionError::InvalidEnvelope)
}

fn parse_target_id(bytes: &[u8]) -> Result<TargetId, FederationSessionError> {
    TargetId::from_bytes(exact_identifier(bytes)?)
        .map_err(|_| FederationSessionError::InvalidEnvelope)
}

fn parse_node_id(bytes: &[u8]) -> Result<NodeId, FederationSessionError> {
    NodeId::from_bytes(exact_identifier(bytes)?)
        .map_err(|_| FederationSessionError::InvalidEnvelope)
}

fn parse_shard(value: Option<&WireShardIdentity>) -> Result<ShardIdentity, FederationSessionError> {
    let value = value.ok_or(FederationSessionError::InvalidEnvelope)?;
    Ok(ShardIdentity {
        manifest_digest: exact_digest(&value.manifest_digest)?,
        stripe_index: value.stripe_index,
        shard_index: u16::try_from(value.shard_index)
            .map_err(|_| FederationSessionError::InvalidEnvelope)?,
        generation: value.generation,
    })
}

fn wire_shard(shard: ShardIdentity) -> WireShardIdentity {
    WireShardIdentity {
        manifest_digest: shard.manifest_digest.to_vec(),
        stripe_index: shard.stripe_index,
        shard_index: u32::from(shard.shard_index),
        generation: shard.generation,
    }
}

fn exact_identifier(bytes: &[u8]) -> Result<[u8; 16], FederationSessionError> {
    bytes
        .try_into()
        .map_err(|_| FederationSessionError::InvalidEnvelope)
}

fn exact_digest(bytes: &[u8]) -> Result<[u8; 32], FederationSessionError> {
    bytes
        .try_into()
        .map_err(|_| FederationSessionError::InvalidEnvelope)
}
