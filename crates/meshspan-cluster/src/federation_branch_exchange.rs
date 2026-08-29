// SPDX-License-Identifier: GPL-2.0-only

//! Bilaterally authorised signed branch-page exchange over dedicated Quinn streams.

use meshspan_domain::{
    FederationGrantId, FederationRelationshipId, FederationResourceScope, UnixMicros,
};
use meshspan_protocol::v1::{FederatedBranchPage, FetchFederatedBranchPage};
use meshspan_transport::{
    AuthenticatedFederationBranchPage, FederationExchangeContext, FederationReplayGuard,
    StreamKind, TransportError, accept_stream, open_stream, receive_federation, send_federation,
    signed_federation_branch_fetch, signed_federation_branch_page,
};

use crate::federation_branch_page_source::grant_allows_history_read;
use crate::federation_resource_wire::{
    decode_federation_resource_scope, version_federation_resource_scope,
};
use crate::federation_session::{envelope_relationship, load_authority};
use crate::{
    FederationAuthoritySource, FederationBranchAuthoritySource, FederationBranchPageQuery,
    FederationBranchPageRecords, FederationBranchPageSource, FederationBranchPageSourceError,
    FederationSessionError, FederationSessionRuntime,
};

/// Complete client-side input for one signed history page fetch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationBranchFetchRequest {
    /// Current approved relationship.
    pub relationship_id: FederationRelationshipId,
    /// Current bilaterally approved grant.
    pub grant_id: FederationGrantId,
    /// Exact typed resource which must equal the grant resource.
    pub resource: FederationResourceScope,
    /// Bounded content identities already held by the requester.
    pub causal_frontier: Vec<[u8; 32]>,
    /// Opaque signed continuation from the previous page.
    pub cursor: Vec<u8>,
    /// Positive maximum combined record count.
    pub limit: u32,
    /// Signed request correlation, deadline and fresh nonce.
    pub context: FederationExchangeContext,
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Fresh server-side response material for one authenticated fetch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationBranchPageServeRequest {
    /// Fresh nonce distinct from the fetch nonce.
    pub response_replay_nonce: [u8; 32],
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Three narrow read boundaries required by the inbound branch-page service.
#[derive(Clone, Copy)]
pub struct FederationBranchPageServices<'a> {
    connection_authority: &'a dyn FederationAuthoritySource,
    grant_authority: &'a dyn FederationBranchAuthoritySource,
    history: &'a dyn FederationBranchPageSource,
}

impl<'a> FederationBranchPageServices<'a> {
    /// Composes current connection authority, bilateral grant authority and immutable history.
    #[must_use]
    pub const fn new(
        connection_authority: &'a dyn FederationAuthoritySource,
        grant_authority: &'a dyn FederationBranchAuthoritySource,
        history: &'a dyn FederationBranchPageSource,
    ) -> Self {
        Self {
            connection_authority,
            grant_authority,
            history,
        }
    }
}

/// Exact non-sensitive outcome of serving one history page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServedFederationBranchPage {
    /// Relationship whose current authority admitted the request.
    pub relationship_id: FederationRelationshipId,
    /// Current bilateral grant used for the lookup.
    pub grant_id: FederationGrantId,
    /// Combined number of commit and immutable-object records sent.
    pub record_count: usize,
    /// Whether the signed page included another continuation.
    pub has_next_page: bool,
}

impl FederationSessionRuntime<'_> {
    /// Sends one locally authorised signed history fetch and authenticates its response.
    ///
    /// # Errors
    ///
    /// Rejects unavailable bilateral authority, request substitution, replay or IO.
    pub async fn fetch_branch_page(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        grants: &impl FederationBranchAuthoritySource,
        request: FederationBranchFetchRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationBranchPage, FederationSessionError> {
        let current = load_authority(authority, request.relationship_id, request.now)?;
        authorise_branch_request(grants, &request)?;
        let local_identity = self.local_identity(&current, request.now)?;
        let peers = meshspan_transport::FederationPeerRegistry::new([current.peer])?;
        let outbound = signed_federation_branch_fetch(
            &local_identity,
            request.context,
            fetch_wire_request(&request),
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
            .authenticate_branch_page(
                connection,
                &response,
                outbound.expectation(),
                request.now,
                replay,
            )
            .map_err(Into::into)
    }

    /// Authenticates and authorises one fetch before invoking its bounded history source.
    ///
    /// # Errors
    ///
    /// Rejects hostile transport, unavailable bilateral authority, wrong rights/resource or
    /// invalid source output before returning any history metadata.
    pub async fn serve_branch_page(
        &self,
        connection: &quinn::Connection,
        services: FederationBranchPageServices<'_>,
        request: FederationBranchPageServeRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<ServedFederationBranchPage, FederationSessionError> {
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
        let fetch = peers.authenticate_branch_fetch(connection, &envelope, request.now, replay)?;
        let query = admitted_query(
            services.grant_authority,
            relationship_id,
            fetch.request(),
            request.now,
        )?;
        let page = services.history.branch_page(query)?;
        validate_source_page(fetch.request().limit, &page)?;
        let response = signed_federation_branch_page(
            &local_identity,
            fetch.response_context(request.response_replay_nonce)?,
            response_page(fetch.request(), page),
            self.negotiation_config.wire_limits(),
            request.now,
        )?;
        send_federation(
            &mut stream.send,
            response.envelope(),
            self.negotiation_config.wire_limits(),
        )
        .await?;
        stream.send.finish().map_err(TransportError::from)?;
        let records = response_records(response.envelope())?;
        Ok(ServedFederationBranchPage {
            relationship_id,
            grant_id: parse_grant_id(&fetch.request().grant_id)?,
            record_count: records.0,
            has_next_page: records.1,
        })
    }
}

fn authorise_branch_request(
    grants: &(impl FederationBranchAuthoritySource + ?Sized),
    request: &FederationBranchFetchRequest,
) -> Result<(), FederationSessionError> {
    let authority = grants
        .effective_grant_authority(request.relationship_id, request.grant_id, request.now)?
        .ok_or(FederationSessionError::AuthorityUnavailable)?;
    if authority.grant.grant_id() != request.grant_id
        || authority.grant.relationship_id() != request.relationship_id
        || authority.grant.resource() != request.resource
        || !grant_allows_history_read(authority)
    {
        return Err(FederationSessionError::AuthorityUnavailable);
    }
    Ok(())
}

fn admitted_query(
    grants: &(impl FederationBranchAuthoritySource + ?Sized),
    relationship_id: FederationRelationshipId,
    request: &FetchFederatedBranchPage,
    now: UnixMicros,
) -> Result<FederationBranchPageQuery, FederationSessionError> {
    let grant_id = parse_grant_id(&request.grant_id)?;
    let resource = decode_federation_resource_scope(
        request
            .resource_scope
            .as_ref()
            .ok_or(FederationSessionError::InvalidEnvelope)?,
    )?;
    let authority = grants
        .effective_grant_authority(relationship_id, grant_id, now)?
        .ok_or(FederationSessionError::AuthorityUnavailable)?;
    if authority.grant.grant_id() != grant_id
        || authority.grant.relationship_id() != relationship_id
        || authority.grant.resource() != resource
        || !grant_allows_history_read(authority)
    {
        return Err(FederationSessionError::AuthorityUnavailable);
    }
    Ok(FederationBranchPageQuery {
        authority,
        resource,
        causal_frontier: parse_digests(&request.causal_frontier)?,
        cursor: request.cursor.clone(),
        limit: request.limit,
    })
}

fn fetch_wire_request(request: &FederationBranchFetchRequest) -> FetchFederatedBranchPage {
    FetchFederatedBranchPage {
        grant_id: request.grant_id.as_bytes().to_vec(),
        resource_scope: Some(version_federation_resource_scope(request.resource)),
        causal_frontier: request
            .causal_frontier
            .iter()
            .map(|digest| digest.to_vec())
            .collect(),
        cursor: request.cursor.clone(),
        limit: request.limit,
        signature: Vec::new(),
    }
}

fn response_page(
    request: &FetchFederatedBranchPage,
    records: FederationBranchPageRecords,
) -> FederatedBranchPage {
    FederatedBranchPage {
        grant_id: request.grant_id.clone(),
        resource_scope: request.resource_scope.clone(),
        branch_commits: records.branch_commits,
        immutable_object_digests: records
            .immutable_object_digests
            .into_iter()
            .map(|digest| digest.to_vec())
            .collect(),
        next_cursor: records.next_cursor,
        page_digest: Vec::new(),
        signature: Vec::new(),
    }
}

fn validate_source_page(
    requested_limit: u32,
    page: &FederationBranchPageRecords,
) -> Result<(), FederationBranchPageSourceError> {
    let limit = usize::try_from(requested_limit)
        .map_err(|_| FederationBranchPageSourceError::InvalidQuery)?;
    let count = page
        .branch_commits
        .len()
        .checked_add(page.immutable_object_digests.len())
        .ok_or(FederationBranchPageSourceError::Corrupt)?;
    if count > limit || (count == 0 && !page.next_cursor.is_empty()) {
        Err(FederationBranchPageSourceError::Corrupt)
    } else {
        Ok(())
    }
}

fn response_records(
    envelope: &meshspan_protocol::v1::FederationEnvelope,
) -> Result<(usize, bool), FederationSessionError> {
    let Some(meshspan_protocol::v1::federation_envelope::Message::BranchPage(page)) =
        envelope.message.as_ref()
    else {
        return Err(FederationSessionError::InvalidEnvelope);
    };
    let count = page
        .branch_commits
        .len()
        .checked_add(page.immutable_object_digests.len())
        .ok_or(FederationSessionError::InvalidEnvelope)?;
    Ok((count, !page.next_cursor.is_empty()))
}

fn parse_grant_id(bytes: &[u8]) -> Result<FederationGrantId, FederationSessionError> {
    let exact: [u8; 16] = bytes
        .try_into()
        .map_err(|_| FederationSessionError::InvalidEnvelope)?;
    FederationGrantId::from_bytes(exact).map_err(|_| FederationSessionError::InvalidEnvelope)
}

fn parse_digests(values: &[Vec<u8>]) -> Result<Vec<[u8; 32]>, FederationSessionError> {
    values
        .iter()
        .map(|value| {
            value
                .as_slice()
                .try_into()
                .map_err(|_| FederationSessionError::InvalidEnvelope)
        })
        .collect()
}
