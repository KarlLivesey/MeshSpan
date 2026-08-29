// SPDX-License-Identifier: GPL-2.0-only

//! Metadata-authorised signed authority fetch/page exchange over dedicated Quinn streams.

use crate::federation_session::{envelope_relationship, load_authority};
use crate::{
    FederationAuthorityPageQuery, FederationAuthorityPageRecords, FederationAuthorityPageSource,
    FederationAuthorityPageSourceError, FederationAuthoritySource, FederationSessionError,
    FederationSessionRuntime,
};
use meshspan_domain::{FederationRelationshipId, Revision, UnixMicros};
use meshspan_transport::{
    AuthenticatedFederationAuthorityPage, FederationExchangeContext, FederationReplayGuard,
    StreamKind, TransportError, accept_stream, open_stream, receive_federation, send_federation,
    signed_federation_authority_fetch, signed_federation_authority_page,
};

/// Complete client-side inputs for one signed authority page fetch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationAuthorityFetchRequest {
    /// Current approved relationship.
    pub relationship_id: FederationRelationshipId,
    /// Signed request correlation, deadline and fresh nonce.
    pub context: FederationExchangeContext,
    /// Last remote authority revision already applied, or zero initially.
    pub after_revision: u64,
    /// Opaque signed continuation from the previous page.
    pub cursor: Vec<u8>,
    /// Requested page size.
    pub limit: u32,
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Fresh server-side response material for one accepted fetch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationAuthorityPageServeRequest {
    /// Fresh nonce distinct from the fetch nonce.
    pub response_replay_nonce: [u8; 32],
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Exact result of serving one authenticated page without exposing its records to logging.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServedFederationAuthorityPage {
    /// Relationship whose authority was served.
    pub relationship_id: FederationRelationshipId,
    /// Exact local committed revision signed into the page.
    pub authority_revision: Revision,
    /// Number of canonical records sent.
    pub record_count: usize,
    /// Whether the signed page included another continuation.
    pub has_next_page: bool,
}

impl FederationSessionRuntime<'_> {
    /// Opens a federation stream, sends one signed fetch and authenticates its signed response.
    ///
    /// # Errors
    ///
    /// Rejects unavailable/currently inconsistent authority, response substitution, replay or IO.
    pub async fn fetch_authority_page(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        request: FederationAuthorityFetchRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationAuthorityPage, FederationSessionError> {
        let current = load_authority(authority, request.relationship_id, request.now)?;
        let local_identity = self.local_identity(&current, request.now)?;
        let peers = meshspan_transport::FederationPeerRegistry::new([current.peer])?;
        let outbound = signed_federation_authority_fetch(
            &local_identity,
            request.context,
            request.after_revision,
            request.cursor,
            request.limit,
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
            .authenticate_authority_page(
                connection,
                &response,
                outbound.expectation(),
                request.now,
                replay,
            )
            .map_err(Into::into)
    }

    /// Accepts and authenticates one signed fetch, then returns a signed stable-revision page.
    ///
    /// # Errors
    ///
    /// Rejects wrong streams, stale/revoked authority, hostile requests or invalid source output.
    pub async fn serve_authority_page(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        source: &impl FederationAuthorityPageSource,
        request: FederationAuthorityPageServeRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<ServedFederationAuthorityPage, FederationSessionError> {
        let mut stream = accept_stream(connection).await?;
        if stream.kind != StreamKind::Federation {
            return Err(FederationSessionError::WrongStream);
        }
        let envelope =
            receive_federation(&mut stream.receive, self.negotiation_config.wire_limits()).await?;
        let relationship_id = envelope_relationship(&envelope)?;
        let current = load_authority(authority, relationship_id, request.now)?;
        let local_identity = self.local_identity(&current, request.now)?;
        let peers = meshspan_transport::FederationPeerRegistry::new([current.peer])?;
        let fetch =
            peers.authenticate_authority_fetch(connection, &envelope, request.now, replay)?;
        let page = source.authority_page(FederationAuthorityPageQuery {
            relationship_id,
            after_revision: fetch.after_revision(),
            cursor: fetch.cursor().to_vec(),
            limit: fetch.limit(),
            authority_revision: current.authority_revision,
        })?;
        validate_source_page(
            fetch.limit(),
            fetch.after_revision(),
            current.authority_revision,
            &page,
        )?;
        let response = signed_federation_authority_page(
            &local_identity,
            fetch.response_context(request.response_replay_nonce)?,
            page.authority_revision.get(),
            page.records,
            page.next_cursor,
            self.negotiation_config.wire_limits(),
            request.now,
        )?;
        let record_count = response_record_count(response.envelope())?;
        let has_next_page = response_has_next_page(response.envelope())?;
        send_federation(
            &mut stream.send,
            response.envelope(),
            self.negotiation_config.wire_limits(),
        )
        .await?;
        stream.send.finish().map_err(TransportError::from)?;
        Ok(ServedFederationAuthorityPage {
            relationship_id,
            authority_revision: page.authority_revision,
            record_count,
            has_next_page,
        })
    }
}

fn validate_source_page(
    requested_limit: u32,
    after_revision: u64,
    current_authority_revision: Revision,
    page: &FederationAuthorityPageRecords,
) -> Result<(), FederationAuthorityPageSourceError> {
    let limit = usize::try_from(requested_limit)
        .map_err(|_| FederationAuthorityPageSourceError::InvalidQuery)?;
    if page.authority_revision.get() < after_revision
        || page.authority_revision > current_authority_revision
        || page.records.len() > limit
        || (page.records.is_empty() && !page.next_cursor.is_empty())
    {
        Err(FederationAuthorityPageSourceError::Corrupt)
    } else {
        Ok(())
    }
}

fn response_page(
    envelope: &meshspan_protocol::v1::FederationEnvelope,
) -> Result<&meshspan_protocol::v1::FederationAuthorityPage, FederationSessionError> {
    let Some(meshspan_protocol::v1::federation_envelope::Message::AuthorityPage(page)) =
        envelope.message.as_ref()
    else {
        return Err(FederationSessionError::InvalidEnvelope);
    };
    Ok(page)
}

fn response_record_count(
    envelope: &meshspan_protocol::v1::FederationEnvelope,
) -> Result<usize, FederationSessionError> {
    Ok(response_page(envelope)?.records.len())
}

fn response_has_next_page(
    envelope: &meshspan_protocol::v1::FederationEnvelope,
) -> Result<bool, FederationSessionError> {
    Ok(!response_page(envelope)?.next_cursor.is_empty())
}
