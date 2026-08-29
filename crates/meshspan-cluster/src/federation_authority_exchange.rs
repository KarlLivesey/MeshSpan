// SPDX-License-Identifier: GPL-2.0-only

//! Metadata-authorised signed authority fetch/page exchange over dedicated Quinn streams.

use meshspan_domain::{FederationRelationshipId, Revision, UnixMicros};
use meshspan_metadata::AuthoritativeRepository;
use meshspan_protocol::v1::VersionedPayload;
use meshspan_transport::{
    AuthenticatedFederationAuthorityPage, FederationAuthorityContext, FederationReplayGuard,
    StreamKind, TransportError, accept_stream, open_stream, receive_federation, send_federation,
    signed_federation_authority_fetch, signed_federation_authority_page,
};
use thiserror::Error;

use crate::federation_session::{envelope_relationship, load_authority};
use crate::{FederationAuthoritySource, FederationSessionError, FederationSessionRuntime};

/// Stable-revision query passed only after the requesting peer and message are authenticated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationAuthorityPageQuery {
    /// Exact admitted relationship.
    pub relationship_id: FederationRelationshipId,
    /// Peer revision floor; zero requests its initial authority snapshot.
    pub after_revision: u64,
    /// Opaque continuation previously emitted in a signed page.
    pub cursor: Vec<u8>,
    /// Positive peer-requested bound already checked against negotiated wire limits.
    pub limit: u32,
    /// Exact local committed revision under which the page must remain stable.
    pub authority_revision: Revision,
}

/// Canonical records and optional continuation returned by an authority source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationAuthorityPageRecords {
    /// Exact stable source revision represented by this page.
    pub authority_revision: Revision,
    /// Independently versioned canonical authority records.
    pub records: Vec<VersionedPayload>,
    /// Opaque continuation, empty only when this stable page is terminal.
    pub next_cursor: Vec<u8>,
}

/// Narrow read boundary for relationship, identity, delegation and restriction history.
pub trait FederationAuthorityPageSource {
    /// Produces one stable page for an already authenticated request.
    ///
    /// # Errors
    ///
    /// Fails closed for stale/forged cursors, unavailable revisions or corrupt authority records.
    fn authority_page(
        &self,
        query: FederationAuthorityPageQuery,
    ) -> Result<FederationAuthorityPageRecords, FederationAuthorityPageSourceError>;
}

/// Deliberately non-diagnostic authority source failures safe to expose across composition layers.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FederationAuthorityPageSourceError {
    /// Cursor, revision or page bounds did not identify one valid stable query.
    #[error("federation authority page query is invalid")]
    InvalidQuery,
    /// The requested stable revision is not currently available.
    #[error("federation authority page revision is unavailable")]
    Unavailable,
    /// Persisted or generated authority evidence failed validation.
    #[error("federation authority page evidence is corrupt")]
    Corrupt,
}

impl FederationAuthorityPageSource for AuthoritativeRepository {
    fn authority_page(
        &self,
        query: FederationAuthorityPageQuery,
    ) -> Result<FederationAuthorityPageRecords, FederationAuthorityPageSourceError> {
        if query.limit == 0 || !query.cursor.is_empty() {
            return Err(FederationAuthorityPageSourceError::InvalidQuery);
        }
        let authority = self
            .federation_transport_authority(query.relationship_id)
            .map_err(|_| FederationAuthorityPageSourceError::Corrupt)?
            .ok_or(FederationAuthorityPageSourceError::Unavailable)?;
        if authority.authority_revision != query.authority_revision
            || query.after_revision > authority.authority_revision.get()
        {
            return Err(FederationAuthorityPageSourceError::InvalidQuery);
        }
        let records = if query.after_revision == authority.authority_revision.get() {
            Vec::new()
        } else {
            vec![VersionedPayload {
                format_version: 1,
                canonical_bytes: authority
                    .canonical_bytes()
                    .map_err(|_| FederationAuthorityPageSourceError::Corrupt)?,
            }]
        };
        Ok(FederationAuthorityPageRecords {
            authority_revision: authority.authority_revision,
            records,
            next_cursor: Vec::new(),
        })
    }
}

/// Complete client-side inputs for one signed authority page fetch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationAuthorityFetchRequest {
    /// Current approved relationship.
    pub relationship_id: FederationRelationshipId,
    /// Signed request correlation, deadline and fresh nonce.
    pub context: FederationAuthorityContext,
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
