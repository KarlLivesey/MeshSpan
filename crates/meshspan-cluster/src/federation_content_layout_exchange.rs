// SPDX-License-Identifier: GPL-2.0-only

//! Bilaterally authorised portable encrypted-content layouts over signed Quinn control streams.

use meshspan_domain::{
    ContentManifestId, FederationGrantId, FederationRelationshipId, FederationResourceScope,
    RandomSource, UnixMicros,
};
use meshspan_filesystem::{
    ContentKeyEnvelopeCipher, ContentKeyTransitCipher, ContentLayoutTransferHeader,
    ContentLayoutTransferPage, MAXIMUM_CONTENT_LAYOUT_PAGE_ITEMS,
};
use meshspan_protocol::v1::{FederatedContentLayoutPage, FetchFederatedContentLayout};
use meshspan_transport::{
    FederationExchangeContext, FederationReplayGuard, StreamKind, TransportError, accept_stream,
    open_stream, receive_federation, send_federation, signed_federation_content_layout_fetch,
    signed_federation_content_layout_page,
};

use crate::federation_branch_exchange::admitted_history_grant;
use crate::federation_content_layout_wire::{
    decode_content_layout_cursor, encode_content_layout_cursor,
};
use crate::federation_resource_wire::{
    decode_federation_resource_scope, version_federation_resource_scope,
};
use crate::federation_session::{envelope_relationship, load_authority};
use crate::{
    FederationAuthoritySource, FederationBranchAuthoritySource, FederationContentLayoutQuery,
    FederationContentLayoutRecords, FederationContentLayoutSource, FederationSessionError,
    FederationSessionRuntime, decode_federated_content_layout_chunk,
    decode_federated_content_layout_header, version_federated_content_layout_chunk,
    version_federated_content_layout_header,
};

const CONTENT_KEY_EXPORTER_LABEL: &[u8] = b"EXPORTER-MeshSpan-Federated-Content-Key-v1";

/// Complete client-side request for one portable encrypted-content layout page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationContentLayoutFetchRequest {
    /// Current approved relationship.
    pub relationship_id: FederationRelationshipId,
    /// Current bilateral namespace grant.
    pub grant_id: FederationGrantId,
    /// Exact shared namespace resource which advertised the manifest.
    pub resource: FederationResourceScope,
    /// Exact immutable manifest to recover.
    pub manifest_id: ContentManifestId,
    /// Live source export which advertised the manifest record.
    pub export_token: [u8; 32],
    /// Exact advertised immutable manifest-record digest.
    pub manifest_object_digest: [u8; 32],
    /// Opaque continuation returned by the preceding page.
    pub cursor: Vec<u8>,
    /// Positive maximum number of chunk identities.
    pub limit: u32,
    /// Receiver-local first-page header retained across continuation requests.
    pub existing_header: Option<ContentLayoutTransferHeader>,
    /// Signed request correlation, deadline and fresh nonce.
    pub context: FederationExchangeContext,
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Fresh response material for one authenticated inbound layout fetch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationContentLayoutServeRequest {
    /// Fresh nonce distinct from the fetch nonce.
    pub response_replay_nonce: [u8; 32],
    /// Current authoritative mesh time.
    pub now: UnixMicros,
}

/// Receiver-side authority, key and entropy boundaries for one layout fetch.
pub struct FederationContentLayoutFetchServices<'a, R: RandomSource> {
    connection_authority: &'a dyn FederationAuthoritySource,
    grant_authority: &'a dyn FederationBranchAuthoritySource,
    target_keys: &'a ContentKeyEnvelopeCipher,
    random: &'a mut R,
}

impl<'a, R: RandomSource> FederationContentLayoutFetchServices<'a, R> {
    /// Composes current relationship/grant authority with receiver-local key wrapping.
    #[must_use]
    pub const fn new(
        connection_authority: &'a dyn FederationAuthoritySource,
        grant_authority: &'a dyn FederationBranchAuthoritySource,
        target_keys: &'a ContentKeyEnvelopeCipher,
        random: &'a mut R,
    ) -> Self {
        Self {
            connection_authority,
            grant_authority,
            target_keys,
            random,
        }
    }
}

/// Authority, source-key and content source boundaries required by the inbound service.
pub struct FederationContentLayoutServices<'a, R: RandomSource> {
    connection_authority: &'a dyn FederationAuthoritySource,
    grant_authority: &'a dyn FederationBranchAuthoritySource,
    content: &'a dyn FederationContentLayoutSource,
    source_keys: &'a ContentKeyEnvelopeCipher,
    random: &'a mut R,
}

impl<'a, R: RandomSource> FederationContentLayoutServices<'a, R> {
    /// Composes current relationship/grant authority with encrypted-content access.
    #[must_use]
    pub const fn new(
        connection_authority: &'a dyn FederationAuthoritySource,
        grant_authority: &'a dyn FederationBranchAuthoritySource,
        content: &'a dyn FederationContentLayoutSource,
        source_keys: &'a ContentKeyEnvelopeCipher,
        random: &'a mut R,
    ) -> Self {
        Self {
            connection_authority,
            grant_authority,
            content,
            source_keys,
            random,
        }
    }
}

/// Receiver-local, independently decoded page ready for durable import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedFederationContentLayoutPage {
    /// Stable receiver-wrapped header from the first page.
    pub header: ContentLayoutTransferHeader,
    /// Provider-neutral identities, absent only for a valid empty file.
    pub page: Option<ContentLayoutTransferPage>,
    /// Exact signed continuation, empty only at the end.
    pub next_cursor: Vec<u8>,
}

/// Non-sensitive successful service outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServedFederationContentLayoutPage {
    /// Relationship whose current authority admitted the request.
    pub relationship_id: FederationRelationshipId,
    /// Grant revalidated immediately before namespace/content lookup.
    pub grant_id: FederationGrantId,
    /// Number of provider-neutral chunk identities returned.
    pub chunk_count: usize,
    /// Whether the signed response included another continuation.
    pub has_next_page: bool,
}

impl FederationSessionRuntime<'_> {
    /// Fetches, authenticates, locally rewraps and validates one content-layout page.
    ///
    /// # Errors
    ///
    /// Rejects unavailable authority, export/manifest substitution, replay, malformed paging,
    /// connection-key mismatch or unavailable local cryptography before returning layout state.
    pub async fn fetch_content_layout_page<R: RandomSource>(
        &self,
        connection: &quinn::Connection,
        services: FederationContentLayoutFetchServices<'_, R>,
        request: FederationContentLayoutFetchRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<ReceivedFederationContentLayoutPage, FederationSessionError> {
        validate_client_request(&request)?;
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
        let outbound = signed_federation_content_layout_fetch(
            &local_identity,
            request.context,
            wire_request(&request),
            self.hello_config.wire_limits(),
            request.now,
        )?;
        let transit = transit_cipher(connection, outbound.expectation().transit_binding())?;
        let (mut send, mut receive) = open_stream(connection, StreamKind::Federation).await?;
        send_federation(
            &mut send,
            outbound.envelope(),
            self.hello_config.wire_limits(),
        )
        .await?;
        send.finish().map_err(TransportError::from)?;
        let response = receive_federation(&mut receive, self.hello_config.wire_limits()).await?;
        let page = peers.authenticate_content_layout_page(
            connection,
            &response,
            outbound.expectation(),
            request.now,
            replay,
        )?;
        decode_received_page(
            &page,
            &request,
            &transit,
            services.target_keys,
            services.random,
        )
    }

    /// Authenticates, reauthorises and serves one exact portable content-layout page.
    ///
    /// # Errors
    ///
    /// Rejects hostile transport, revoked authority, unadvertised manifests, invalid source
    /// output, connection-key failure or framing IO before returning success.
    pub async fn serve_content_layout_page<R: RandomSource>(
        &self,
        connection: &quinn::Connection,
        services: FederationContentLayoutServices<'_, R>,
        request: FederationContentLayoutServeRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<ServedFederationContentLayoutPage, FederationSessionError> {
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
            peers.authenticate_content_layout_fetch(connection, &envelope, request.now, replay)?;
        let query = admitted_content_query(
            services.grant_authority,
            relationship_id,
            fetch.request(),
            request.now,
        )?;
        let grant_id = query.authority.grant.grant_id();
        let records = services.content.content_layout(query).await?;
        validate_source_records(fetch.request(), &records)?;
        let transit = transit_cipher(connection, fetch.transit_binding())?;
        let transit_key = transit
            .wrap_from_volume(
                records.header.manifest.manifest_id,
                services.source_keys,
                records.header.wrapped_key,
                services.random,
            )
            .map_err(|_| FederationSessionError::InvalidEnvelope)?;
        let response = signed_federation_content_layout_page(
            &local_identity,
            fetch.response_context(request.response_replay_nonce)?,
            response_page(fetch.request(), records, transit_key)?,
            self.negotiation_config.wire_limits(),
            request.now,
        )?;
        let outcome = response_outcome(response.envelope())?;
        send_federation(
            &mut stream.send,
            response.envelope(),
            self.negotiation_config.wire_limits(),
        )
        .await?;
        stream.send.finish().map_err(TransportError::from)?;
        Ok(ServedFederationContentLayoutPage {
            relationship_id,
            grant_id,
            chunk_count: outcome.0,
            has_next_page: outcome.1,
        })
    }
}

fn admitted_content_query(
    grants: &(impl FederationBranchAuthoritySource + ?Sized),
    relationship_id: FederationRelationshipId,
    request: &FetchFederatedContentLayout,
    now: UnixMicros,
) -> Result<FederationContentLayoutQuery, FederationSessionError> {
    let grant_id = grant_id(&request.grant_id)?;
    let resource = decode_federation_resource_scope(
        request
            .resource_scope
            .as_ref()
            .ok_or(FederationSessionError::InvalidEnvelope)?,
    )?;
    let authority = admitted_history_grant(grants, relationship_id, grant_id, resource, now)?;
    Ok(FederationContentLayoutQuery {
        authority,
        resource,
        manifest_id: manifest_id(&request.manifest_id)?,
        export_token: digest(&request.export_token)?,
        manifest_object_digest: digest(&request.manifest_object_digest)?,
        after_index: decode_content_layout_cursor(&request.cursor)?,
        limit: usize::try_from(request.limit)
            .map_err(|_| FederationSessionError::InvalidEnvelope)?,
        now,
    })
}

fn wire_request(request: &FederationContentLayoutFetchRequest) -> FetchFederatedContentLayout {
    FetchFederatedContentLayout {
        grant_id: request.grant_id.as_bytes().to_vec(),
        resource_scope: Some(version_federation_resource_scope(request.resource)),
        manifest_id: request.manifest_id.as_bytes().to_vec(),
        export_token: request.export_token.to_vec(),
        manifest_object_digest: request.manifest_object_digest.to_vec(),
        cursor: request.cursor.clone(),
        limit: request.limit,
        signature: Vec::new(),
    }
}

fn response_page(
    request: &FetchFederatedContentLayout,
    records: FederationContentLayoutRecords,
    transit_key: meshspan_filesystem::TransitWrappedContentKey,
) -> Result<FederatedContentLayoutPage, FederationSessionError> {
    let (chunks, next_cursor) = match records.page {
        Some(page) => {
            let chunks = page
                .chunks()
                .iter()
                .copied()
                .map(version_federated_content_layout_chunk)
                .collect::<Result<Vec<_>, _>>()?;
            let cursor = page
                .next_index()
                .map_or_else(Vec::new, encode_content_layout_cursor);
            (chunks, cursor)
        }
        None => (Vec::new(), Vec::new()),
    };
    Ok(FederatedContentLayoutPage {
        grant_id: request.grant_id.clone(),
        resource_scope: request.resource_scope.clone(),
        manifest_id: request.manifest_id.clone(),
        export_token: request.export_token.clone(),
        manifest_object_digest: request.manifest_object_digest.clone(),
        layout_header: Some(version_federated_content_layout_header(
            records.header,
            transit_key,
        )),
        chunks,
        next_cursor,
        page_digest: Vec::new(),
        signature: Vec::new(),
    })
}

fn decode_received_page<R: RandomSource>(
    page: &meshspan_transport::AuthenticatedFederationContentLayoutPage,
    request: &FederationContentLayoutFetchRequest,
    transit: &ContentKeyTransitCipher,
    target_keys: &ContentKeyEnvelopeCipher,
    random: &mut R,
) -> Result<ReceivedFederationContentLayoutPage, FederationSessionError> {
    let decoded_header = decode_federated_content_layout_header(
        page.layout_header()
            .ok_or(FederationSessionError::InvalidEnvelope)?,
        transit,
        target_keys,
        random,
    )?;
    let header = stable_receiver_header(request, decoded_header)?;
    let chunks = page
        .chunks()
        .iter()
        .map(decode_federated_content_layout_chunk)
        .collect::<Result<Vec<_>, _>>()?;
    let next_index = decode_content_layout_cursor(page.next_cursor())?;
    let layout_page = if chunks.is_empty() {
        if header.chunk_count != 0 || next_index.is_some() || !request.cursor.is_empty() {
            return Err(FederationSessionError::InvalidEnvelope);
        }
        None
    } else {
        let decoded = ContentLayoutTransferPage::from_untrusted(chunks, next_index)
            .map_err(|_| FederationSessionError::InvalidEnvelope)?;
        validate_page_position(&request.cursor, header, &decoded)?;
        Some(decoded)
    };
    Ok(ReceivedFederationContentLayoutPage {
        header,
        page: layout_page,
        next_cursor: page.next_cursor().to_vec(),
    })
}

fn stable_receiver_header(
    request: &FederationContentLayoutFetchRequest,
    decoded: ContentLayoutTransferHeader,
) -> Result<ContentLayoutTransferHeader, FederationSessionError> {
    if decoded.manifest.manifest_id != request.manifest_id {
        return Err(FederationSessionError::InvalidEnvelope);
    }
    match request.existing_header {
        None if request.cursor.is_empty() => Ok(decoded),
        Some(existing)
            if !request.cursor.is_empty()
                && existing.manifest == decoded.manifest
                && existing.chunk_bytes == decoded.chunk_bytes
                && existing.chunk_count == decoded.chunk_count =>
        {
            Ok(existing)
        }
        None | Some(_) => Err(FederationSessionError::InvalidEnvelope),
    }
}

fn validate_page_position(
    cursor: &[u8],
    header: ContentLayoutTransferHeader,
    page: &ContentLayoutTransferPage,
) -> Result<(), FederationSessionError> {
    let after = decode_content_layout_cursor(cursor)?;
    let first = page
        .chunks()
        .first()
        .ok_or(FederationSessionError::InvalidEnvelope)?
        .chunk_index;
    let last = page
        .chunks()
        .last()
        .ok_or(FederationSessionError::InvalidEnvelope)?
        .chunk_index;
    let expected_first = after.map_or(Some(0), |index| index.checked_add(1));
    let has_more = last
        .checked_add(1)
        .is_some_and(|next| next < header.chunk_count);
    if Some(first) == expected_first
        && last < header.chunk_count
        && page.next_index() == has_more.then_some(last)
    {
        Ok(())
    } else {
        Err(FederationSessionError::InvalidEnvelope)
    }
}

fn validate_client_request(
    request: &FederationContentLayoutFetchRequest,
) -> Result<(), FederationSessionError> {
    let limit =
        usize::try_from(request.limit).map_err(|_| FederationSessionError::InvalidEnvelope)?;
    let continuation_shape = request.cursor.is_empty() == request.existing_header.is_none();
    if limit == 0
        || limit > MAXIMUM_CONTENT_LAYOUT_PAGE_ITEMS
        || !continuation_shape
        || decode_content_layout_cursor(&request.cursor).is_err()
    {
        Err(FederationSessionError::InvalidEnvelope)
    } else {
        Ok(())
    }
}

fn validate_source_records(
    request: &FetchFederatedContentLayout,
    records: &FederationContentLayoutRecords,
) -> Result<(), FederationSessionError> {
    let manifest = manifest_id(&request.manifest_id)?;
    if records.header.manifest.manifest_id != manifest {
        return Err(FederationSessionError::InvalidEnvelope);
    }
    match &records.page {
        None if records.header.chunk_count == 0 && request.cursor.is_empty() => Ok(()),
        Some(page) => validate_page_position(&request.cursor, records.header, page),
        None => Err(FederationSessionError::InvalidEnvelope),
    }
}

fn transit_cipher(
    connection: &quinn::Connection,
    binding: [u8; 32],
) -> Result<ContentKeyTransitCipher, FederationSessionError> {
    let mut exporter_key = [0_u8; 32];
    connection
        .export_keying_material(&mut exporter_key, CONTENT_KEY_EXPORTER_LABEL, &binding)
        .map_err(|_| FederationSessionError::InvalidEnvelope)?;
    ContentKeyTransitCipher::new(exporter_key, binding)
        .map_err(|_| FederationSessionError::InvalidEnvelope)
}

fn response_outcome(
    envelope: &meshspan_protocol::v1::FederationEnvelope,
) -> Result<(usize, bool), FederationSessionError> {
    let Some(meshspan_protocol::v1::federation_envelope::Message::ContentLayoutPage(page)) =
        envelope.message.as_ref()
    else {
        return Err(FederationSessionError::InvalidEnvelope);
    };
    Ok((page.chunks.len(), !page.next_cursor.is_empty()))
}

fn grant_id(bytes: &[u8]) -> Result<FederationGrantId, FederationSessionError> {
    FederationGrantId::from_bytes(
        bytes
            .try_into()
            .map_err(|_| FederationSessionError::InvalidEnvelope)?,
    )
    .map_err(|_| FederationSessionError::InvalidEnvelope)
}

fn manifest_id(bytes: &[u8]) -> Result<ContentManifestId, FederationSessionError> {
    ContentManifestId::from_bytes(
        bytes
            .try_into()
            .map_err(|_| FederationSessionError::InvalidEnvelope)?,
    )
    .map_err(|_| FederationSessionError::InvalidEnvelope)
}

fn digest(bytes: &[u8]) -> Result<[u8; 32], FederationSessionError> {
    bytes
        .try_into()
        .map_err(|_| FederationSessionError::InvalidEnvelope)
}
