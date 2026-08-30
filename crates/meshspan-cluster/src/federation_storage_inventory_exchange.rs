// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated bounded federation storage inventory over one Quinn stream.

use meshspan_contracts::{
    BoundedBytes, BoundedItems, ContractError, FederatedStorageInventoryRecord, StorageProvider,
};
use meshspan_domain::{
    FederationGrantId, FederationRelationshipId, FederationResourceScope, MeshId, TargetId,
    UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeRepository, FederationStorageAuthorityRequest, FederationStorageInventoryError,
    LocalDatabase, MAXIMUM_FEDERATED_STORAGE_INVENTORY_ITEMS, RepositoryError,
};
use meshspan_protocol::v1::{FederatedStorageInventoryPage, FetchFederatedStorageInventory};
use meshspan_transport::{
    FederationExchangeContext, FederationReplayGuard, StreamKind, TransportError, accept_stream,
    open_stream, receive_federation, send_federation, signed_federation_storage_inventory_fetch,
    signed_federation_storage_inventory_page,
};
use thiserror::Error;

use crate::federation_session::{envelope_relationship, load_authority};
use crate::federation_storage_inventory_wire::{decode_inventory_cursor, encode_inventory_cursor};
use crate::{
    FederationAuthoritySource, FederationSessionError, FederationSessionRuntime,
    decode_federated_storage_inventory_record, version_federated_storage_inventory_record,
};

/// Complete consumer-side input for one bounded provider inventory request.
#[derive(Clone, Debug, PartialEq)]
pub struct FederationStorageInventoryFetchRequest {
    /// Current bilateral relationship carrying the query.
    pub relationship_id: FederationRelationshipId,
    /// Signed tenant, target, continuation and page limit.
    pub inventory: FetchFederatedStorageInventory,
    /// Fresh request identity, deadline and replay nonce.
    pub context: FederationExchangeContext,
    /// Current quorum-derived mesh time.
    pub now: UnixMicros,
}

/// Fresh provider-side values for one inventory response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageInventoryServeRequest {
    /// Fresh response nonce distinct from the request nonce.
    pub response_replay_nonce: [u8; 32],
    /// Current quorum-derived mesh time.
    pub now: UnixMicros,
}

/// Provider resources whose independent catalogues must agree before publication.
pub struct FederationStorageInventoryProvider<'a, Provider> {
    /// Current replicated relationship, grant and allocation authority.
    pub repository: &'a AuthoritativeRepository,
    /// Node-local tenant and logical shard catalogue.
    pub local_database: &'a LocalDatabase,
    /// Exact target provider catalogue.
    pub provider: &'a Provider,
}

/// Authenticated and canonically decoded provider inventory page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedFederationStorageInventoryPage {
    /// Active encrypted shards in stable provider order.
    pub records: BoundedItems<FederatedStorageInventoryRecord>,
    /// Opaque signed continuation, absent only at the end.
    pub next_cursor: Option<BoundedBytes>,
}

/// Non-secret provider outcome after signing and sending one page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServedFederationStorageInventoryPage {
    /// Relationship whose authenticated peer requested the page.
    pub relationship_id: FederationRelationshipId,
    /// Number of exact active records returned.
    pub record_count: usize,
    /// Whether the signed response carried a continuation.
    pub has_more: bool,
}

impl FederationSessionRuntime<'_> {
    /// Sends one signed bounded inventory query and authenticates every response record.
    ///
    /// # Errors
    ///
    /// Rejects unavailable authority, signature/replay/correlation failure, non-canonical records
    /// or cursors, framing bounds and Quinn IO.
    pub async fn request_storage_inventory(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        request: FederationStorageInventoryFetchRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<ReceivedFederationStorageInventoryPage, FederationSessionError> {
        let current = load_authority(authority, request.relationship_id, request.now)?;
        let local_identity = self.local_identity(&current, request.now)?;
        let peers = meshspan_transport::FederationPeerRegistry::new([current.peer])?;
        let outbound = signed_federation_storage_inventory_fetch(
            &local_identity,
            request.context,
            request.inventory,
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
        let authenticated = peers.authenticate_storage_inventory_page(
            connection,
            &response,
            outbound.expectation(),
            request.now,
            replay,
        )?;
        let requested_limit = usize::try_from(outbound.expectation().request_limit())
            .map_err(|_| FederationStorageInventoryExchangeError::InvalidQuery)?;
        decode_received_page(
            &authenticated,
            requested_limit,
            self.hello_config.wire_limits().maximum_control_bytes(),
        )
        .map_err(Into::into)
    }

    /// Authenticates a query, revalidates every current authority and signs one exact page.
    ///
    /// # Errors
    ///
    /// Rejects wrong streams, revoked or substituted grants/allocations, tenant mismatch,
    /// contradictory logical/provider catalogues, malformed paging and transport failure.
    pub async fn serve_storage_inventory<Provider: StorageProvider>(
        &self,
        connection: &quinn::Connection,
        resources: FederationStorageInventoryProvider<'_, Provider>,
        request: FederationStorageInventoryServeRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<ServedFederationStorageInventoryPage, FederationSessionError> {
        let mut stream = accept_stream(connection).await?;
        if stream.kind != StreamKind::Federation {
            return Err(FederationSessionError::WrongStream);
        }
        let envelope =
            receive_federation(&mut stream.receive, self.negotiation_config.wire_limits()).await?;
        let relationship_id = envelope_relationship(&envelope)?;
        let current = load_authority(resources.repository, relationship_id, request.now)?;
        let local_identity = self.local_identity(&current, request.now)?;
        let peers = meshspan_transport::FederationPeerRegistry::new([current.peer])?;
        let authenticated = peers.authenticate_storage_inventory_fetch(
            connection,
            &envelope,
            request.now,
            replay,
        )?;
        let response_context = authenticated.response_context(request.response_replay_nonce)?;
        let query = parse_query(authenticated.request())?;
        validate_grant(
            resources.repository,
            relationship_id,
            authenticated.remote_mesh_id(),
            local_identity.binding().local_mesh_id,
            query.grant_id,
            request.now,
        )?;
        let page = resources
            .local_database
            .federated_storage_inventory_page(
                authenticated.remote_mesh_id(),
                query.grant_id,
                query.target_id,
                query.target_generation,
                query.cursor,
                query.limit,
            )
            .map_err(FederationStorageInventoryExchangeError::from)?;
        validate_records(
            &resources,
            relationship_id,
            authenticated.remote_mesh_id(),
            query,
            page.records.as_slice(),
            request.now,
        )?;
        let records = page
            .records
            .as_slice()
            .iter()
            .copied()
            .map(version_federated_storage_inventory_record)
            .collect::<Result<Vec<_>, _>>()
            .map_err(FederationStorageInventoryExchangeError::from)?;
        let next_cursor = page
            .next_cursor
            .map_or_else(Vec::new, encode_inventory_cursor);
        let signed = signed_federation_storage_inventory_page(
            &local_identity,
            response_context,
            FederatedStorageInventoryPage {
                grant_id: query.grant_id.as_bytes().to_vec(),
                target_id: query.target_id.as_bytes().to_vec(),
                target_generation: query.target_generation,
                records,
                next_cursor,
                page_digest: Vec::new(),
                signature: Vec::new(),
            },
            self.negotiation_config.wire_limits(),
            request.now,
        )?;
        send_federation(
            &mut stream.send,
            signed.envelope(),
            self.negotiation_config.wire_limits(),
        )
        .await?;
        stream.send.finish().map_err(TransportError::from)?;
        Ok(ServedFederationStorageInventoryPage {
            relationship_id,
            record_count: page.records.len(),
            has_more: page.next_cursor.is_some(),
        })
    }
}

#[derive(Clone, Copy)]
struct ParsedInventoryQuery {
    grant_id: FederationGrantId,
    target_id: TargetId,
    target_generation: u64,
    cursor: Option<meshspan_metadata::FederationStorageInventoryCursor>,
    limit: usize,
}

fn parse_query(
    request: &FetchFederatedStorageInventory,
) -> Result<ParsedInventoryQuery, FederationStorageInventoryExchangeError> {
    let limit = usize::try_from(request.limit)
        .map_err(|_| FederationStorageInventoryExchangeError::InvalidQuery)?;
    if !(1..=MAXIMUM_FEDERATED_STORAGE_INVENTORY_ITEMS).contains(&limit) {
        return Err(FederationStorageInventoryExchangeError::InvalidQuery);
    }
    Ok(ParsedInventoryQuery {
        grant_id: FederationGrantId::from_bytes(exact(&request.grant_id)?)
            .map_err(|_| FederationStorageInventoryExchangeError::InvalidQuery)?,
        target_id: TargetId::from_bytes(exact(&request.target_id)?)
            .map_err(|_| FederationStorageInventoryExchangeError::InvalidQuery)?,
        target_generation: request.target_generation,
        cursor: decode_inventory_cursor(&request.cursor)?,
        limit,
    })
}

fn validate_grant(
    repository: &AuthoritativeRepository,
    relationship_id: FederationRelationshipId,
    remote_mesh_id: MeshId,
    local_mesh_id: MeshId,
    grant_id: FederationGrantId,
    now: UnixMicros,
) -> Result<(), FederationStorageInventoryExchangeError> {
    let record = repository
        .active_federation_grant(grant_id)?
        .ok_or(FederationStorageInventoryExchangeError::AuthorityUnavailable)?;
    let grant = record.grant;
    let valid = grant.relationship_id() == relationship_id
        && grant.recipient_mesh_id() == remote_mesh_id
        && grant.resource()
            == FederationResourceScope::StorageCapacity {
                provider_mesh_id: local_mesh_id,
            }
        && now >= grant.valid_from()
        && grant.valid_until().is_none_or(|until| now < until);
    if valid {
        Ok(())
    } else {
        Err(FederationStorageInventoryExchangeError::AuthorityUnavailable)
    }
}

fn validate_records<Provider: StorageProvider>(
    resources: &FederationStorageInventoryProvider<'_, Provider>,
    relationship_id: FederationRelationshipId,
    remote_mesh_id: MeshId,
    query: ParsedInventoryQuery,
    records: &[FederatedStorageInventoryRecord],
    now: UnixMicros,
) -> Result<(), FederationStorageInventoryExchangeError> {
    for record in records {
        let authority = resources
            .repository
            .active_federation_storage_allocation_authority(FederationStorageAuthorityRequest {
                relationship_id,
                remote_mesh_id,
                provider_node_id: resources.local_database.node_id(),
                allocation_id: record.allocation_id,
                grant_id: query.grant_id,
                target_id: query.target_id,
                target_generation: query.target_generation,
                requested_bytes: record.length,
                observed_at: now,
            })?
            .ok_or(FederationStorageInventoryExchangeError::AuthorityUnavailable)?;
        if authority.allocation().allocation_id() != record.allocation_id {
            return Err(FederationStorageInventoryExchangeError::AuthorityUnavailable);
        }
        let expected = record.provider_entry(remote_mesh_id);
        let observed = resources
            .provider
            .inventory_exact(expected.shard)?
            .ok_or(FederationStorageInventoryExchangeError::CatalogueMismatch)?;
        if observed.shard != expected.shard
            || observed.length != expected.length
            || observed.digest != expected.digest
        {
            return Err(FederationStorageInventoryExchangeError::CatalogueMismatch);
        }
    }
    Ok(())
}

fn decode_received_page(
    page: &meshspan_transport::AuthenticatedFederationStorageInventoryPage,
    requested_limit: usize,
    maximum_cursor_bytes: usize,
) -> Result<ReceivedFederationStorageInventoryPage, FederationStorageInventoryExchangeError> {
    let records = page
        .records()
        .iter()
        .map(decode_federated_storage_inventory_record)
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = if page.next_cursor().is_empty() {
        None
    } else {
        decode_inventory_cursor(page.next_cursor())?;
        Some(
            BoundedBytes::copy_from(page.next_cursor(), maximum_cursor_bytes)
                .map_err(|_| FederationStorageInventoryExchangeError::InvalidQuery)?,
        )
    };
    Ok(ReceivedFederationStorageInventoryPage {
        records: BoundedItems::new(records, requested_limit)
            .map_err(|_| FederationStorageInventoryExchangeError::InvalidQuery)?,
        next_cursor,
    })
}

fn exact<const LENGTH: usize>(
    bytes: &[u8],
) -> Result<[u8; LENGTH], FederationStorageInventoryExchangeError> {
    bytes
        .try_into()
        .map_err(|_| FederationStorageInventoryExchangeError::InvalidQuery)
}

/// Stable failures while producing or consuming exact provider inventory.
#[derive(Debug, Error)]
pub enum FederationStorageInventoryExchangeError {
    /// Request or canonical wire record/cursor was malformed.
    #[error("federation storage inventory query is invalid")]
    InvalidQuery,
    /// Current relationship, grant or allocation authority is unavailable.
    #[error("federation storage inventory authority is unavailable")]
    AuthorityUnavailable,
    /// Logical and target-provider catalogues contradicted one another.
    #[error("federation storage inventory catalogues disagree")]
    CatalogueMismatch,
    /// Node-local logical inventory could not be read safely.
    #[error("federation storage inventory metadata failed")]
    Metadata(#[from] FederationStorageInventoryError),
    /// Replicated grant or allocation evidence could not be read safely.
    #[error("federation storage inventory authority read failed")]
    Repository(#[from] RepositoryError),
    /// Canonical inventory record or cursor bytes were invalid.
    #[error("federation storage inventory wire value failed")]
    Wire(#[from] crate::FederationStorageInventoryWireError),
    /// Exact provider catalogue lookup failed.
    #[error("federation storage provider catalogue failed")]
    Provider(#[from] ContractError),
}
