// SPDX-License-Identifier: GPL-2.0-only

//! Focused real-QUIC proof support for stable federation authority paging.

use std::error::Error;

use meshspan_cluster::{
    FederationAuthorityFetchRequest, FederationAuthorityPageQuery,
    FederationAuthorityPageServeRequest, FederationAuthorityPageSource,
    FederationAuthorityPageSourceError,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    DurationMicros, FederatedPrincipal, FederationGrant, FederationGrantId, FederationPolicy,
    FederationRelationshipId, FederationResourceScope, MeshId, PrincipalId, Revision,
    StorageFederationPolicy, StorageParticipation, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, FederationGrantRecord, FederationGrantRestriction,
    FederationTransportAuthority, IssueFederationGrant,
};
use meshspan_protocol::v1::ProtocolVersion;
use meshspan_transport::{FederationAuthorityContext, FederationReplayGuard};

use super::{NOW, SessionProof, prove_admitted_session, replay_guard};

struct CompleteAuthorityStream {
    records: Vec<meshspan_protocol::v1::VersionedPayload>,
    first_cursor: Vec<u8>,
}

#[derive(Clone, Debug)]
struct AuthorityPageRequest {
    after_revision: u64,
    cursor: Vec<u8>,
    sequence: u8,
}

impl AuthorityPageRequest {
    const fn initial(after_revision: u64) -> Self {
        Self {
            after_revision,
            cursor: Vec::new(),
            sequence: 0,
        }
    }
}

pub(super) async fn prove_initial_authority(
    proof: &SessionProof<'_>,
) -> Result<(), Box<dyn Error>> {
    prove_admitted_session(proof).await?;
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let page = exchange_authority_page(
        proof,
        AuthorityPageRequest::initial(0),
        &mut client_replay,
        &mut server_replay,
    )
    .await?;
    assert_eq!(page.authority_revision(), 3);
    let snapshot =
        FederationTransportAuthority::from_canonical_bytes(&page.records()[0].canonical_bytes)?;
    assert_eq!(snapshot.relationship.authority_epoch, 1);
    assert_eq!(snapshot.remote_identity.identity.generation, 1);
    assert!(page.next_cursor().is_empty());
    Ok(())
}

pub(super) async fn prove_rotated_authority(
    proof: &SessionProof<'_>,
    expected_grants: &[FederationGrantId],
) -> Result<Vec<u8>, Box<dyn Error>> {
    prove_admitted_session(proof).await?;
    let stream = exchange_complete_authority(proof, 3).await?;
    let snapshot =
        FederationTransportAuthority::from_canonical_bytes(&stream.records[0].canonical_bytes)?;
    assert_eq!(snapshot.remote_identity.identity.generation, 2);
    let received_grants = stream.records[1..]
        .iter()
        .map(|record| FederationGrantRecord::from_canonical_bytes(&record.canonical_bytes))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        received_grants
            .iter()
            .map(|record| record.grant.grant_id())
            .collect::<Vec<_>>(),
        expected_grants
    );
    prove_authority_cursor_fails_closed(proof, &stream.first_cursor)?;
    Ok(stream.first_cursor)
}

async fn exchange_authority_page(
    proof: &SessionProof<'_>,
    request: AuthorityPageRequest,
    client_replay: &mut FederationReplayGuard,
    server_replay: &mut FederationReplayGuard,
) -> Result<meshspan_transport::AuthenticatedFederationAuthorityPage, Box<dyn Error>> {
    let seed = proof
        .session_seed
        .saturating_add(40)
        .saturating_add(request.sequence.saturating_mul(8));
    let fetch = proof.client_runtime.fetch_authority_page(
        proof.client_connection,
        proof.client_authority,
        FederationAuthorityFetchRequest {
            relationship_id: proof.relationship_id,
            context: FederationAuthorityContext::new(
                ProtocolVersion { major: 1, minor: 1 },
                [seed; 16],
                [seed.saturating_add(1); 16],
                [seed.saturating_add(2); 16],
                UnixMicros::new(2_000_000),
                [seed.saturating_add(3); 32],
            )?,
            after_revision: request.after_revision,
            cursor: request.cursor,
            limit: 1,
            now: NOW,
        },
        client_replay,
    );
    let serve = proof.server_runtime.serve_authority_page(
        proof.server_connection,
        proof.server_authority,
        proof.server_authority,
        FederationAuthorityPageServeRequest {
            response_replay_nonce: [seed.saturating_add(4); 32],
            now: NOW,
        },
        server_replay,
    );
    let (page, served) = tokio::try_join!(fetch, serve)?;
    assert_eq!(served.relationship_id, proof.relationship_id);
    assert_eq!(served.authority_revision.get(), page.authority_revision());
    assert_eq!(served.record_count, page.records().len());
    assert_eq!(served.has_next_page, !page.next_cursor().is_empty());
    Ok(page)
}

async fn exchange_complete_authority(
    proof: &SessionProof<'_>,
    after_revision: u64,
) -> Result<CompleteAuthorityStream, Box<dyn Error>> {
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let mut cursor = Vec::new();
    let mut first_cursor = Vec::new();
    let mut records = Vec::new();
    for sequence in 0..4 {
        let page = exchange_authority_page(
            proof,
            AuthorityPageRequest {
                after_revision,
                cursor,
                sequence,
            },
            &mut client_replay,
            &mut server_replay,
        )
        .await?;
        assert_eq!(page.authority_revision(), 6);
        records.extend_from_slice(page.records());
        cursor = page.next_cursor().to_vec();
        if sequence == 0 {
            first_cursor.clone_from(&cursor);
        }
        if cursor.is_empty() {
            return Ok(CompleteAuthorityStream {
                records,
                first_cursor,
            });
        }
    }
    Err("authority stream did not terminate within its exact expected bound".into())
}

fn prove_authority_cursor_fails_closed(
    proof: &SessionProof<'_>,
    cursor: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut tampered = cursor.to_vec();
    let first = tampered.first_mut().ok_or("authority cursor missing")?;
    *first ^= 1;
    assert!(matches!(
        proof
            .server_authority
            .authority_page(FederationAuthorityPageQuery {
                relationship_id: proof.relationship_id,
                after_revision: 3,
                cursor: tampered,
                limit: 1,
                authority_revision: Revision::new(6),
            }),
        Err(FederationAuthorityPageSourceError::InvalidQuery)
    ));
    Ok(())
}

pub(super) fn storage_grant_command(
    grant_id: FederationGrantId,
    relationship_id: FederationRelationshipId,
    consumer_mesh_id: MeshId,
    provider_mesh_id: MeshId,
) -> Result<AuthoritativeCommand, Box<dyn Error>> {
    let consumer_policy = storage_policy(100, true)?;
    let provider_policy = storage_policy(50, false)?;
    let restrictions = ordered_restrictions(
        consumer_mesh_id,
        consumer_policy,
        provider_mesh_id,
        provider_policy,
    );
    let policies = restrictions
        .iter()
        .map(|restriction| restriction.policy)
        .collect::<Vec<_>>();
    let grant = FederationGrant::new(
        grant_id,
        relationship_id,
        FederatedPrincipal::new(consumer_mesh_id, PrincipalId::from_bytes([90; 16])?),
        FederationResourceScope::StorageCapacity { provider_mesh_id },
        FederationPolicy::intersect(&policies)?,
        1,
        UnixMicros::new(4),
        Some(UnixMicros::new(1_000_000)),
    )?;
    Ok(AuthoritativeCommand::IssueFederationGrant(
        IssueFederationGrant {
            grant,
            restrictions: BoundedItems::new(restrictions, 2)?,
        },
    ))
}

fn ordered_restrictions(
    first_mesh: MeshId,
    first_policy: FederationPolicy,
    second_mesh: MeshId,
    second_policy: FederationPolicy,
) -> Vec<FederationGrantRestriction> {
    let mut restrictions = vec![
        FederationGrantRestriction {
            imposing_mesh_id: first_mesh,
            policy: first_policy,
        },
        FederationGrantRestriction {
            imposing_mesh_id: second_mesh,
            policy: second_policy,
        },
    ];
    restrictions.sort_by_key(|restriction| restriction.imposing_mesh_id);
    restrictions
}

fn storage_policy(
    maximum_storage_bytes: u64,
    counts_towards_protection: bool,
) -> Result<FederationPolicy, Box<dyn Error>> {
    Ok(FederationPolicy::Storage(StorageFederationPolicy::new(
        maximum_storage_bytes,
        StorageParticipation::new(counts_towards_protection, true),
        Some(DurationMicros::new(1_000_000)),
    )?))
}
