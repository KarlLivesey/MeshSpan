// SPDX-License-Identifier: GPL-2.0-only

//! Focused real-QUIC proof support for stable federation authority paging.

use std::error::Error;

use meshspan_cluster::{
    FederationAuthorityFetchRequest, FederationAuthorityImportLimits, FederationAuthorityPageQuery,
    FederationAuthorityPageServeRequest, FederationAuthorityPageSource,
    FederationAuthorityPageSourceError, FederationAuthoritySyncError,
    FederationAuthoritySyncOutcome, FederationAuthoritySyncRequest, FederationAuthorityUpdate,
    FederationRemoteAuthoritySnapshotReceiver, federation_connection_authority,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    DurationMicros, FederatedPrincipal, FederationGrant, FederationGrantId, FederationPolicy,
    FederationRelationshipId, FederationResourceScope, MeshId, NodeId, PrincipalId, Revision,
    StorageFederationPolicy, StorageParticipation, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, FederationGrantRestriction, FederationRemoteAuthorityCacheDisposition,
    IssueFederationGrant, LocalDatabase,
};
use meshspan_protocol::v1::ProtocolVersion;
use meshspan_transport::{FederationExchangeContext, FederationReplayGuard};
use tempfile::tempdir;

use super::branch_page_proof::prove_branch_page_service;
use super::{NOW, SessionProof, prove_admitted_session, replay_guard};

struct CompleteAuthorityStream {
    update: FederationAuthorityUpdate,
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
    let mut receiver = receiver(proof, Revision::ZERO)?;
    receiver.accept_page(&[], &page)?;
    let FederationAuthorityUpdate::Snapshot(snapshot) = receiver.finish()? else {
        return Err("initial authority snapshot was not returned".into());
    };
    assert_eq!(snapshot.relationship.relationship.authority_epoch, 1);
    assert_eq!(snapshot.relationship.local_identity.identity.generation, 1);
    assert!(page.next_cursor().is_empty());
    prove_branch_page_service(proof).await?;
    Ok(())
}

pub(super) async fn prove_rotated_authority(
    proof: &SessionProof<'_>,
    expected_grants: &[FederationGrantId],
) -> Result<Vec<u8>, Box<dyn Error>> {
    prove_admitted_session(proof).await?;
    let stream = exchange_complete_authority(proof, 3).await?;
    let FederationAuthorityUpdate::Snapshot(snapshot) = stream.update else {
        return Err("rotated authority snapshot was not returned".into());
    };
    assert_eq!(snapshot.relationship.remote_identity.identity.generation, 2);
    assert_eq!(
        snapshot
            .grants
            .iter()
            .map(|record| record.grant.grant_id())
            .collect::<Vec<_>>(),
        expected_grants
    );
    prove_persisted_authority_sync(proof, expected_grants).await?;
    prove_authority_cursor_fails_closed(proof, &stream.first_cursor)?;
    Ok(stream.first_cursor)
}

async fn prove_persisted_authority_sync(
    proof: &SessionProof<'_>,
    expected_grants: &[FederationGrantId],
) -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let database_path = directory.path().join("local.sqlite3");
    let node_id = NodeId::from_bytes([101; 16])?;
    let mut cache = LocalDatabase::open(&database_path, node_id, NOW)?;
    assert_eq!(
        cache.remote_federation_authority_revision(proof.relationship_id)?,
        Revision::ZERO
    );
    let page_count = expected_grants.len().saturating_add(1);
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let incomplete_sync = proof.client_runtime.sync_remote_authority(
        proof.client_connection,
        proof.client_authority,
        &mut cache,
        sync_request(proof.relationship_id, 1, 130)?,
        &mut client_replay,
    );
    let incomplete_serve = async {
        serve_sync_pages(proof, 1, 140, &mut server_replay)
            .await
            .map_err(FederationAuthoritySyncError::from)
    };
    let incomplete = tokio::try_join!(incomplete_sync, incomplete_serve);
    assert!(matches!(
        incomplete,
        Err(FederationAuthoritySyncError::Incomplete)
    ));
    assert_eq!(
        cache.remote_federation_authority_revision(proof.relationship_id)?,
        Revision::ZERO
    );

    let sync = proof.client_runtime.sync_remote_authority(
        proof.client_connection,
        proof.client_authority,
        &mut cache,
        sync_request(proof.relationship_id, page_count, 150)?,
        &mut client_replay,
    );
    let serve = async {
        serve_sync_pages(proof, page_count, 190, &mut server_replay)
            .await
            .map_err(FederationAuthoritySyncError::from)
    };
    let (outcome, ()) = tokio::try_join!(sync, serve)?;
    assert_eq!(
        outcome,
        FederationAuthoritySyncOutcome::Updated {
            authority_revision: Revision::new(6),
            disposition: FederationRemoteAuthorityCacheDisposition::Applied,
            pages: page_count,
            records: page_count,
        }
    );
    assert_eq!(
        cache.remote_federation_authority_revision(proof.relationship_id)?,
        Revision::new(6)
    );
    for grant_id in expected_grants {
        assert!(
            cache
                .remote_federation_grant_authority(proof.relationship_id, *grant_id)?
                .is_some()
        );
    }
    drop(cache);

    let mut cache = LocalDatabase::open(&database_path, node_id, NOW)?;
    let sync = proof.client_runtime.sync_remote_authority(
        proof.client_connection,
        proof.client_authority,
        &mut cache,
        sync_request(proof.relationship_id, 1, 220)?,
        &mut client_replay,
    );
    let serve = async {
        serve_sync_pages(proof, 1, 230, &mut server_replay)
            .await
            .map_err(FederationAuthoritySyncError::from)
    };
    let (outcome, ()) = tokio::try_join!(sync, serve)?;
    assert_eq!(
        outcome,
        FederationAuthoritySyncOutcome::Unchanged {
            authority_revision: Revision::new(6),
            pages: 1,
        }
    );
    Ok(())
}

async fn serve_sync_pages(
    proof: &SessionProof<'_>,
    page_count: usize,
    nonce_seed: u8,
    replay: &mut FederationReplayGuard,
) -> Result<(), meshspan_cluster::FederationSessionError> {
    for index in 0..page_count {
        let offset = u8::try_from(index).unwrap_or(u8::MAX);
        proof
            .server_runtime
            .serve_authority_page(
                proof.server_connection,
                proof.server_authority,
                proof.server_authority,
                FederationAuthorityPageServeRequest {
                    response_replay_nonce: [nonce_seed.saturating_add(offset); 32],
                    now: NOW,
                },
                replay,
            )
            .await?;
    }
    Ok(())
}

fn sync_request(
    relationship_id: FederationRelationshipId,
    page_count: usize,
    seed: u8,
) -> Result<FederationAuthoritySyncRequest, Box<dyn Error>> {
    let contexts = (0..page_count)
        .map(|index| {
            let offset = u8::try_from(index).unwrap_or(u8::MAX).saturating_mul(5);
            FederationExchangeContext::new(
                ProtocolVersion { major: 1, minor: 1 },
                [seed.saturating_add(offset); 16],
                [seed.saturating_add(offset).saturating_add(1); 16],
                [seed.saturating_add(offset).saturating_add(2); 16],
                UnixMicros::new(2_000_000),
                [seed.saturating_add(offset).saturating_add(3); 32],
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(FederationAuthoritySyncRequest::new(
        relationship_id,
        contexts,
        1,
        FederationAuthorityImportLimits::new(page_count, page_count, 1_048_576)?,
        NOW,
    )?)
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
            context: FederationExchangeContext::new(
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
    let mut receiver = receiver(proof, Revision::new(after_revision))?;
    for sequence in 0..4 {
        let requested_cursor = cursor;
        let page = exchange_authority_page(
            proof,
            AuthorityPageRequest {
                after_revision,
                cursor: requested_cursor.clone(),
                sequence,
            },
            &mut client_replay,
            &mut server_replay,
        )
        .await?;
        assert_eq!(page.authority_revision(), 6);
        receiver.accept_page(&requested_cursor, &page)?;
        cursor = receiver.next_cursor().map_or_else(Vec::new, <[u8]>::to_vec);
        if sequence == 0 {
            first_cursor.clone_from(&cursor);
        }
        if cursor.is_empty() {
            return Ok(CompleteAuthorityStream {
                update: receiver.finish()?,
                first_cursor,
            });
        }
    }
    Err("authority stream did not terminate within its exact expected bound".into())
}

fn receiver(
    proof: &SessionProof<'_>,
    after_revision: Revision,
) -> Result<FederationRemoteAuthoritySnapshotReceiver, Box<dyn Error>> {
    let authority =
        federation_connection_authority(proof.client_authority, proof.relationship_id, NOW)?
            .ok_or("local federation authority missing")?;
    Ok(FederationRemoteAuthoritySnapshotReceiver::new(
        authority,
        after_revision,
        FederationAuthorityImportLimits::new(4, 4, 1_048_576)?,
    ))
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
        Some(UnixMicros::new(3_000_000)),
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
        Some(DurationMicros::new(3_000_000)),
    )?))
}
