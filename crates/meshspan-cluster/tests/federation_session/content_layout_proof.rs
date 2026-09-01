// SPDX-License-Identifier: GPL-2.0-only

//! Real-Quinn proof for export-bound, connection-keyed portable encrypted-content layouts.

use std::error::Error;
use std::fs;
use std::io::Write;
use std::time::Duration;

use meshspan_cluster::{
    FederationContentHealingRequest, FederationContentLayoutFetchRequest,
    FederationContentLayoutServeRequest, FederationContentLayoutServices,
    FederationContentLayoutSourceError, FederationContentRouteSource,
    FederationContentShardFetchRequest, FederationContentShardFetchServices,
    FederationContentShardProviderBinding, FederationContentShardServeRequest,
    FederationContentShardServices, FederationHistoryObjectServeRequest,
    FederationHistoryObjectServices, FederationSessionError,
    FilesystemFederationContentShardSource, FilesystemFederationContentSource,
    FilesystemFederationHistorySource, heal_federated_content_shard,
};
use meshspan_contracts::StoragePermitMacKey;
use meshspan_domain::{
    ContentManifestId, DurationMicros, EntropyError, MeshId, NodeId, OperationId, RandomSource,
    Revision, TargetId, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    CompletedStage, ContentChunkLimits, ContentKeyEnvelopeCipher, ContentPublicationError,
    ContentPublicationRequest, ContentReadRequest, DurableContentPublisher, DurableContentReader,
    NamespaceHistoryImmutableRecord, PublishedContentReference, UnprotectedContentAccess,
    UnprotectedContentPublisher, VersionPublicationStore, VolumeContentKeyring,
    VolumeKeyEncryptionKey,
};
use meshspan_protocol::v1::ProtocolVersion;
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder, StoragePermitVerifier,
    UsageLimit,
};
use meshspan_transport::{
    FederationExchangeContext, FederationReplayGuard, StreamKind, accept_stream,
};
use tempfile::tempdir;

use super::branch_page_proof::{BranchFixture, StaticBranchAuthority, publication};
use super::{NOW, SessionProof, replay_guard};

const STORAGE_PERMIT_KEY: [u8; 32] = [42; 32];
const SOURCE_VOLUME_KEY: [u8; 32] = [24; 32];
const TARGET_VOLUME_KEY: [u8; 32] = [25; 32];

pub(super) async fn prove_federated_content_layout(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
) -> Result<(), Box<dyn Error>> {
    let root = tempdir()?;
    let source_state = root.path().join("source-filesystem");
    let registration = registration(proof.server_mesh)?;
    let provider = provider(root.path(), "source", registration)?;
    let (content, provider) = publish_content(&source_state, provider, registration)?;
    publish_namespace(&source_state, content)?;

    let history = FilesystemFederationHistorySource::new(&source_state);
    let client_grants = StaticBranchAuthority::admit(fixture.authority.clone());
    let server_grants = StaticBranchAuthority::admit(fixture.authority.clone());
    let (export_token, manifest_object_digest) = advertised_manifest(
        proof,
        fixture,
        &history,
        &client_grants,
        &server_grants,
        content,
    )
    .await
    .map_err(|error| format!("manifest advertisement proof failed: {error}"))?;

    let source = FilesystemFederationContentSource::new(&source_state);
    let routes = StaticContentRoutes {
        node_id: NodeId::from_bytes([211; 16])?,
        target_id: registration.target_id,
        target_generation: registration.generation,
    };
    let source_keys = source_key_cipher()?;
    let target_keys = target_key_cipher()?;
    prove_advertised_content_layout(
        proof,
        fixture,
        &source,
        &routes,
        &client_grants,
        &server_grants,
        &source_keys,
        &target_keys,
        &source_state,
        provider,
        registration,
        root.path(),
        content,
        export_token,
        manifest_object_digest,
    )
    .await?;
    prove_unadvertised_manifest_fails_closed(
        proof,
        fixture,
        &source,
        &routes,
        &client_grants,
        &server_grants,
        &source_keys,
        &target_keys,
        content,
        manifest_object_digest,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn prove_advertised_content_layout(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
    source: &FilesystemFederationContentSource,
    routes: &StaticContentRoutes,
    client_grants: &StaticBranchAuthority,
    server_grants: &StaticBranchAuthority,
    source_keys: &ContentKeyEnvelopeCipher,
    target_keys: &ContentKeyEnvelopeCipher,
    source_state: &std::path::Path,
    provider: FolderShardStore,
    registration: FolderRegistration,
    root: &std::path::Path,
    content: PublishedContentReference,
    export_token: [u8; 32],
    manifest_object_digest: [u8; 32],
) -> Result<(), Box<dyn Error>> {
    let first = fetch_page(
        proof,
        fixture,
        source,
        routes,
        client_grants,
        server_grants,
        source_keys,
        target_keys,
        content,
        export_token,
        manifest_object_digest,
        Vec::new(),
        None,
        220,
    )
    .await
    .map_err(|error| format!("first content layout page failed: {error}"))?;
    assert_eq!(first.received.header.manifest, content.manifest);
    target_keys.unwrap(
        first.received.header.manifest.manifest_id,
        first.received.header.wrapped_key,
    )?;
    let first_page = first.received.page.as_ref().ok_or("missing first page")?;
    assert_eq!(chunk_indexes(first_page), vec![0, 1]);
    assert_eq!(first.served.chunk_count, 2);
    assert!(first.served.has_next_page);
    assert_eq!(first.received.routes.len(), 2);

    let second = fetch_page(
        proof,
        fixture,
        source,
        routes,
        client_grants,
        server_grants,
        source_keys,
        target_keys,
        content,
        export_token,
        manifest_object_digest,
        first.received.next_cursor.clone(),
        Some(first.received.header),
        226,
    )
    .await
    .map_err(|error| format!("continuation content layout page failed: {error}"))?;
    assert_eq!(second.received.header, first.received.header);
    let second_page = second.received.page.as_ref().ok_or("missing final page")?;
    assert_eq!(chunk_indexes(second_page), vec![2]);
    assert!(second.received.next_cursor.is_empty());
    assert!(!second.served.has_next_page);
    let shard_source = FilesystemFederationContentShardSource::new(
        source_state,
        provider,
        FederationContentShardProviderBinding {
            mesh_id: registration.mesh_id,
            provider_node_id: routes.node_id,
            target_id: registration.target_id,
            target_generation: registration.generation,
            maximum_shard_bytes: 1_024,
        },
        StoragePermitMacKey::from_bytes(STORAGE_PERMIT_KEY)?,
    )?;
    let shard_routes = shard_routes(&first.received, &second.received);
    prove_content_healing(
        proof,
        fixture,
        client_grants,
        server_grants,
        &shard_source,
        root,
        content,
        export_token,
        manifest_object_digest,
        first.received.header,
        &[first_page.clone(), second_page.clone()],
        &shard_routes,
    )
    .await?;
    prove_substituted_route_fails_closed(
        proof,
        fixture,
        client_grants,
        server_grants,
        &shard_source,
        content,
        export_token,
        manifest_object_digest,
        shard_routes[0],
    )
    .await?;
    Ok(())
}

fn chunk_indexes(page: &meshspan_filesystem::ContentLayoutTransferPage) -> Vec<u64> {
    page.chunks()
        .iter()
        .map(|chunk| chunk.chunk_index)
        .collect()
}

fn shard_routes(
    first: &meshspan_cluster::ReceivedFederationContentLayoutPage,
    second: &meshspan_cluster::ReceivedFederationContentLayoutPage,
) -> Vec<meshspan_cluster::FederationContentShardRoute> {
    first
        .routes
        .as_slice()
        .iter()
        .chain(second.routes.as_slice())
        .copied()
        .collect()
}

struct PageExchange {
    received: meshspan_cluster::ReceivedFederationContentLayoutPage,
    served: meshspan_cluster::ServedFederationContentLayoutPage,
}

struct StaticContentRoutes {
    node_id: NodeId,
    target_id: TargetId,
    target_generation: u64,
}

impl FederationContentRouteSource for StaticContentRoutes {
    fn provider_node(
        &self,
        target_id: TargetId,
        target_generation: u64,
    ) -> Result<Option<NodeId>, FederationContentLayoutSourceError> {
        Ok(
            (target_id == self.target_id && target_generation == self.target_generation)
                .then_some(self.node_id),
        )
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_page(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
    source: &FilesystemFederationContentSource,
    routes: &StaticContentRoutes,
    client_grants: &StaticBranchAuthority,
    server_grants: &StaticBranchAuthority,
    source_keys: &ContentKeyEnvelopeCipher,
    target_keys: &ContentKeyEnvelopeCipher,
    content: PublishedContentReference,
    export_token: [u8; 32],
    manifest_object_digest: [u8; 32],
    cursor: Vec<u8>,
    existing_header: Option<meshspan_filesystem::ContentLayoutTransferHeader>,
    seed: u8,
) -> Result<PageExchange, Box<dyn Error>> {
    let mut client_random = FixedRandom(seed.saturating_add(6));
    let mut server_random = FixedRandom(seed.saturating_add(7));
    let mut client_replay = FederationReplayGuard::new(256, DurationMicros::new(1_000_000))?;
    let mut server_replay = FederationReplayGuard::new(256, DurationMicros::new(1_000_000))?;
    let fetch = proof.client_runtime.fetch_content_layout_page(
        proof.client_connection,
        meshspan_cluster::FederationContentLayoutFetchServices::new(
            proof.client_authority,
            client_grants,
            target_keys,
            &mut client_random,
        ),
        layout_request(
            proof,
            fixture,
            content,
            export_token,
            manifest_object_digest,
            cursor,
            existing_header,
            seed,
        )?,
        &mut client_replay,
    );
    let serve = proof.server_runtime.serve_content_layout_page(
        proof.server_connection,
        FederationContentLayoutServices::new(
            proof.server_authority,
            server_grants,
            source,
            routes,
            source_keys,
            &mut server_random,
        ),
        FederationContentLayoutServeRequest {
            response_replay_nonce: [seed.saturating_add(5); 32],
            now: NOW,
        },
        &mut server_replay,
    );
    let (received, served) = tokio::try_join!(fetch, serve)?;
    Ok(PageExchange { received, served })
}

#[allow(clippy::too_many_arguments)]
fn layout_request(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
    content: PublishedContentReference,
    export_token: [u8; 32],
    manifest_object_digest: [u8; 32],
    cursor: Vec<u8>,
    existing_header: Option<meshspan_filesystem::ContentLayoutTransferHeader>,
    seed: u8,
) -> Result<FederationContentLayoutFetchRequest, Box<dyn Error>> {
    Ok(FederationContentLayoutFetchRequest {
        relationship_id: proof.relationship_id,
        grant_id: fixture.grant_id,
        resource: fixture.resource,
        manifest_id: content.manifest.manifest_id,
        export_token,
        manifest_object_digest,
        cursor,
        limit: 2,
        existing_header,
        context: exchange_context(seed)?,
        now: NOW,
    })
}

#[allow(clippy::too_many_arguments)]
async fn prove_unadvertised_manifest_fails_closed(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
    source: &FilesystemFederationContentSource,
    routes: &StaticContentRoutes,
    client_grants: &StaticBranchAuthority,
    server_grants: &StaticBranchAuthority,
    source_keys: &ContentKeyEnvelopeCipher,
    target_keys: &ContentKeyEnvelopeCipher,
    content: PublishedContentReference,
    manifest_object_digest: [u8; 32],
) -> Result<(), Box<dyn Error>> {
    let mut client_random = FixedRandom(248);
    let mut server_random = FixedRandom(249);
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let request = layout_request(
        proof,
        fixture,
        content,
        [247; 32],
        manifest_object_digest,
        Vec::new(),
        None,
        240,
    )?;
    let attempts = async {
        tokio::join!(
            proof.client_runtime.fetch_content_layout_page(
                proof.client_connection,
                meshspan_cluster::FederationContentLayoutFetchServices::new(
                    proof.client_authority,
                    client_grants,
                    target_keys,
                    &mut client_random,
                ),
                request,
                &mut client_replay,
            ),
            proof.server_runtime.serve_content_layout_page(
                proof.server_connection,
                FederationContentLayoutServices::new(
                    proof.server_authority,
                    server_grants,
                    source,
                    routes,
                    source_keys,
                    &mut server_random,
                ),
                FederationContentLayoutServeRequest {
                    response_replay_nonce: [245; 32],
                    now: NOW,
                },
                &mut server_replay,
            )
        )
    };
    let (fetch, serve) = tokio::time::timeout(Duration::from_secs(2), attempts).await?;
    assert!(fetch.is_err());
    assert!(matches!(
        serve,
        Err(FederationSessionError::ContentLayout(
            meshspan_cluster::FederationContentLayoutSourceError::InvalidQuery
        ))
    ));
    Ok(())
}

async fn advertised_manifest(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
    source: &FilesystemFederationHistorySource,
    client_grants: &StaticBranchAuthority,
    server_grants: &StaticBranchAuthority,
    content: PublishedContentReference,
) -> Result<([u8; 32], [u8; 32]), Box<dyn Error>> {
    let objects = ManifestObjectExchange {
        proof,
        fixture,
        source,
        client_grants,
        server_grants,
    };
    let mut client_replay = FederationReplayGuard::new(256, DurationMicros::new(1_000_000))?;
    let mut server_replay = FederationReplayGuard::new(256, DurationMicros::new(1_000_000))?;
    let mut cursor = Vec::new();
    let mut expected_export = None;
    let mut page_seed = 180_u8;
    let mut page_nonce = 1_u8;
    let mut object_seed = 20_u8;
    loop {
        let mut request = fixture.request(page_seed)?;
        request.context.replay_nonce = page_replay_nonce(180, page_nonce);
        request.requested_heads = vec![publication_for(content)?.namespace_commit_id];
        request.known_commits.clear();
        request.cursor.clone_from(&cursor);
        request.limit = 16;
        let fetch = proof.client_runtime.fetch_branch_page(
            proof.client_connection,
            proof.client_authority,
            client_grants,
            request,
            &mut client_replay,
        );
        let serve = proof.server_runtime.serve_branch_page(
            proof.server_connection,
            meshspan_cluster::FederationBranchPageServices::new(
                proof.server_authority,
                server_grants,
                source,
            ),
            meshspan_cluster::FederationBranchPageServeRequest {
                response_replay_nonce: page_replay_nonce(181, page_nonce),
                now: NOW,
            },
            &mut server_replay,
        );
        let (page, served) = tokio::join!(fetch, serve);
        let served =
            served.map_err(|error| format!("manifest branch service failed: {error:?}"))?;
        let page = page
            .map_err(|error| format!("manifest branch fetch failed after {served:?}: {error:?}"))?;
        let export_token = exact_digest(page.export_token())?;
        if expected_export
            .replace(export_token)
            .is_some_and(|prior| prior != export_token)
        {
            return Err("manifest export token changed between pages".into());
        }
        let terminal = page.next_cursor().is_empty();
        if terminal {
            for value in page.immutable_object_digests() {
                let object_digest = exact_digest(value)?;
                let record = objects
                    .fetch(
                        export_token,
                        object_digest,
                        object_seed,
                        &mut client_replay,
                        &mut server_replay,
                    )
                    .await?;
                if record.as_manifest()? == Some(content.manifest) {
                    return Ok((export_token, object_digest));
                }
                object_seed = object_seed
                    .checked_add(5)
                    .ok_or("manifest object seed overflow")?;
            }
        }
        if terminal {
            break;
        }
        cursor = page.next_cursor().to_vec();
        page_seed = page_seed
            .checked_add(1)
            .ok_or("manifest page seed overflow")?;
        page_nonce = page_nonce
            .checked_add(1)
            .ok_or("manifest page nonce overflow")?;
    }
    Err("authorised export omitted the committed content manifest".into())
}

struct ManifestObjectExchange<'a> {
    proof: &'a SessionProof<'a>,
    fixture: &'a BranchFixture,
    source: &'a FilesystemFederationHistorySource,
    client_grants: &'a StaticBranchAuthority,
    server_grants: &'a StaticBranchAuthority,
}

impl ManifestObjectExchange<'_> {
    async fn fetch(
        &self,
        export_token: [u8; 32],
        object_digest: [u8; 32],
        seed: u8,
        client_replay: &mut FederationReplayGuard,
        server_replay: &mut FederationReplayGuard,
    ) -> Result<NamespaceHistoryImmutableRecord, Box<dyn Error>> {
        let fetch = self.proof.client_runtime.fetch_history_object(
            self.proof.client_connection,
            self.proof.client_authority,
            self.client_grants,
            self.fixture
                .object_request(seed, export_token, object_digest)?,
            client_replay,
        );
        let response_nonce = seed.checked_add(4).ok_or("manifest object seed overflow")?;
        let serve = self.proof.server_runtime.serve_history_object(
            self.proof.server_connection,
            FederationHistoryObjectServices::new(
                self.proof.server_authority,
                self.server_grants,
                self.source,
            ),
            FederationHistoryObjectServeRequest {
                response_replay_nonce: [response_nonce; 32],
                now: NOW,
            },
            server_replay,
        );
        let (record, served) = tokio::join!(fetch, serve);
        let served = served.map_err(|error| {
            format!(
                "manifest object service failed for seed {seed}, digest {object_digest:?}: {error:?}"
            )
        })?;
        record.map_err(|error| {
            format!("manifest object fetch failed after {served:?}: {error:?}").into()
        })
    }
}

fn page_replay_nonce(domain: u8, sequence: u8) -> [u8; 32] {
    let mut nonce = [domain; 32];
    nonce[0] = sequence;
    nonce
}

#[allow(clippy::too_many_arguments)]
async fn prove_content_healing(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
    client_grants: &StaticBranchAuthority,
    server_grants: &StaticBranchAuthority,
    source: &FilesystemFederationContentShardSource<FolderShardStore>,
    root: &std::path::Path,
    content: PublishedContentReference,
    export_token: [u8; 32],
    manifest_object_digest: [u8; 32],
    header: meshspan_filesystem::ContentLayoutTransferHeader,
    pages: &[meshspan_filesystem::ContentLayoutTransferPage],
    routes: &[meshspan_cluster::FederationContentShardRoute],
) -> Result<(), Box<dyn Error>> {
    if routes.len() != 3 || pages.len() != 2 {
        return Err("incomplete recovery fixture".into());
    }
    let registration = target_registration(proof.client_mesh)?;
    let target_provider = provider(root, "target", registration)?;
    let fingerprint = target_provider.target_marker().fingerprint();
    let target_state = root.join("target-filesystem");
    let local_request = recovery_request(content, NOW)?;
    let mut receiver = open_receiver(&target_state, target_provider, registration, NOW, 170)?;
    receiver.begin_content_recovery(local_request, header)?;
    for page in pages {
        receiver.append_content_recovery_layout(local_request, header, page)?;
    }
    assert_eq!(
        receiver.seal_content_recovery_layout(local_request, header)?,
        content.manifest
    );
    prove_interrupted_transfer_can_retry(
        proof,
        fixture,
        client_grants,
        content,
        export_token,
        manifest_object_digest,
        routes[0],
    )
    .await?;
    heal_route(
        proof,
        fixture,
        client_grants,
        server_grants,
        source,
        &mut receiver,
        local_request,
        content,
        export_token,
        manifest_object_digest,
        routes[0],
        210,
    )
    .await?;
    assert!(matches!(
        receiver.finish_content_recovery(local_request),
        Err(ContentPublicationError::Unavailable)
    ));

    drop(receiver.into_provider());
    let resumed_at = UnixMicros::new(NOW.get() + 10);
    let resumed_request = ContentPublicationRequest {
        observed_at: resumed_at,
        ..local_request
    };
    let target_provider = reopen_provider(root, "target", registration, fingerprint, resumed_at)?;
    let mut receiver = open_receiver(
        &target_state,
        target_provider,
        registration,
        resumed_at,
        171,
    )?;
    receiver.begin_content_recovery(resumed_request, header)?;
    for page in pages {
        receiver.append_content_recovery_layout(resumed_request, header, page)?;
    }
    assert_eq!(
        receiver
            .pending_content_recovery(resumed_request, None, 10)?
            .chunks
            .len(),
        2
    );
    for (route, seed) in routes[1..].iter().copied().zip([220, 230]) {
        heal_route(
            proof,
            fixture,
            client_grants,
            server_grants,
            source,
            &mut receiver,
            resumed_request,
            content,
            export_token,
            manifest_object_digest,
            route,
            seed,
        )
        .await?;
    }
    assert_eq!(
        receiver.finish_content_recovery(resumed_request)?,
        content.manifest
    );
    assert_eq!(
        read_exact(&mut receiver, resumed_request, content)?,
        b"helloworld"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn prove_interrupted_transfer_can_retry(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
    client_grants: &StaticBranchAuthority,
    content: PublishedContentReference,
    export_token: [u8; 32],
    manifest_object_digest: [u8; 32],
    route: meshspan_cluster::FederationContentShardRoute,
) -> Result<(), Box<dyn Error>> {
    let request = content_shard_request(
        proof,
        fixture,
        content,
        export_token,
        manifest_object_digest,
        route,
        200,
    )?;
    let mut client_replay = replay_guard()?;
    let fetch = proof.client_runtime.fetch_content_shard(
        proof.client_connection,
        FederationContentShardFetchServices::new(proof.client_authority, client_grants),
        request,
        &mut client_replay,
    );
    let interrupt = async {
        let stream = accept_stream(proof.server_connection).await?;
        if stream.kind != StreamKind::Federation {
            return Err(FederationSessionError::WrongStream);
        }
        drop(stream);
        Ok(())
    };
    let (fetch, interrupted) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(fetch, interrupt)
    })
    .await?;
    interrupted?;
    assert!(fetch.is_err());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn heal_route(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
    client_grants: &StaticBranchAuthority,
    server_grants: &StaticBranchAuthority,
    source: &FilesystemFederationContentShardSource<FolderShardStore>,
    receiver: &mut UnprotectedContentPublisher<FolderShardStore, FixedRandom>,
    local_request: ContentPublicationRequest,
    content: PublishedContentReference,
    export_token: [u8; 32],
    manifest_object_digest: [u8; 32],
    route: meshspan_cluster::FederationContentShardRoute,
    seed: u8,
) -> Result<(), Box<dyn Error>> {
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let remote = content_shard_request(
        proof,
        fixture,
        content,
        export_token,
        manifest_object_digest,
        route,
        seed,
    )?;
    let heal = heal_federated_content_shard(
        proof.client_runtime,
        proof.client_connection,
        FederationContentShardFetchServices::new(proof.client_authority, client_grants),
        &mut client_replay,
        receiver,
        FederationContentHealingRequest {
            remote,
            local: local_request,
        },
    );
    let serve = proof.server_runtime.serve_content_shard(
        proof.server_connection,
        FederationContentShardServices::new(proof.server_authority, server_grants, source),
        FederationContentShardServeRequest {
            response_replay_nonce: [seed.saturating_add(5); 32],
            now: NOW,
        },
        &mut server_replay,
    );
    let (healed, served) = tokio::join!(heal, serve);
    let healed = healed?;
    let served = served?;
    assert_eq!(healed.chunk_index, route.shard.stripe_index);
    assert_eq!(healed.byte_count, usize::try_from(route.expected_length)?);
    assert_eq!(served.byte_count, healed.byte_count);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn content_shard_request(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
    content: PublishedContentReference,
    export_token: [u8; 32],
    manifest_object_digest: [u8; 32],
    route: meshspan_cluster::FederationContentShardRoute,
    seed: u8,
) -> Result<FederationContentShardFetchRequest, Box<dyn Error>> {
    Ok(FederationContentShardFetchRequest {
        relationship_id: proof.relationship_id,
        grant_id: fixture.grant_id,
        resource: fixture.resource,
        manifest_id: content.manifest.manifest_id,
        export_token,
        manifest_object_digest,
        provider_node_id: route.provider_node_id,
        target_id: route.target_id,
        target_generation: route.target_generation,
        shard: route.shard,
        expected_length: route.expected_length,
        expected_digest: route.expected_digest,
        maximum_shard_bytes: 1_024,
        context: exchange_context(seed)?,
        now: NOW,
    })
}

#[allow(clippy::too_many_arguments)]
async fn prove_substituted_route_fails_closed(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
    client_grants: &StaticBranchAuthority,
    server_grants: &StaticBranchAuthority,
    source: &FilesystemFederationContentShardSource<FolderShardStore>,
    content: PublishedContentReference,
    export_token: [u8; 32],
    manifest_object_digest: [u8; 32],
    mut route: meshspan_cluster::FederationContentShardRoute,
) -> Result<(), Box<dyn Error>> {
    route.provider_node_id = NodeId::from_bytes([212; 16])?;
    let request = content_shard_request(
        proof,
        fixture,
        content,
        export_token,
        manifest_object_digest,
        route,
        239,
    )?;
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let attempts = async {
        tokio::join!(
            proof.client_runtime.fetch_content_shard(
                proof.client_connection,
                FederationContentShardFetchServices::new(proof.client_authority, client_grants),
                request,
                &mut client_replay,
            ),
            proof.server_runtime.serve_content_shard(
                proof.server_connection,
                FederationContentShardServices::new(proof.server_authority, server_grants, source,),
                FederationContentShardServeRequest {
                    response_replay_nonce: [244; 32],
                    now: NOW,
                },
                &mut server_replay,
            )
        )
    };
    let (fetch, serve) = tokio::time::timeout(Duration::from_secs(2), attempts).await?;
    assert!(fetch.is_err());
    assert!(matches!(
        serve,
        Err(FederationSessionError::ContentShard(
            meshspan_cluster::FederationContentShardSourceError::InvalidQuery
        ))
    ));
    Ok(())
}

fn publish_content(
    state_directory: &std::path::Path,
    provider: FolderShardStore,
    registration: FolderRegistration,
) -> Result<(PublishedContentReference, FolderShardStore), Box<dyn Error>> {
    let request = content_request()?;
    let mut publisher = UnprotectedContentPublisher::open(
        state_directory,
        UnixMicros::new(1),
        provider,
        FixedRandom(7),
        source_keyring()?,
        ContentChunkLimits::new(4)?,
        UnprotectedContentAccess::new(
            registration.mesh_id,
            registration.target_id,
            registration.generation,
            StoragePermitMacKey::from_bytes(STORAGE_PERMIT_KEY)?,
        )?,
    )?;
    let mut sink = publisher.begin(request)?;
    sink.write_all(b"helloworld")?;
    let manifest = publisher.finish(
        request,
        sink,
        CompletedStage {
            logical_length: 10,
            content_digest: blake3::hash(b"helloworld").into(),
        },
    )?;
    let provider = publisher.into_provider();
    Ok((
        PublishedContentReference {
            publication_operation_id: request.operation_id,
            manifest,
        },
        provider,
    ))
}

fn publish_namespace(
    state_directory: &std::path::Path,
    content: PublishedContentReference,
) -> Result<(), Box<dyn Error>> {
    let mut store = VersionPublicationStore::open(state_directory, UnixMicros::new(1))?;
    store.publish_root_file(&publication_for(content)?)?;
    Ok(())
}

fn publication_for(
    content: PublishedContentReference,
) -> Result<meshspan_filesystem::RootFilePublication, Box<dyn Error>> {
    let mut value = publication()?;
    value.file.operation_id = content.publication_operation_id;
    value.file.manifest = content.manifest;
    Ok(value)
}

fn content_request() -> Result<ContentPublicationRequest, Box<dyn Error>> {
    Ok(ContentPublicationRequest {
        operation_id: OperationId::from_bytes([160; 16])?,
        volume_id: VolumeId::from_bytes([163; 16])?,
        request_digest: [161; 32],
        manifest_id: ContentManifestId::from_bytes([162; 16])?,
        format_version: 1,
        logical_length: 10,
        authorization_revision: Revision::new(9),
        deadline: UnixMicros::new(3_000_000),
        observed_at: UnixMicros::new(1_000_000),
    })
}

fn registration(mesh_id: MeshId) -> Result<FolderRegistration, Box<dyn Error>> {
    Ok(FolderRegistration {
        mesh_id,
        target_id: TargetId::from_bytes([164; 16])?,
        generation: 1,
        usage_limit: UsageLimit::DEFAULT,
    })
}

fn target_registration(mesh_id: MeshId) -> Result<FolderRegistration, Box<dyn Error>> {
    Ok(FolderRegistration {
        mesh_id,
        target_id: TargetId::from_bytes([174; 16])?,
        generation: 1,
        usage_limit: UsageLimit::DEFAULT,
    })
}

fn provider(
    root: &std::path::Path,
    label: &str,
    registration: FolderRegistration,
) -> Result<FolderShardStore, Box<dyn Error>> {
    let storage_directory = root.join(format!("{label}-storage"));
    let provider_state = root.join(format!("{label}-provider-state"));
    fs::create_dir(&storage_directory)?;
    let folder =
        RegisteredFolder::register_new(&storage_directory, registration, &mut FixedRandom(165))?;
    Ok(FolderShardStore::open(
        folder,
        &provider_state,
        CapacityPolicy {
            usage_limit: UsageLimit::DEFAULT,
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(
            registration.mesh_id,
            1,
            Revision::new(1),
            StoragePermitMacKey::from_bytes(STORAGE_PERMIT_KEY)?,
        )?,
        UnixMicros::new(1),
        &mut FixedRandom(166),
    )?)
}

fn reopen_provider(
    root: &std::path::Path,
    label: &str,
    registration: FolderRegistration,
    fingerprint: meshspan_storage::MarkerFingerprint,
    opened_at: UnixMicros,
) -> Result<FolderShardStore, Box<dyn Error>> {
    let storage_directory = root.join(format!("{label}-storage"));
    let provider_state = root.join(format!("{label}-provider-state"));
    let folder = RegisteredFolder::reopen(&storage_directory, registration, fingerprint)?;
    Ok(FolderShardStore::open(
        folder,
        &provider_state,
        CapacityPolicy {
            usage_limit: UsageLimit::DEFAULT,
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(
            registration.mesh_id,
            1,
            Revision::new(1),
            StoragePermitMacKey::from_bytes(STORAGE_PERMIT_KEY)?,
        )?,
        opened_at,
        &mut FixedRandom(176),
    )?)
}

fn open_receiver(
    state_directory: &std::path::Path,
    provider: FolderShardStore,
    registration: FolderRegistration,
    opened_at: UnixMicros,
    random_seed: u8,
) -> Result<UnprotectedContentPublisher<FolderShardStore, FixedRandom>, Box<dyn Error>> {
    Ok(UnprotectedContentPublisher::open(
        state_directory,
        opened_at,
        provider,
        FixedRandom(random_seed),
        target_keyring()?,
        ContentChunkLimits::new(4)?,
        UnprotectedContentAccess::new(
            registration.mesh_id,
            registration.target_id,
            registration.generation,
            StoragePermitMacKey::from_bytes(STORAGE_PERMIT_KEY)?,
        )?,
    )?)
}

fn recovery_request(
    content: PublishedContentReference,
    observed_at: UnixMicros,
) -> Result<ContentPublicationRequest, Box<dyn Error>> {
    Ok(ContentPublicationRequest {
        operation_id: OperationId::from_bytes([177; 16])?,
        volume_id: VolumeId::from_bytes([163; 16])?,
        request_digest: [178; 32],
        manifest_id: content.manifest.manifest_id,
        format_version: content.manifest.format_version,
        logical_length: content.manifest.logical_length,
        authorization_revision: Revision::new(10),
        deadline: UnixMicros::new(3_000_000),
        observed_at,
    })
}

fn read_exact(
    receiver: &mut UnprotectedContentPublisher<FolderShardStore, FixedRandom>,
    request: ContentPublicationRequest,
    content: PublishedContentReference,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    receiver.stream_range(
        ContentReadRequest {
            operation_id: OperationId::from_bytes([179; 16])?,
            content: PublishedContentReference {
                publication_operation_id: request.operation_id,
                ..content
            },
            offset: 0,
            length: content.manifest.logical_length,
            authorization_revision: request.authorization_revision,
            deadline: request.deadline,
            observed_at: request.observed_at,
        },
        &mut bytes,
    )?;
    Ok(bytes)
}

fn source_key_cipher() -> Result<ContentKeyEnvelopeCipher, Box<dyn Error>> {
    Ok(ContentKeyEnvelopeCipher::new(
        VolumeKeyEncryptionKey::from_bytes(1, SOURCE_VOLUME_KEY)?,
    ))
}

fn target_key_cipher() -> Result<ContentKeyEnvelopeCipher, Box<dyn Error>> {
    Ok(ContentKeyEnvelopeCipher::new(
        VolumeKeyEncryptionKey::from_bytes(2, TARGET_VOLUME_KEY)?,
    ))
}

fn source_keyring() -> Result<VolumeContentKeyring, Box<dyn Error>> {
    Ok(VolumeContentKeyring::new(
        VolumeId::from_bytes([163; 16])?,
        VolumeKeyEncryptionKey::from_bytes(1, SOURCE_VOLUME_KEY)?,
    ))
}

fn target_keyring() -> Result<VolumeContentKeyring, Box<dyn Error>> {
    Ok(VolumeContentKeyring::new(
        VolumeId::from_bytes([163; 16])?,
        VolumeKeyEncryptionKey::from_bytes(2, TARGET_VOLUME_KEY)?,
    ))
}

fn exchange_context(seed: u8) -> Result<FederationExchangeContext, Box<dyn Error>> {
    Ok(FederationExchangeContext::new(
        ProtocolVersion { major: 1, minor: 1 },
        [seed; 16],
        [seed.saturating_add(1); 16],
        [seed.saturating_add(2); 16],
        UnixMicros::new(2_000_000),
        [seed.saturating_add(3); 32],
    )?)
}

fn exact_digest(bytes: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    bytes.try_into().map_err(|_| "invalid digest".into())
}

struct FixedRandom(u8);

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(self.0);
        Ok(())
    }
}
