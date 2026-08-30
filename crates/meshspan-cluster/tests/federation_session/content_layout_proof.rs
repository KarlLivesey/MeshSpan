// SPDX-License-Identifier: GPL-2.0-only

//! Real-Quinn proof for export-bound, connection-keyed portable encrypted-content layouts.

use std::error::Error;
use std::fs;
use std::io::Write;
use std::time::Duration;

use meshspan_cluster::{
    FederationContentLayoutFetchRequest, FederationContentLayoutServeRequest,
    FederationContentLayoutServices, FederationHistoryObjectServeRequest,
    FederationHistoryObjectServices, FederationSessionError, FilesystemFederationContentSource,
    FilesystemFederationHistorySource,
};
use meshspan_contracts::StoragePermitMacKey;
use meshspan_domain::{
    ContentManifestId, DurationMicros, EntropyError, MeshId, OperationId, RandomSource, Revision,
    TargetId, UnixMicros,
};
use meshspan_filesystem::{
    CompletedStage, ContentChunkLimits, ContentKeyEnvelopeCipher, ContentPublicationRequest,
    DurableContentPublisher, NamespaceHistoryImmutableRecord, PublishedContentReference,
    UnprotectedContentAccess, UnprotectedContentPublisher, VersionPublicationStore,
    VolumeKeyEncryptionKey,
};
use meshspan_protocol::v1::ProtocolVersion;
use meshspan_storage::{
    CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder, StoragePermitVerifier,
    UsageLimit,
};
use meshspan_transport::{FederationExchangeContext, FederationReplayGuard};
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
    let provider = provider(root.path(), registration)?;
    let content = publish_content(&source_state, provider, registration)?;
    publish_namespace(&source_state, content)?;

    let history = FilesystemFederationHistorySource::new(&source_state);
    let client_grants = StaticBranchAuthority::admit(fixture.authority);
    let server_grants = StaticBranchAuthority::admit(fixture.authority);
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
    let source_keys = source_key_cipher()?;
    let target_keys = target_key_cipher()?;
    let first = fetch_page(
        proof,
        fixture,
        &source,
        &client_grants,
        &server_grants,
        &source_keys,
        &target_keys,
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
    assert_eq!(
        first_page
            .chunks()
            .iter()
            .map(|chunk| chunk.chunk_index)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(first.served.chunk_count, 2);
    assert!(first.served.has_next_page);

    let second = fetch_page(
        proof,
        fixture,
        &source,
        &client_grants,
        &server_grants,
        &source_keys,
        &target_keys,
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
    assert_eq!(
        second_page
            .chunks()
            .iter()
            .map(|chunk| chunk.chunk_index)
            .collect::<Vec<_>>(),
        vec![2]
    );
    assert!(second.received.next_cursor.is_empty());
    assert!(!second.served.has_next_page);
    prove_unadvertised_manifest_fails_closed(
        proof,
        fixture,
        &source,
        &client_grants,
        &server_grants,
        &source_keys,
        &target_keys,
        content,
        manifest_object_digest,
    )
    .await
}

struct PageExchange {
    received: meshspan_cluster::ReceivedFederationContentLayoutPage,
    served: meshspan_cluster::ServedFederationContentLayoutPage,
}

#[allow(clippy::too_many_arguments)]
async fn fetch_page(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
    source: &FilesystemFederationContentSource,
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

fn publish_content(
    state_directory: &std::path::Path,
    provider: FolderShardStore,
    registration: FolderRegistration,
) -> Result<PublishedContentReference, Box<dyn Error>> {
    let request = content_request()?;
    let mut publisher = UnprotectedContentPublisher::open(
        state_directory,
        UnixMicros::new(1),
        provider,
        FixedRandom(7),
        source_key_cipher()?,
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
    drop(publisher.into_provider());
    Ok(PublishedContentReference {
        publication_operation_id: request.operation_id,
        manifest,
    })
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

fn provider(
    root: &std::path::Path,
    registration: FolderRegistration,
) -> Result<FolderShardStore, Box<dyn Error>> {
    let storage_directory = root.join("source-storage");
    let provider_state = root.join("source-provider-state");
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
