// SPDX-License-Identifier: GPL-2.0-only

//! Real-Quinn proof that bilateral grant admission precedes federated history lookup.

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use meshspan_cluster::{
    EffectiveFederationGrantAuthority, EffectiveFederationGrantAuthorityError,
    FederationBranchAuthoritySource, FederationBranchFetchRequest, FederationBranchPageFuture,
    FederationBranchPageQuery, FederationBranchPageRecords, FederationBranchPageServeRequest,
    FederationBranchPageServices, FederationBranchPageSource, FederationBranchPageSourceError,
    FederationHistoryObjectFetchRequest, FederationHistoryObjectServeRequest,
    FederationHistoryObjectServices, FederationSessionError, FilesystemFederationHistorySource,
};
use meshspan_domain::{
    BranchId, ContentManifestId, FederatedPrincipal, FederationAccess, FederationGrant,
    FederationGrantId, FederationPolicy, FederationPreset, FederationRelationshipId,
    FederationResourceScope, FileVersionId, NamespaceCommitId, NamespaceFederationPolicy, ObjectId,
    ObjectRevisionId, OperationId, PrincipalId, Revision, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    FilePublication, ManifestPublication, NamespaceHistoryCommitRecord, NamespaceLimits,
    NamespacePath, NamespacePublicationPath, RootFilePublication, VersionPublicationStore,
};
use meshspan_protocol::v1::{ProtocolVersion, VersionedPayload};
use meshspan_transport::FederationExchangeContext;
use tempfile::tempdir;

use super::content_layout_proof::prove_federated_content_layout;
use super::history_sync_proof::prove_restart_resumable_filesystem_sync;
use super::{NOW, SessionProof, replay_guard};

pub(super) async fn prove_branch_page_service(
    proof: &SessionProof<'_>,
) -> Result<(), Box<dyn Error>> {
    let fixture = BranchFixture::new(proof)?;
    prove_authorised_exchange(proof, &fixture).await?;
    prove_filesystem_backed_exchange(proof, &fixture).await?;
    prove_restart_resumable_filesystem_sync(proof, &fixture).await?;
    prove_federated_content_layout(proof, &fixture).await?;
    prove_denied_exchange_skips_source(proof, &fixture).await?;
    prove_excessive_source_page_fails_closed(proof, &fixture).await
}

async fn prove_filesystem_backed_exchange(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
) -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let publication = publication()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&publication)?;
    drop(store);
    let source = FilesystemFederationHistorySource::new(directory.path());
    let client_grants = StaticBranchAuthority::admit(fixture.authority);
    let server_grants = StaticBranchAuthority::admit(fixture.authority);
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let mut request = fixture.request(130)?;
    request.requested_heads = vec![publication.namespace_commit_id];
    request.known_commits.clear();
    request.cursor.clear();
    request.limit = 1;
    let fetch = proof.client_runtime.fetch_branch_page(
        proof.client_connection,
        proof.client_authority,
        &client_grants,
        request,
        &mut client_replay,
    );
    let serve = proof.server_runtime.serve_branch_page(
        proof.server_connection,
        FederationBranchPageServices::new(proof.server_authority, &server_grants, &source),
        FederationBranchPageServeRequest {
            response_replay_nonce: [135; 32],
            now: NOW,
        },
        &mut server_replay,
    );
    let (page, served) = tokio::try_join!(fetch, serve)?;
    assert_eq!(page.branch_commits().len(), 1);
    assert_eq!(page.export_token().len(), 32);
    assert!(page.immutable_object_digests().is_empty());
    assert!(!page.next_cursor().is_empty());
    NamespaceHistoryCommitRecord::from_canonical_bytes(
        page.branch_commits()[0].canonical_bytes.clone(),
    )?;
    assert_eq!(served.record_count, 1);
    assert!(served.has_next_page);

    let first_cursor = page.next_cursor().to_vec();
    let mut next_request = fixture.request(136)?;
    next_request.requested_heads = vec![publication.namespace_commit_id];
    next_request.known_commits.clear();
    next_request.cursor = first_cursor;
    next_request.limit = 1;
    let next_fetch = proof.client_runtime.fetch_branch_page(
        proof.client_connection,
        proof.client_authority,
        &client_grants,
        next_request,
        &mut client_replay,
    );
    let next_serve = proof.server_runtime.serve_branch_page(
        proof.server_connection,
        FederationBranchPageServices::new(proof.server_authority, &server_grants, &source),
        FederationBranchPageServeRequest {
            response_replay_nonce: [141; 32],
            now: NOW,
        },
        &mut server_replay,
    );
    let (next_page, _) = tokio::try_join!(next_fetch, next_serve)?;
    assert_eq!(next_page.immutable_object_digests().len(), 1);
    let export_token = exact_digest(next_page.export_token())?;
    let object_digest = exact_digest(&next_page.immutable_object_digests()[0])?;
    let object_fetch = proof.client_runtime.fetch_history_object(
        proof.client_connection,
        proof.client_authority,
        &client_grants,
        fixture.object_request(142, export_token, object_digest)?,
        &mut client_replay,
    );
    let object_serve = proof.server_runtime.serve_history_object(
        proof.server_connection,
        FederationHistoryObjectServices::new(proof.server_authority, &server_grants, &source),
        FederationHistoryObjectServeRequest {
            response_replay_nonce: [147; 32],
            now: NOW,
        },
        &mut server_replay,
    );
    let (object, object_served) = tokio::try_join!(object_fetch, object_serve)?;
    assert_eq!(object.digest(), object_digest);
    assert_eq!(object_served.byte_count, object.canonical_bytes().len());
    assert!(object_served.frame_count > 0);
    Ok(())
}

fn exact_digest(bytes: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    bytes.try_into().map_err(|_| "invalid digest".into())
}

async fn prove_authorised_exchange(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
) -> Result<(), Box<dyn Error>> {
    let source = RecordingHistorySource::new(fixture.authority, fixture.resource);
    let client_grants = StaticBranchAuthority::admit(fixture.authority);
    let server_grants = StaticBranchAuthority::admit(fixture.authority);
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let fetch = proof.client_runtime.fetch_branch_page(
        proof.client_connection,
        proof.client_authority,
        &client_grants,
        fixture.request(100)?,
        &mut client_replay,
    );
    let serve = proof.server_runtime.serve_branch_page(
        proof.server_connection,
        FederationBranchPageServices::new(proof.server_authority, &server_grants, &source),
        FederationBranchPageServeRequest {
            response_replay_nonce: [105; 32],
            now: NOW,
        },
        &mut server_replay,
    );
    let (page, served) = tokio::try_join!(fetch, serve)?;
    assert_eq!(page.grant_id(), fixture.grant_id.as_bytes());
    assert_eq!(page.branch_commits().len(), 1);
    assert_eq!(page.immutable_object_digests(), &[vec![9; 32]]);
    assert_eq!(page.next_cursor(), &[10; 16]);
    assert_eq!(served.relationship_id, proof.relationship_id);
    assert_eq!(served.grant_id, fixture.grant_id);
    assert_eq!(served.record_count, 2);
    assert!(served.has_next_page);
    assert_eq!(source.calls(), 1);
    Ok(())
}

async fn prove_denied_exchange_skips_source(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
) -> Result<(), Box<dyn Error>> {
    let source = RecordingHistorySource::new(fixture.authority, fixture.resource);
    let client_grants = StaticBranchAuthority::admit(fixture.authority);
    let server_grants = StaticBranchAuthority::deny();
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let request = fixture.request(110)?;
    let attempts = async {
        tokio::join!(
            proof.client_runtime.fetch_branch_page(
                proof.client_connection,
                proof.client_authority,
                &client_grants,
                request,
                &mut client_replay,
            ),
            proof.server_runtime.serve_branch_page(
                proof.server_connection,
                FederationBranchPageServices::new(proof.server_authority, &server_grants, &source,),
                FederationBranchPageServeRequest {
                    response_replay_nonce: [115; 32],
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
        Err(FederationSessionError::AuthorityUnavailable)
    ));
    assert_eq!(source.calls(), 0);
    Ok(())
}

async fn prove_excessive_source_page_fails_closed(
    proof: &SessionProof<'_>,
    fixture: &BranchFixture,
) -> Result<(), Box<dyn Error>> {
    let source = RecordingHistorySource::excessive(fixture.authority, fixture.resource);
    let client_grants = StaticBranchAuthority::admit(fixture.authority);
    let server_grants = StaticBranchAuthority::admit(fixture.authority);
    let mut client_replay = replay_guard()?;
    let mut server_replay = replay_guard()?;
    let request = fixture.request(120)?;
    let attempts = async {
        tokio::join!(
            proof.client_runtime.fetch_branch_page(
                proof.client_connection,
                proof.client_authority,
                &client_grants,
                request,
                &mut client_replay,
            ),
            proof.server_runtime.serve_branch_page(
                proof.server_connection,
                FederationBranchPageServices::new(proof.server_authority, &server_grants, &source,),
                FederationBranchPageServeRequest {
                    response_replay_nonce: [125; 32],
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
        Err(FederationSessionError::BranchPage(
            FederationBranchPageSourceError::Corrupt
        ))
    ));
    assert_eq!(source.calls(), 1);
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct BranchFixture {
    pub(super) authority: EffectiveFederationGrantAuthority,
    pub(super) grant_id: FederationGrantId,
    pub(super) resource: FederationResourceScope,
    pub(super) relationship_id: FederationRelationshipId,
}

impl BranchFixture {
    pub(super) fn new(proof: &SessionProof<'_>) -> Result<Self, Box<dyn Error>> {
        let grant_id = FederationGrantId::from_bytes([7; 16])?;
        let resource = FederationResourceScope::Volume {
            owner_mesh_id: proof.server_mesh,
            volume_id: VolumeId::from_bytes([8; 16])?,
        };
        let grant = FederationGrant::new(
            grant_id,
            proof.relationship_id,
            FederatedPrincipal::new(proof.client_mesh, PrincipalId::from_bytes([6; 16])?),
            resource,
            FederationPolicy::Namespace(NamespaceFederationPolicy::new(
                FederationAccess::from_preset(FederationPreset::View),
                None,
            )),
            1,
            UnixMicros::new(1),
            Some(UnixMicros::new(3_000_000)),
        )?;
        Ok(Self {
            authority: EffectiveFederationGrantAuthority {
                grant,
                local_authority_revision: Revision::new(3),
                local_grant_revision: Revision::new(4),
                remote_authority_revision: Revision::new(3),
                remote_grant_revision: Revision::new(4),
                remote_observed_at: NOW,
            },
            grant_id,
            resource,
            relationship_id: proof.relationship_id,
        })
    }

    pub(super) fn request(self, seed: u8) -> Result<FederationBranchFetchRequest, Box<dyn Error>> {
        Ok(FederationBranchFetchRequest {
            relationship_id: self.relationship_id,
            grant_id: self.grant_id,
            resource: self.resource,
            requested_heads: vec![NamespaceCommitId::from_bytes([11; 16])?],
            known_commits: vec![NamespaceCommitId::from_bytes([12; 16])?],
            cursor: vec![12; 16],
            limit: 2,
            context: FederationExchangeContext::new(
                ProtocolVersion { major: 1, minor: 1 },
                [seed; 16],
                [seed.saturating_add(1); 16],
                [seed.saturating_add(2); 16],
                UnixMicros::new(2_000_000),
                [seed.saturating_add(3); 32],
            )?,
            now: NOW,
        })
    }

    pub(super) fn object_request(
        self,
        seed: u8,
        export_token: [u8; 32],
        object_digest: [u8; 32],
    ) -> Result<FederationHistoryObjectFetchRequest, Box<dyn Error>> {
        Ok(FederationHistoryObjectFetchRequest {
            relationship_id: self.relationship_id,
            grant_id: self.grant_id,
            resource: self.resource,
            export_token,
            object_digest,
            context: FederationExchangeContext::new(
                ProtocolVersion { major: 1, minor: 1 },
                [seed; 16],
                [seed.saturating_add(1); 16],
                [seed.saturating_add(2); 16],
                UnixMicros::new(2_000_000),
                [seed.saturating_add(3); 32],
            )?,
            now: NOW,
        })
    }
}

pub(super) struct StaticBranchAuthority {
    authority: Option<EffectiveFederationGrantAuthority>,
}

impl StaticBranchAuthority {
    pub(super) const fn admit(authority: EffectiveFederationGrantAuthority) -> Self {
        Self {
            authority: Some(authority),
        }
    }

    const fn deny() -> Self {
        Self { authority: None }
    }
}

impl FederationBranchAuthoritySource for StaticBranchAuthority {
    fn effective_grant_authority(
        &self,
        relationship_id: FederationRelationshipId,
        grant_id: FederationGrantId,
        _now: UnixMicros,
    ) -> Result<Option<EffectiveFederationGrantAuthority>, EffectiveFederationGrantAuthorityError>
    {
        Ok(self.authority.filter(|authority| {
            authority.grant.relationship_id() == relationship_id
                && authority.grant.grant_id() == grant_id
        }))
    }
}

struct RecordingHistorySource {
    expected_authority: EffectiveFederationGrantAuthority,
    expected_resource: FederationResourceScope,
    excessive: bool,
    calls: AtomicUsize,
}

impl RecordingHistorySource {
    const fn new(
        expected_authority: EffectiveFederationGrantAuthority,
        expected_resource: FederationResourceScope,
    ) -> Self {
        Self {
            expected_authority,
            expected_resource,
            excessive: false,
            calls: AtomicUsize::new(0),
        }
    }

    const fn excessive(
        expected_authority: EffectiveFederationGrantAuthority,
        expected_resource: FederationResourceScope,
    ) -> Self {
        Self {
            expected_authority,
            expected_resource,
            excessive: true,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl FederationBranchPageSource for RecordingHistorySource {
    fn branch_page(&self, query: FederationBranchPageQuery) -> FederationBranchPageFuture<'_> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if query.authority != self.expected_authority
                || query.resource != self.expected_resource
                || query.requested_heads
                    != vec![
                        NamespaceCommitId::from_bytes([11; 16])
                            .map_err(|_| FederationBranchPageSourceError::InvalidQuery)?,
                    ]
                || query.known_commits
                    != vec![
                        NamespaceCommitId::from_bytes([12; 16])
                            .map_err(|_| FederationBranchPageSourceError::InvalidQuery)?,
                    ]
                || query.cursor != vec![12; 16]
                || query.limit != 2
                || query.now != NOW
            {
                return Err(FederationBranchPageSourceError::InvalidQuery);
            }
            let commit = VersionedPayload {
                format_version: 1,
                canonical_bytes: b"canonical-history-record".to_vec(),
            };
            Ok(FederationBranchPageRecords {
                export_token: [8; 32],
                branch_commits: if self.excessive {
                    vec![commit.clone(), commit]
                } else {
                    vec![commit]
                },
                immutable_object_digests: vec![[9; 32]],
                next_cursor: vec![10; 16],
            })
        })
    }
}

pub(super) fn publication() -> Result<RootFilePublication, Box<dyn Error>> {
    Ok(RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([140; 16])?,
            branch_id: BranchId::from_bytes([141; 16])?,
            volume_id: VolumeId::from_bytes([8; 16])?,
            object_id: ObjectId::from_bytes([142; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([143; 16])?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes([144; 16])?,
                format_version: 1,
                logical_length: 4,
                content_digest: [145; 32],
                root_digest: [146; 32],
            },
            created_by: PrincipalId::from_bytes([147; 16])?,
            created_at: UnixMicros::new(140),
        },
        root_object_id: ObjectId::from_bytes([148; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([149; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([150; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([151; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["report"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })
}
