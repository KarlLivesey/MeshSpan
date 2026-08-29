// SPDX-License-Identifier: GPL-2.0-only

//! Real-Quinn proof that bilateral grant admission precedes federated history lookup.

use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use meshspan_cluster::{
    EffectiveFederationGrantAuthority, EffectiveFederationGrantAuthorityError,
    FederationBranchAuthoritySource, FederationBranchFetchRequest, FederationBranchPageQuery,
    FederationBranchPageRecords, FederationBranchPageServeRequest, FederationBranchPageServices,
    FederationBranchPageSource, FederationBranchPageSourceError, FederationSessionError,
};
use meshspan_domain::{
    FederatedPrincipal, FederationAccess, FederationGrant, FederationGrantId, FederationPolicy,
    FederationPreset, FederationRelationshipId, FederationResourceScope, NamespaceFederationPolicy,
    PrincipalId, Revision, UnixMicros, VolumeId,
};
use meshspan_protocol::v1::{ProtocolVersion, VersionedPayload};
use meshspan_transport::FederationExchangeContext;

use super::{NOW, SessionProof, replay_guard};

pub(super) async fn prove_branch_page_service(
    proof: &SessionProof<'_>,
) -> Result<(), Box<dyn Error>> {
    let fixture = BranchFixture::new(proof)?;
    prove_authorised_exchange(proof, &fixture).await?;
    prove_denied_exchange_skips_source(proof, &fixture).await?;
    prove_excessive_source_page_fails_closed(proof, &fixture).await
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
struct BranchFixture {
    authority: EffectiveFederationGrantAuthority,
    grant_id: FederationGrantId,
    resource: FederationResourceScope,
    relationship_id: FederationRelationshipId,
}

impl BranchFixture {
    fn new(proof: &SessionProof<'_>) -> Result<Self, Box<dyn Error>> {
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

    fn request(self, seed: u8) -> Result<FederationBranchFetchRequest, FederationSessionError> {
        Ok(FederationBranchFetchRequest {
            relationship_id: self.relationship_id,
            grant_id: self.grant_id,
            resource: self.resource,
            causal_frontier: vec![[11; 32]],
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
}

struct StaticBranchAuthority {
    authority: Option<EffectiveFederationGrantAuthority>,
}

impl StaticBranchAuthority {
    const fn admit(authority: EffectiveFederationGrantAuthority) -> Self {
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
    fn branch_page(
        &self,
        query: FederationBranchPageQuery,
    ) -> Result<FederationBranchPageRecords, FederationBranchPageSourceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if query.authority != self.expected_authority
            || query.resource != self.expected_resource
            || query.causal_frontier != vec![[11; 32]]
            || query.cursor != vec![12; 16]
            || query.limit != 2
        {
            return Err(FederationBranchPageSourceError::InvalidQuery);
        }
        let commit = VersionedPayload {
            format_version: 1,
            canonical_bytes: b"canonical-history-record".to_vec(),
        };
        Ok(FederationBranchPageRecords {
            branch_commits: if self.excessive {
                vec![commit.clone(), commit]
            } else {
                vec![commit]
            },
            immutable_object_digests: vec![[9; 32]],
            next_cursor: vec![10; 16],
        })
    }
}
