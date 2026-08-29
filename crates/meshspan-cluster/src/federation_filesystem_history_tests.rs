// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BranchId, ContentManifestId, FederatedPrincipal, FederationAccess, FederationGrant,
    FederationGrantId, FederationPolicy, FederationPreset, FederationRelationshipId,
    FederationResourceScope, FileVersionId, MeshId, NamespaceCommitId, NamespaceFederationPolicy,
    ObjectId, ObjectRevisionId, OperationId, PrincipalId, Revision, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    FilePublication, ManifestPublication, NamespaceHistoryCommitRecord,
    NamespaceHistoryImmutableRecord, NamespaceLimits, NamespacePath, NamespacePublicationPath,
    RootFilePublication, VersionPublicationStore,
};
use tempfile::tempdir;

use super::FilesystemFederationHistorySource;
use crate::{
    EffectiveFederationGrantAuthority, FederationBranchPageQuery, FederationBranchPageSource,
    FederationBranchPageSourceError, FederationHistoryObjectQuery, FederationHistoryObjectSource,
};

#[tokio::test(flavor = "multi_thread")]
async fn real_store_pages_after_restart_and_fences_changed_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let publication = publication()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&publication)?;
    drop(store);

    let authority = test_authority(publication.file.volume_id, Revision::new(4))?;
    let source = FilesystemFederationHistorySource::new(directory.path());
    let first = source
        .branch_page(query(&publication, authority, Vec::new()))
        .await?;
    assert_eq!(first.branch_commits.len(), 1);
    assert!(first.immutable_object_digests.is_empty());
    assert!(!first.next_cursor.is_empty());
    NamespaceHistoryCommitRecord::from_canonical_bytes(
        first.branch_commits[0].canonical_bytes.clone(),
    )?;

    let restarted = FilesystemFederationHistorySource::new(directory.path());
    let refreshed = EffectiveFederationGrantAuthority {
        remote_observed_at: UnixMicros::new(99),
        ..authority
    };
    let second = restarted
        .branch_page(query(&publication, refreshed, first.next_cursor.clone()))
        .await?;
    assert!(second.branch_commits.is_empty());
    assert_eq!(second.immutable_object_digests.len(), 1);
    let digest = second.immutable_object_digests[0];
    let object = restarted
        .history_object(FederationHistoryObjectQuery {
            authority: refreshed,
            resource: refreshed.grant.resource(),
            export_token: first.export_token,
            object_digest: digest,
            now: UnixMicros::new(100),
        })
        .await?;
    NamespaceHistoryImmutableRecord::from_expected_digest(digest, object.canonical_bytes)?;

    let changed = test_authority(publication.file.volume_id, Revision::new(5))?;
    assert_eq!(
        restarted
            .branch_page(query(&publication, changed, first.next_cursor))
            .await,
        Err(FederationBranchPageSourceError::InvalidQuery)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn narrower_scope_is_rejected_until_a_non_leaking_projection_exists()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let publication = publication()?;
    let authority = test_authority(publication.file.volume_id, Revision::new(4))?;
    let resource = FederationResourceScope::File {
        owner_mesh_id: MeshId::from_bytes([1; 16])?,
        volume_id: publication.file.volume_id,
        object_id: publication.file.object_id,
    };
    let grant = FederationGrant::new(
        authority.grant.grant_id(),
        authority.grant.relationship_id(),
        authority.grant.subject(),
        resource,
        authority.grant.policy(),
        authority.grant.authority_epoch(),
        authority.grant.valid_from(),
        authority.grant.valid_until(),
    )?;
    let source = FilesystemFederationHistorySource::new(directory.path());
    assert_eq!(
        source
            .branch_page(FederationBranchPageQuery {
                authority: EffectiveFederationGrantAuthority { grant, ..authority },
                resource,
                requested_heads: vec![publication.namespace_commit_id],
                known_commits: Vec::new(),
                cursor: Vec::new(),
                limit: 1,
                now: UnixMicros::new(100),
            })
            .await,
        Err(FederationBranchPageSourceError::Unavailable)
    );
    Ok(())
}

fn query(
    publication: &RootFilePublication,
    authority: EffectiveFederationGrantAuthority,
    cursor: Vec<u8>,
) -> FederationBranchPageQuery {
    FederationBranchPageQuery {
        authority,
        resource: authority.grant.resource(),
        requested_heads: vec![publication.namespace_commit_id],
        known_commits: Vec::new(),
        cursor,
        limit: 1,
        now: UnixMicros::new(100),
    }
}

fn test_authority(
    volume_id: VolumeId,
    local_grant_revision: Revision,
) -> Result<EffectiveFederationGrantAuthority, Box<dyn std::error::Error>> {
    let relationship_id = FederationRelationshipId::from_bytes([2; 16])?;
    let resource = FederationResourceScope::Volume {
        owner_mesh_id: MeshId::from_bytes([1; 16])?,
        volume_id,
    };
    let grant = FederationGrant::new(
        FederationGrantId::from_bytes([3; 16])?,
        relationship_id,
        FederatedPrincipal::new(
            MeshId::from_bytes([4; 16])?,
            PrincipalId::from_bytes([5; 16])?,
        ),
        resource,
        FederationPolicy::Namespace(NamespaceFederationPolicy::new(
            FederationAccess::from_preset(FederationPreset::View),
            None,
        )),
        1,
        UnixMicros::new(1),
        Some(UnixMicros::new(10_000_000_000)),
    )?;
    Ok(EffectiveFederationGrantAuthority {
        grant,
        local_authority_revision: Revision::new(3),
        local_grant_revision,
        remote_authority_revision: Revision::new(3),
        remote_grant_revision: Revision::new(4),
        remote_observed_at: UnixMicros::new(90),
    })
}

fn publication() -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    Ok(RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([20; 16])?,
            branch_id: BranchId::from_bytes([21; 16])?,
            volume_id: VolumeId::from_bytes([22; 16])?,
            object_id: ObjectId::from_bytes([23; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([24; 16])?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes([25; 16])?,
                format_version: 1,
                logical_length: 4,
                content_digest: [26; 32],
                root_digest: [27; 32],
            },
            created_by: PrincipalId::from_bytes([28; 16])?,
            created_at: UnixMicros::new(20),
        },
        root_object_id: ObjectId::from_bytes([29; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([30; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([31; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([32; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["report"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })
}
