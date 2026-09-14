// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId,
    OperationId, PartitionId, PrincipalId, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    FilePublication, ManifestPublication, NamespaceLimits, NamespacePath, NamespacePublicationPath,
    NamespacePublicationReceipt, RootFilePublication, VersionPublicationStore,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommitConvergedVolumeHead,
    ConvergedHeadEvidence, PartitionDatabase,
};

use super::{RunningAuthority, command_context};
use crate::ConsensusAuthenticationAuthority;
use crate::native_filesystem_runtime::publication::{
    commit_publication_head, confirm_or_commit_publication,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strong_publication_accepts_background_first_and_later_head_without_republishing()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RunningAuthority::start().await?;
    let volume = fixture.volume_lifecycle()?.record.volume_id;
    let reader = AuthoritativeRepository::new(PartitionDatabase::open(
        &fixture.directory.path().join("partition.sqlite3"),
        PartitionId::from_bytes([2; 16])?,
        UnixMicros::new(60),
    )?);
    let authority = ConsensusAuthenticationAuthority::new(
        reader,
        fixture.handle.clone(),
        tokio::runtime::Handle::current(),
    );
    let outcome = tokio::task::block_in_place(|| -> Result<(), Box<dyn std::error::Error>> {
        let publication = CommitConvergedVolumeHead {
            volume_id: volume,
            expected_namespace_commit_id: None,
            namespace_commit_id: NamespaceCommitId::from_bytes([80; 16])?,
            root_object_revision_id: ObjectRevisionId::from_bytes([81; 16])?,
            evidence: ConvergedHeadEvidence::Publication {
                operation_id: OperationId::from_bytes([82; 16])?,
                request_digest: [83; 32],
                result_digest: [84; 32],
            },
        };
        let background = command_context(fixture.administrator_id, 85, 86, 61, None)?;
        let foreground = command_context(fixture.administrator_id, 82, 87, 61, None)?;
        authority.commit_authoritative(
            background,
            &AuthoritativeCommand::CommitConvergedVolumeHead(publication),
        )?;
        let original = authority
            .reader()
            .converged_volume_head(volume)?
            .ok_or("head")?;
        assert_eq!(original.metadata_operation_id, background.operation_id);
        commit_publication_head(&authority, foreground, publication, None)?;
        assert_eq!(
            authority.reader().converged_volume_head(volume)?,
            Some(original)
        );
        let later = CommitConvergedVolumeHead {
            expected_namespace_commit_id: Some(publication.namespace_commit_id),
            namespace_commit_id: NamespaceCommitId::from_bytes([90; 16])?,
            root_object_revision_id: ObjectRevisionId::from_bytes([91; 16])?,
            evidence: ConvergedHeadEvidence::Publication {
                operation_id: OperationId::from_bytes([92; 16])?,
                request_digest: [93; 32],
                result_digest: [94; 32],
            },
            ..publication
        };
        commit_publication_head(
            &authority,
            command_context(fixture.administrator_id, 92, 95, 62, None)?,
            later,
            None,
        )?;
        let revision = authority.reader().current_revision()?;
        commit_publication_head(&authority, foreground, publication, None)?;
        assert_eq!(authority.reader().current_revision()?, revision);
        assert_eq!(
            authority
                .reader()
                .converged_volume_head(volume)?
                .ok_or("later head")?
                .namespace_commit_id,
            later.namespace_commit_id
        );
        let substituted = CommitConvergedVolumeHead {
            root_object_revision_id: ObjectRevisionId::from_bytes([96; 16])?,
            ..publication
        };
        assert!(matches!(
            commit_publication_head(&authority, foreground, substituted, Some(UnixMicros::new(0))),
            Err(crate::native_filesystem_runtime::NativeFilesystemRuntimeError::StrongBarrierPending)
        ));
        assert_eq!(authority.reader().current_revision()?, revision);
        Ok(())
    });
    fixture.shutdown().await?;
    outcome
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strong_replay_reopens_superseded_local_history_without_new_proposal()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RunningAuthority::start().await?;
    let volume = fixture.volume_lifecycle()?.record.volume_id;
    let outcome = tokio::task::block_in_place(|| strong_replay_scenario(&fixture, volume));
    fixture.shutdown().await?;
    outcome
}

fn strong_replay_scenario(
    fixture: &RunningAuthority,
    volume: VolumeId,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = reopened_authority(fixture)?;
    let state = fixture.directory.path().join("publication-state");
    let mut store = VersionPublicationStore::open(&state, UnixMicros::new(60))?;
    let first = initial_publication(volume, fixture.administrator_id)?;
    let first_receipt = store.publish_root_file(&first)?;
    confirm_or_commit_publication(&authority, &store, first_receipt, None)?;
    let second = following_publication(&first, 110)?;
    let second_receipt = store.publish_root_file(&second)?;
    confirm_or_commit_publication(&authority, &store, second_receipt, None)?;
    let third = following_publication(&second, 120)?;
    let unconfirmed = store.publish_root_file(&third)?;
    let fourth = following_publication(&third, 130)?;
    store.publish_root_file(&fourth)?;
    drop(store);
    drop(authority);

    let authority = reopened_authority(fixture)?;
    let store = VersionPublicationStore::open(&state, UnixMicros::new(200))?;
    let before = authority.reader().load_consensus_state(1)?;
    let revision = authority.reader().current_revision()?;
    let head = authority.reader().converged_volume_head(volume)?;
    // Expired wait budget cannot invalidate an exact, already committed strong outcome.
    confirm_or_commit_publication(&authority, &store, first_receipt, Some(UnixMicros::new(0)))?;
    assert_eq!(authority.reader().load_consensus_state(1)?, before);
    for invalid in [
        unconfirmed,
        NamespacePublicationReceipt {
            result_digest: [99; 32],
            ..first_receipt
        },
        NamespacePublicationReceipt {
            namespace_commit_id: second.namespace_commit_id,
            ..first_receipt
        },
    ] {
        assert!(matches!(
            confirm_or_commit_publication(&authority, &store, invalid, None),
            Err(
                crate::native_filesystem_runtime::NativeFilesystemRuntimeError::StrongBarrierFailed
            )
        ));
        assert_eq!(authority.reader().load_consensus_state(1)?, before);
    }
    assert_eq!(authority.reader().current_revision()?, revision);
    assert_eq!(authority.reader().converged_volume_head(volume)?, head);
    assert_eq!(
        head.ok_or("committed head")?.namespace_commit_id,
        second.namespace_commit_id
    );
    assert_eq!(
        store
            .namespace_head(first.file.branch_id, volume)?
            .ok_or("local head")?
            .namespace_commit_id,
        fourth.namespace_commit_id
    );
    Ok(())
}

fn reopened_authority(
    fixture: &RunningAuthority,
) -> Result<ConsensusAuthenticationAuthority, Box<dyn std::error::Error>> {
    Ok(ConsensusAuthenticationAuthority::new(
        AuthoritativeRepository::new(PartitionDatabase::open(
            &fixture.directory.path().join("partition.sqlite3"),
            PartitionId::from_bytes([2; 16])?,
            UnixMicros::new(200),
        )?),
        fixture.handle.clone(),
        tokio::runtime::Handle::current(),
    ))
}

fn initial_publication(
    volume_id: VolumeId,
    created_by: PrincipalId,
) -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    Ok(RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([100; 16])?,
            branch_id: BranchId::from_bytes([101; 16])?,
            volume_id,
            object_id: ObjectId::from_bytes([102; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([103; 16])?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes([104; 16])?,
                format_version: 1,
                logical_length: 0,
                content_digest: blake3::hash(&[]).into(),
                root_digest: [105; 32],
            },
            created_by,
            created_at: UnixMicros::new(100),
        },
        root_object_id: ObjectId::from_bytes([51; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([106; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([107; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([108; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["strong.bin"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })
}

fn following_publication(
    previous: &RootFilePublication,
    marker: u8,
) -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    let mut next = previous.clone();
    next.file.operation_id = OperationId::from_bytes([marker; 16])?;
    next.file.version_id = FileVersionId::from_bytes([marker + 1; 16])?;
    next.file.expected_current_version_id = Some(previous.file.version_id);
    next.file.parent_version_id = Some(previous.file.version_id);
    next.file.manifest.manifest_id = ContentManifestId::from_bytes([marker + 2; 16])?;
    next.file.created_at = UnixMicros::new(i64::from(marker));
    next.expected_namespace_commit_id = Some(previous.namespace_commit_id);
    next.expected_file_object_revision_id = Some(previous.file_object_revision_id);
    next.file_object_revision_id = ObjectRevisionId::from_bytes([marker + 3; 16])?;
    next.root_object_revision_id = ObjectRevisionId::from_bytes([marker + 4; 16])?;
    next.namespace_commit_id = NamespaceCommitId::from_bytes([marker + 5; 16])?;
    Ok(next)
}
