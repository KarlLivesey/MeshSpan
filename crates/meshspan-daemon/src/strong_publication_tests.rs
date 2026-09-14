// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{NamespaceCommitId, ObjectRevisionId, OperationId, PartitionId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommitConvergedVolumeHead,
    ConvergedHeadEvidence, PartitionDatabase,
};

use super::{RunningAuthority, command_context};
use crate::ConsensusAuthenticationAuthority;
use crate::native_filesystem_runtime::publication::commit_publication_head;

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
        commit_publication_head(&authority, foreground, publication)?;
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
        )?;
        let revision = authority.reader().current_revision()?;
        commit_publication_head(&authority, foreground, publication)?;
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
            commit_publication_head(&authority, foreground, substituted),
            Err(crate::native_filesystem_runtime::NativeFilesystemRuntimeError::StrongBarrierPending)
        ));
        assert_eq!(authority.reader().current_revision()?, revision);
        Ok(())
    });
    fixture.shutdown().await?;
    outcome
}
