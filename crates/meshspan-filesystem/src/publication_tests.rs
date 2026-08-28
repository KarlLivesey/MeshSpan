// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, ObjectId, OperationId, PrincipalId, UnixMicros,
    VolumeId,
};
use tempfile::tempdir;

use super::{
    BranchFileHead, FilePublication, ManifestPublication, PublicationDisposition, PublicationError,
    PublicationFaultPoint, PublicationReceipt, VersionPublicationStore,
};

#[test]
fn exact_retry_and_restart_return_one_immutable_version() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let publication = make_publication(1, None, 2)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    let applied = store.publish(publication)?;
    assert_eq!(applied.disposition, PublicationDisposition::Applied);
    drop(store);

    let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(3))?;
    let replayed = reopened.publish(publication)?;
    assert_eq!(replayed.disposition, PublicationDisposition::Replayed);
    assert_eq!(applied.result_digest, replayed.result_digest);
    assert_eq!(
        reopened.file_head(publication.branch_id, publication.object_id)?,
        Some(BranchFileHead {
            branch_id: publication.branch_id,
            object_id: publication.object_id,
            volume_id: publication.volume_id,
            current_version_id: Some(publication.version_id),
            sequence: 1,
        })
    );
    let next = make_publication(3, Some(publication.version_id), 4)?;
    reopened.publish(next)?;
    assert_eq!(
        reopened.resolve(publication.operation_id)?,
        Some(PublicationReceipt {
            disposition: PublicationDisposition::Replayed,
            ..applied
        })
    );
    Ok(())
}

#[test]
fn stale_base_and_conflicting_replay_change_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = make_publication(4, None, 5)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish(first)?;
    let conflicting = FilePublication {
        version_id: FileVersionId::from_bytes([6; 16])?,
        ..first
    };
    assert!(matches!(
        store.publish(conflicting),
        Err(PublicationError::OperationConflict)
    ));
    let stale = make_publication(7, None, 8)?;
    assert!(matches!(
        store.publish(stale),
        Err(PublicationError::StaleHead)
    ));
    assert_eq!(
        store
            .file_head(first.branch_id, first.object_id)?
            .map(|head| head.current_version_id),
        Some(Some(first.version_id))
    );
    Ok(())
}

#[test]
fn every_transaction_fault_rolls_back_before_retry() -> Result<(), Box<dyn std::error::Error>> {
    for (index, fault) in [
        PublicationFaultPoint::Manifest,
        PublicationFaultPoint::Version,
        PublicationFaultPoint::Head,
        PublicationFaultPoint::Operation,
    ]
    .into_iter()
    .enumerate()
    {
        let directory = tempdir()?;
        let publication = make_publication(u8::try_from(index + 10)?, None, 20)?;
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        assert!(matches!(
            store.publish_inner(publication, Some(fault)),
            Err(PublicationError::InjectedFault)
        ));
        assert_eq!(store.resolve(publication.operation_id)?, None);
        assert_eq!(
            store.file_head(publication.branch_id, publication.object_id)?,
            None
        );
        drop(store);

        let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(2))?;
        assert_eq!(
            reopened.publish(publication)?.disposition,
            PublicationDisposition::Applied
        );
    }
    Ok(())
}

#[test]
fn corrupt_receipt_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let publication = make_publication(40, None, 41)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish(publication)?;
    store.connection.execute(
        "UPDATE publication_operations SET result_digest = zeroblob(32)
         WHERE operation_id = ?1",
        [publication.operation_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        store.resolve(publication.operation_id),
        Err(PublicationError::Corrupt)
    ));
    Ok(())
}

fn make_publication(
    operation: u8,
    parent: Option<FileVersionId>,
    version: u8,
) -> Result<FilePublication, Box<dyn std::error::Error>> {
    Ok(FilePublication {
        operation_id: OperationId::from_bytes([operation; 16])?,
        branch_id: BranchId::from_bytes([30; 16])?,
        volume_id: VolumeId::from_bytes([31; 16])?,
        object_id: ObjectId::from_bytes([32; 16])?,
        expected_current_version_id: parent,
        version_id: FileVersionId::from_bytes([version; 16])?,
        parent_version_id: parent,
        manifest: ManifestPublication {
            manifest_id: ContentManifestId::from_bytes([version.wrapping_add(1); 16])?,
            format_version: 1,
            logical_length: 7,
            content_digest: [version; 32],
            root_digest: [version.wrapping_add(2); 32],
        },
        created_by: PrincipalId::from_bytes([33; 16])?,
        created_at: UnixMicros::new(i64::from(operation)),
    })
}
