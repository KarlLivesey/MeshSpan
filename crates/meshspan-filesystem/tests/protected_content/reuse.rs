// SPDX-License-Identifier: GPL-2.0-only

//! Independent uploads retain their file identities but share compatible encrypted bytes.

use super::*;
use meshspan_contracts::StorageUsageSource;
use meshspan_domain::{
    BranchId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId, PrincipalId, StageId,
};
use meshspan_filesystem::{
    FilesystemCommitService, NamespaceLimits, NamespacePath, NamespacePublicationPath,
    PublicationDisposition, RootFileCommitRequest, StageCompletionRequest, StageRegistration,
    StageWrite, VersionPublicationStore,
};

#[test]
fn independent_uploads_reuse_real_shards_and_read_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let mesh = MeshId::from_bytes([1; 16])?;
    let volume = VolumeId::from_bytes([2; 16])?;
    let fixture = protection_fixture(root.path(), mesh)?;
    let state = root.path().join("filesystem");
    let publisher = protected_publisher(
        &state,
        fixture.router.clone(),
        volume,
        fixture.protection.clone(),
        mesh,
        8,
    )?;
    let mut service = FilesystemCommitService::open(&state, UnixMicros::new(1), publisher)?;
    let bytes = fixture_bytes();
    let first = staged_upload(&mut service, volume, 20, "first.txt", None, &bytes)?;
    service
        .commit_root_file(&first)
        .map_err(|error| format!("first upload: {error:?}"))?;
    let original_usage = physical_payload(&fixture.router)?;
    assert!(original_usage > 0);
    let second = staged_upload(
        &mut service,
        volume,
        40,
        "second.txt",
        Some(first.namespace_commit_id),
        &bytes,
    )?;
    service
        .commit_root_file(&second)
        .map_err(|error| format!("duplicate upload: {error:?}"))?;
    assert_eq!(
        physical_payload(&fixture.router)?,
        original_usage,
        "duplicate upload wrote more shards"
    );
    drop(service);

    let publications = VersionPublicationStore::open(&state, UnixMicros::new(30))?;
    let first_content = publications
        .published_content_for_version(first.version_id)?
        .ok_or("first version missing")?;
    let second_content = publications
        .published_content_for_version(second.version_id)?
        .ok_or("second version missing")?;
    assert_eq!(first_content.manifest, second_content.manifest);
    assert_ne!(
        first_content.publication_operation_id,
        second_content.publication_operation_id
    );
    let connection = rusqlite::Connection::open(state.join("filesystem-branch.sqlite3"))?;
    let (files, owners, logical): (i64, i64, i64) = connection.query_row(
        "SELECT COUNT(DISTINCT object_id), COUNT(DISTINCT created_by), SUM(logical_length) FROM file_versions",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!((files, owners, logical), (2, 2, 600_000));
    drop(connection);
    drop(publications);
    let mut publisher = protected_publisher(
        &state,
        fixture.router.clone(),
        volume,
        fixture.protection,
        mesh,
        8,
    )?;
    assert_exact_read(&mut publisher, first_content, &bytes, 70)
        .map_err(|error| format!("original read: {error}"))?;
    assert_exact_read(&mut publisher, second_content, &bytes, 71)
        .map_err(|error| format!("reused read: {error}"))?;
    assert_eq!(
        publisher.resolve(second.content_publication_request())?,
        Some(first_content.manifest)
    );
    let evidence = publisher.acknowledgement_evidence(second.content_publication_request())?;
    assert!(evidence.required_shard_receipts > 0);
    assert_eq!(evidence.pending_eventual_shards, 0);
    let mut service = FilesystemCommitService::open(&state, UnixMicros::new(30), publisher)?;
    assert_eq!(
        service.commit_root_file(&second)?.disposition,
        PublicationDisposition::Replayed
    );
    assert_eq!(physical_payload(&fixture.router)?, original_usage);
    Ok(())
}

fn physical_payload(router: &TestRouter) -> Result<u64, ContractError> {
    router
        .lock()?
        .providers
        .values()
        .try_fold(0_u64, |total, provider| {
            total
                .checked_add(provider.observe_usage()?.committed_bytes)
                .ok_or(ContractError::Corrupt)
        })
}

#[test]
fn reuse_rechecks_availability_volume_and_complete_upload_after_catalogue_upgrade()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let mesh = MeshId::from_bytes([1; 16])?;
    let volume = VolumeId::from_bytes([2; 16])?;
    let fixture = protection_fixture(root.path(), mesh)?;
    let state = root.path().join("filesystem");
    let mut publisher = protected_publisher(
        &state,
        fixture.router.clone(),
        volume,
        fixture.protection.clone(),
        mesh,
        8,
    )?;
    let bytes = fixture_bytes();
    let source = publish(&mut publisher, publication_request(volume, 80)?, &bytes)?;
    let original_usage = physical_payload(&fixture.router)?;
    drop(publisher);
    // Recreate schema 11 with its committed content intact. Later tables are empty;
    // remove their objects and the newer physical-generation column together.
    let database = rusqlite::Connection::open(state.join("filesystem-content.sqlite3"))?;
    let later_rows: i64 = database.query_row(
        "SELECT (SELECT COUNT(*) FROM content_reuse) +
                (SELECT COUNT(*) FROM content_repair_projection_cursors)",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(later_rows, 0);
    database.execute_batch(
        "BEGIN IMMEDIATE;
        DROP TABLE content_repair_projection_cursors;
        DROP INDEX content_publications_repair_projection;
        DROP TABLE content_reuse;
        ALTER TABLE content_shard_repair_effects DROP COLUMN replacement_shard_generation;
        DELETE FROM schema_migrations WHERE version >= 12;
        PRAGMA user_version = 11;
        COMMIT;",
    )?;
    drop(database);
    let mut publisher = protected_publisher(
        &state,
        fixture.router.clone(),
        volume,
        fixture.protection,
        mesh,
        8,
    )?;
    assert_exact_read(&mut publisher, source, &bytes, 81)?;
    let request = publication_request(volume, 90)?;
    let completed = CompletedStage {
        logical_length: 300_000,
        content_digest: *blake3::hash(&bytes).as_bytes(),
    };
    let wrong_volume = ContentPublicationRequest {
        volume_id: VolumeId::from_bytes([3; 16])?,
        ..request
    };
    assert!(
        publisher
            .verify_reuse(wrong_volume, source.manifest, completed)?
            .is_none()
    );
    fixture.control.set_offline(fixture.required_targets[0])?;
    assert!(
        publisher
            .verify_reuse(request, source.manifest, completed)?
            .is_none()
    );
    fixture.control.set_all_online()?;
    let reuse = publisher
        .verify_reuse(request, source.manifest, completed)?
        .ok_or("compatible source not found")?;
    let mut sink = publisher.begin(request)?;
    let mut wrong_bytes = bytes.clone();
    wrong_bytes[123] ^= 1;
    sink.write_all(&wrong_bytes)?;
    assert!(matches!(
        publisher.finish_reuse(request, sink, reuse),
        Err(meshspan_filesystem::ContentPublicationError::Corrupt)
    ));
    assert_eq!(publisher.resolve(request)?, None);
    assert_eq!(physical_payload(&fixture.router)?, original_usage);
    Ok(())
}

fn staged_upload(
    service: &mut FilesystemCommitService<TestProtectedPublisher>,
    volume: VolumeId,
    seed: u8,
    name: &str,
    prior: Option<NamespaceCommitId>,
    bytes: &[u8],
) -> Result<RootFileCommitRequest, Box<dyn std::error::Error>> {
    let stage = StageId::from_bytes([seed; 16])?;
    let length = u64::try_from(bytes.len())?;
    service.stages_mut().register(StageRegistration {
        stage_id: stage,
        stage_fence: 1,
        maximum_bytes: length,
        created_at: UnixMicros::new(1),
        expires_at: UnixMicros::new(1_000),
    })?;
    service.stages_mut().write(
        stage,
        &StageWrite {
            operation_id: OperationId::from_bytes([seed + 1; 16])?,
            stage_fence: 1,
            offset: 0,
            digest: *blake3::hash(bytes).as_bytes(),
            bytes: BoundedBytes::copy_from(bytes, bytes.len())?,
        },
        UnixMicros::new(2),
    )?;
    Ok(RootFileCommitRequest {
        completion: StageCompletionRequest {
            operation_id: OperationId::from_bytes([seed + 2; 16])?,
            stage_id: stage,
            stage_fence: 1,
            expected_sequence: 1,
            final_length: length,
            sparse: false,
            observed_at: UnixMicros::new(10),
        },
        branch_id: BranchId::from_bytes([3; 16])?,
        volume_id: volume,
        object_id: ObjectId::from_bytes([seed + 3; 16])?,
        expected_current_version_id: None,
        version_id: FileVersionId::from_bytes([seed + 4; 16])?,
        retain_superseded_history: true,
        retention_policy_sequence: 1,
        manifest_id: ContentManifestId::from_bytes([seed + 5; 16])?,
        manifest_format_version: 2,
        content_authorization_revision: Revision::new(1),
        content_deadline: UnixMicros::new(1_000),
        root_object_id: ObjectId::from_bytes([4; 16])?,
        expected_namespace_commit_id: prior,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([seed + 6; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([seed + 7; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([seed + 8; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components([name], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
        created_by: PrincipalId::from_bytes([seed + 9; 16])?,
        created_at: UnixMicros::new(10),
    })
}
