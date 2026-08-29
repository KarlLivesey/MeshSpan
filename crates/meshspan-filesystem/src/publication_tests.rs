// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BranchId, ContentManifestId, DurationMicros, FileVersionId, HandleId, NamespaceCommitId,
    NodeId, ObjectId, ObjectRevisionId, OperationId, PrincipalId, Revision, SnapshotId, UnixMicros,
    VolumeId,
};
use rusqlite::{Connection, TransactionBehavior, params};
use tempfile::tempdir;

use super::{
    DATABASE_FILE, DirectoryPublication, DirectoryRevisionTransition, FilePublication, MIGRATIONS,
    ManifestPublication, NamespacePublicationPath, NamespacePublicationReceipt,
    NamespaceReconciliationApplication, PublicationDisposition, PublicationError,
    PublicationPathError, RootFilePublication, SCHEMA_VERSION, SnapshotRestorePublication,
    VersionPublicationStore, configure,
};
use crate::{
    BranchMutation, BranchMutationIntent, BranchRenameIntent, CreateDisposition, DirectoryEntry,
    DirectoryEntryKind, DirectoryNodeRecord, DirectoryTrie, DirectoryTrieError, HandleAccess,
    HandleError, HandleShare, NamespaceComponent, NamespaceLimits, NamespacePath,
    NamespaceRenamePublication, NamespaceRenameReceipt, NamespaceReplayDisposition,
    OpenHandleRequest, ReachabilityRoot, ReachabilityRootPage, ReachabilityRootSource,
    ReconciliationFrontier, ReconciliationLimits, VersionCleanupCancellationAuthority,
    VersionCleanupCancellationError, VersionCleanupRetirementAuthority,
    VersionCleanupRetirementError, VersionReachabilityError, VersionReachabilityScanRequest,
    VersionReachabilityState, VersionReclaimMode, VersionRetentionCandidate,
    VersionRetentionCandidateReason, VersionRetentionError, VersionRetentionPageLimit,
    VersionRetentionPressure, VersionRetentionSelectionPolicy, reachability_root_digest,
    reachability_root_set_digest, reachability_subject_digest,
};

#[test]
fn publication_path_requires_every_ancestor_and_new_revision()
-> Result<(), Box<dyn std::error::Error>> {
    let path = NamespacePath::from_components(["a", "b", "file"], NamespaceLimits::PORTABLE)?;
    let first = DirectoryRevisionTransition::new(
        ObjectId::from_bytes([40; 16])?,
        ObjectRevisionId::from_bytes([41; 16])?,
        ObjectRevisionId::from_bytes([42; 16])?,
    )?;
    let second = DirectoryRevisionTransition::new(
        ObjectId::from_bytes([43; 16])?,
        ObjectRevisionId::from_bytes([44; 16])?,
        ObjectRevisionId::from_bytes([45; 16])?,
    )?;
    let selected = NamespacePublicationPath::new(path.clone(), vec![first, second])?;
    assert_eq!(selected.path(), &path);
    assert_eq!(selected.ancestors(), &[first, second]);
    assert_eq!(
        selected.leaf_name().map(NamespaceComponent::display),
        Some("file")
    );
    assert_eq!(
        NamespacePublicationPath::new(path, vec![first]),
        Err(PublicationPathError::TransitionCount)
    );
    assert_eq!(
        DirectoryRevisionTransition::new(
            ObjectId::from_bytes([46; 16])?,
            ObjectRevisionId::from_bytes([47; 16])?,
            ObjectRevisionId::from_bytes([47; 16])?,
        ),
        Err(PublicationPathError::ReusedRevision)
    );
    Ok(())
}

#[test]
fn directory_nodes_round_trip_after_restart_and_corruption_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut trie = DirectoryTrie::empty();
    let entry = DirectoryEntry::new(
        NamespaceComponent::new("persisted", NamespaceLimits::PORTABLE)?,
        ObjectId::from_bytes([50; 16])?,
        meshspan_domain::ObjectRevisionId::from_bytes([51; 16])?,
        DirectoryEntryKind::File,
        1,
    )?;
    let mutation = trie.upsert(entry, None)?;
    let records = mutation_records(&trie, &mutation.created_nodes)?;
    let selected = records.first().ok_or("missing node")?.clone();
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.persist_directory_nodes(&records, UnixMicros::new(2))?;
    store.persist_directory_nodes(&records, UnixMicros::new(3))?;
    drop(store);

    let reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(4))?;
    assert_eq!(
        reopened.directory_node(selected.digest())?,
        Some(selected.clone())
    );
    reopened.connection.execute(
        "UPDATE directory_nodes SET encoded_node = X'00' WHERE node_digest = ?1",
        [selected.digest().as_bytes().as_slice()],
    )?;
    assert!(matches!(
        reopened.directory_node(selected.digest()),
        Err(PublicationError::Directory(DirectoryTrieError::Corrupt))
    ));
    Ok(())
}

#[test]
fn version_one_database_migrates_to_current_branch_schema() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let file = directory.path().join(DATABASE_FILE);
    let mut connection = Connection::open(&file)?;
    configure(&connection)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(MIGRATIONS[0].sql)?;
    let digest: [u8; 32] = blake3::hash(MIGRATIONS[0].sql.as_bytes()).into();
    transaction.execute(
        "INSERT INTO schema_migrations(version, migration_digest, applied_at)
         VALUES (1, ?1, 1)",
        params![digest.as_slice()],
    )?;
    transaction.pragma_update(None, "user_version", 1)?;
    transaction.commit()?;
    drop(connection);

    let store = VersionPublicationStore::open(directory.path(), UnixMicros::new(2))?;
    let version: u32 = store
        .connection
        .pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, SCHEMA_VERSION);
    for table in [
        "directory_nodes",
        "branch_namespace_heads",
        "directory_publication_operations",
        "namespace_commit_intents",
        "namespace_commit_intent_ancestors",
        "namespace_reconciliation_operations",
        "namespace_snapshot_restore_operations",
        "namespace_rename_operations",
        "namespace_commit_deletions",
        "file_version_history",
        "open_handles",
        "pending_object_deletes",
        "handle_write_admissions",
        "open_handle_path_components",
        "handle_flush_plans",
        "handle_flush_progress",
        "version_reachability_scans",
        "version_reachability_roots",
        "version_reachability_work",
        "version_cleanup_reference_fences",
        "retired_manifest_roots",
        "cancelled_cleanup_releases",
    ] {
        assert_table_exists(&store.connection, table)?;
    }
    let acquired_lock_fence: i64 = store.connection.query_row(
        "SELECT count(*) FROM pragma_table_info('range_locks')
         WHERE name = 'acquired_handle_fence' AND \"notnull\" = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(acquired_lock_fence, 1);
    Ok(())
}

fn assert_table_exists(
    connection: &Connection,
    table: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )?;
    assert_eq!(exists, 1, "missing migrated table {table}");
    Ok(())
}

#[test]
fn version_nine_migration_backfills_history_after_a_cross_branch_fork()
-> Result<(), Box<dyn std::error::Error>> {
    let mut connection = Connection::open_in_memory()?;
    configure(&connection)?;
    for migration in &MIGRATIONS[..8] {
        connection.execute_batch(migration.sql)?;
    }
    seed_pre_v9_cross_branch_versions(&mut connection)?;
    connection.execute_batch(MIGRATIONS[8].sql)?;
    let stored: (Vec<u8>, i64) = connection.query_row(
        "SELECT branch_id, policy_sequence FROM file_version_history",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(stored.0, vec![2; 16]);
    assert_eq!(stored.1, 1);
    Ok(())
}

fn seed_pre_v9_cross_branch_versions(
    connection: &mut Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO content_manifests(
            manifest_id, format_version, logical_length, content_digest, root_digest, state
         ) VALUES (?1, 1, 1, ?2, ?3, 1)",
        params![&[5_u8; 16], &[6_u8; 32], &[7_u8; 32]],
    )?;
    for branch in [1_u8, 2] {
        transaction.execute(
            "INSERT INTO branch_files(
                branch_id, object_id, volume_id, current_version_id, head_sequence
             ) VALUES (?1, ?2, ?3, ?4, 1)",
            params![&[branch; 16], &[3_u8; 16], &[4_u8; 16], &[branch; 16]],
        )?;
    }
    transaction.execute(
        "INSERT INTO file_versions(
            version_id, branch_id, volume_id, object_id, parent_version_id, manifest_id,
            logical_length, content_digest, created_by, created_at, publication_operation_id
         ) VALUES (?1, ?2, ?3, ?4, NULL, ?5, 1, ?6, ?7, 10, ?8)",
        params![
            &[1_u8; 16],
            &[1_u8; 16],
            &[4_u8; 16],
            &[3_u8; 16],
            &[5_u8; 16],
            &[6_u8; 32],
            &[8_u8; 16],
            &[9_u8; 16]
        ],
    )?;
    transaction.execute(
        "INSERT INTO file_versions(
            version_id, branch_id, volume_id, object_id, parent_version_id, manifest_id,
            logical_length, content_digest, created_by, created_at, publication_operation_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, 20, ?9)",
        params![
            &[2_u8; 16],
            &[2_u8; 16],
            &[4_u8; 16],
            &[3_u8; 16],
            &[1_u8; 16],
            &[5_u8; 16],
            &[6_u8; 32],
            &[8_u8; 16],
            &[10_u8; 16]
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

#[test]
fn version_retention_selection_is_bounded_oldest_first_and_policy_exact()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let mut third = following_root_publication(&second, 80, 81, 82, 83, 84)?;
    third.file.retain_superseded_history = false;
    let fourth = following_root_publication(&third, 90, 91, 92, 93, 94)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    for publication in [&first, &second, &third, &fourth] {
        store.publish_root_file(publication)?;
    }
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    crate::version_retention::record_conflict_protection(
        &transaction,
        first.file.version_id,
        UnixMicros::new(85),
    )?;
    transaction.commit()?;

    let policy = VersionRetentionSelectionPolicy::new(
        7,
        DurationMicros::new(15),
        None,
        Some(1),
        VersionReclaimMode::UnderPressure,
        true,
        DurationMicros::new(30),
    )?;
    assert_normal_retention_selection(&store, &first, &second, &fourth, policy)?;
    assert_maximum_age_is_pressure_independent(&store, &third)?;
    assert_critical_retention_selection(&store, &first, &second, &third)?;
    let before_restart = store.version_retention_candidates(
        first.file.volume_id,
        policy,
        VersionRetentionPressure::Pressure,
        UnixMicros::new(120),
        None,
        VersionRetentionPageLimit::new(10)?,
    )?;
    drop(store);
    assert_retention_restart_and_corruption(directory.path(), &first, policy, &before_restart)?;
    Ok(())
}

fn assert_maximum_age_is_pressure_independent(
    store: &VersionPublicationStore,
    expected: &RootFilePublication,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = VersionRetentionSelectionPolicy::new(
        9,
        DurationMicros::new(15),
        Some(DurationMicros::new(30)),
        None,
        VersionReclaimMode::UnderPressure,
        false,
        DurationMicros::new(30),
    )?;
    let page = store.version_retention_candidates(
        expected.file.volume_id,
        policy,
        VersionRetentionPressure::None,
        UnixMicros::new(120),
        None,
        VersionRetentionPageLimit::new(10)?,
    )?;
    assert!(page.items.iter().any(|candidate| {
        candidate.version_id == expected.file.version_id
            && candidate.reason == VersionRetentionCandidateReason::MaximumAge
    }));
    Ok(())
}

#[test]
fn version_retention_rejects_unsafe_policy_and_page_bounds() {
    assert!(matches!(
        VersionRetentionSelectionPolicy::new(
            0,
            DurationMicros::new(1),
            None,
            None,
            VersionReclaimMode::UnderPressure,
            false,
            DurationMicros::new(1),
        ),
        Err(VersionRetentionError::InvalidPolicy)
    ));
    assert!(matches!(
        VersionRetentionSelectionPolicy::new(
            u64::MAX,
            DurationMicros::new(1),
            None,
            None,
            VersionReclaimMode::UnderPressure,
            false,
            DurationMicros::new(1),
        ),
        Err(VersionRetentionError::InvalidPolicy)
    ));
    assert!(matches!(
        VersionRetentionSelectionPolicy::new(
            1,
            DurationMicros::new(2),
            Some(DurationMicros::new(1)),
            None,
            VersionReclaimMode::AfterMaximumAge,
            false,
            DurationMicros::new(2),
        ),
        Err(VersionRetentionError::InvalidPolicy)
    ));
    assert!(matches!(
        VersionRetentionPageLimit::new(0),
        Err(VersionRetentionError::InvalidLimit)
    ));
    assert!(matches!(
        VersionRetentionPageLimit::new(4_097),
        Err(VersionRetentionError::InvalidLimit)
    ));
}

#[test]
fn reachability_scan_is_bounded_restart_safe_and_proves_an_old_version_unreachable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let policy = eager_retention_policy()?;
    let candidate = retention_candidate(&store, first.file.volume_id, policy)?;
    let roots = vec![publication_root(&second)];
    let request = reachability_request(candidate, policy, &roots, 170)?;
    let mut peer_request = request;
    peer_request.operation_id = OperationId::from_bytes([169; 16])?;
    assert_eq!(
        reachability_subject_digest(&request),
        reachability_subject_digest(&peer_request)
    );

    let begun = store.begin_version_reachability_scan(&request)?;
    assert_eq!(begun.state, VersionReachabilityState::CollectingRoots);
    let page = ReachabilityRootPage {
        operation_id: request.operation_id,
        start_ordinal: 0,
        roots,
    };
    store.append_version_reachability_roots(&page)?;
    drop(store);

    let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(121))?;
    let resumed = reopened.begin_version_reachability_scan(&request)?;
    assert_eq!(resumed.state, VersionReachabilityState::CollectingRoots);
    assert_eq!(resumed.roots_received, 1);
    assert!(matches!(
        reopened.prepare_snapshot_restore(snapshot_restore_publication(&first, &second)?),
        Err(PublicationError::CleanupFenced)
    ));
    assert_eq!(
        reopened
            .append_version_reachability_roots(&page)?
            .roots_received,
        1
    );
    let progress =
        reopened.seal_version_reachability_roots(request.operation_id, UnixMicros::new(122))?;
    assert_eq!(progress.state, VersionReachabilityState::Scanning);
    let progress = finish_reachability_scan(&mut reopened, request.operation_id, progress, 1)?;
    assert_eq!(progress.state, VersionReachabilityState::Unreachable);
    let proof = progress.proof.ok_or("missing unreachable proof")?;
    assert_eq!(proof.version_id, first.file.version_id);
    assert_eq!(proof.manifest_id, first.file.manifest.manifest_id);
    assert_eq!(proof.retention_policy_sequence, policy.sequence());
    assert_eq!(proof.root_count, request.root_count);
    assert_eq!(proof.root_digest, request.root_digest);
    assert_eq!(proof.subject_digest, reachability_subject_digest(&request));
    assert!(progress.work_processed >= 3);
    assert_eq!(progress.work_pending, 0);
    let mut republished = following_root_publication(&second, 190, 191, 192, 193, 194)?;
    republished.file.manifest = first.file.manifest;
    republished.file.manifest.manifest_id = ContentManifestId::from_bytes([195; 16])?;
    assert!(matches!(
        reopened.publish_root_file(&republished),
        Err(PublicationError::CleanupFenced)
    ));
    assert!(matches!(
        crate::cleanup_fence::reject_version_reference(&reopened.connection, first.file.version_id,),
        Err(PublicationError::CleanupFenced)
    ));
    assert!(matches!(
        reopened.prepare_snapshot_restore(snapshot_restore_publication(&first, &second)?),
        Err(PublicationError::CleanupFenced)
    ));
    assert_eq!(
        reopened.advance_version_reachability_scan(
            request.operation_id,
            1,
            UnixMicros::new(124),
        )?,
        progress
    );
    Ok(())
}

#[test]
fn completed_cleanup_permanently_retires_the_exact_manifest_root()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let policy = eager_retention_policy()?;
    let candidate = retention_candidate(&store, first.file.volume_id, policy)?;
    let roots = vec![publication_root(&second)];
    let request = reachability_request(candidate, policy, &roots, 165)?;
    store.begin_version_reachability_scan(&request)?;
    store.append_version_reachability_roots(&ReachabilityRootPage {
        operation_id: request.operation_id,
        start_ordinal: 0,
        roots,
    })?;
    let progress =
        store.seal_version_reachability_roots(request.operation_id, UnixMicros::new(122))?;
    let progress = finish_reachability_scan(&mut store, request.operation_id, progress, 1)?;
    let proof = progress.proof.ok_or("missing unreachable proof")?;
    let authority = retirement_authority(proof.operation_id, proof.subject_digest)?;
    let mut wrong_subject = authority;
    wrong_subject.reachability_subject_digest[0] ^= 1;
    assert!(matches!(
        store.retire_completed_version_cleanup(wrong_subject),
        Err(VersionCleanupRetirementError::Stale)
    ));

    let receipt = store.retire_completed_version_cleanup(authority)?;
    assert_eq!(receipt.manifest_id, first.file.manifest.manifest_id);
    assert_eq!(
        receipt.manifest_root_digest,
        first.file.manifest.root_digest
    );
    assert_eq!(store.retire_completed_version_cleanup(authority)?, receipt);
    assert!(matches!(
        store.release_cancelled_version_cleanup(cancellation_authority(
            proof.operation_id,
            proof.subject_digest,
        )?),
        Err(VersionCleanupCancellationError::Conflict)
    ));
    drop(store);

    let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(130))?;
    assert_eq!(
        reopened.retire_completed_version_cleanup(authority)?,
        receipt
    );
    reopened.connection.execute(
        "UPDATE version_cleanup_reference_fences SET state = 2, released_at = 131
         WHERE operation_id = ?1",
        [request.operation_id.as_bytes().as_slice()],
    )?;
    let mut republished = following_root_publication(&second, 196, 197, 198, 199, 200)?;
    republished.file.manifest = first.file.manifest;
    republished.file.manifest.manifest_id = ContentManifestId::from_bytes([201; 16])?;
    assert!(matches!(
        reopened.publish_root_file(&republished),
        Err(PublicationError::CleanupFenced)
    ));
    let mut repeated_scan = request;
    repeated_scan.operation_id = OperationId::from_bytes([202; 16])?;
    assert!(matches!(
        reopened.begin_version_reachability_scan(&repeated_scan),
        Err(VersionReachabilityError::Conflict)
    ));
    Ok(())
}

#[test]
fn cleanup_retirement_rejects_invalid_replay_and_persisted_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let policy = eager_retention_policy()?;
    let candidate = retention_candidate(&store, first.file.volume_id, policy)?;
    let roots = vec![publication_root(&second)];
    let request = reachability_request(candidate, policy, &roots, 164)?;
    store.begin_version_reachability_scan(&request)?;
    store.append_version_reachability_roots(&ReachabilityRootPage {
        operation_id: request.operation_id,
        start_ordinal: 0,
        roots,
    })?;
    let progress =
        store.seal_version_reachability_roots(request.operation_id, UnixMicros::new(122))?;
    let progress = finish_reachability_scan(&mut store, request.operation_id, progress, 64)?;
    let proof = progress.proof.ok_or("missing unreachable proof")?;
    let authority = retirement_authority(proof.operation_id, proof.subject_digest)?;
    assert!(matches!(
        crate::cleanup_fence::retire_completed_with_fault(&mut store.connection, authority),
        Err(VersionCleanupRetirementError::InjectedFault)
    ));
    let retired_count: i64 =
        store
            .connection
            .query_row("SELECT count(*) FROM retired_manifest_roots", [], |row| {
                row.get(0)
            })?;
    assert_eq!(retired_count, 0);
    store.retire_completed_version_cleanup(authority)?;

    let mut conflicting = authority;
    conflicting.completion_digest[0] ^= 1;
    assert!(matches!(
        store.retire_completed_version_cleanup(conflicting),
        Err(VersionCleanupRetirementError::Conflict)
    ));
    let mut duplicate_cleanup = authority;
    duplicate_cleanup.retirement_operation_id = OperationId::from_bytes([239; 16])?;
    assert!(matches!(
        store.retire_completed_version_cleanup(duplicate_cleanup),
        Err(VersionCleanupRetirementError::Conflict)
    ));
    store.connection.execute(
        "UPDATE retired_manifest_roots SET retirement_digest = ?1",
        [[9_u8; 32].as_slice()],
    )?;
    assert!(matches!(
        store.retire_completed_version_cleanup(authority),
        Err(VersionCleanupRetirementError::Corrupt)
    ));
    Ok(())
}

#[test]
fn cancelled_cleanup_release_is_atomic_replayable_and_restart_safe()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let policy = eager_retention_policy()?;
    let candidate = retention_candidate(&store, first.file.volume_id, policy)?;
    let roots = vec![publication_root(&second)];
    let request = reachability_request(candidate, policy, &roots, 163)?;
    store.begin_version_reachability_scan(&request)?;
    store.append_version_reachability_roots(&ReachabilityRootPage {
        operation_id: request.operation_id,
        start_ordinal: 0,
        roots,
    })?;
    let progress =
        store.seal_version_reachability_roots(request.operation_id, UnixMicros::new(122))?;
    let progress = finish_reachability_scan(&mut store, request.operation_id, progress, 64)?;
    let proof = progress.proof.ok_or("missing unreachable proof")?;
    let authority = cancellation_authority(proof.operation_id, proof.subject_digest)?;
    let mut wrong_subject = authority;
    wrong_subject.reachability_subject_digest[0] ^= 1;
    assert!(matches!(
        store.release_cancelled_version_cleanup(wrong_subject),
        Err(VersionCleanupCancellationError::Stale)
    ));
    assert!(matches!(
        crate::cleanup_cancellation::release_with_fault(&mut store.connection, authority),
        Err(VersionCleanupCancellationError::InjectedFault)
    ));
    let release_count: i64 = store.connection.query_row(
        "SELECT count(*) FROM cancelled_cleanup_releases",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(release_count, 0);

    let receipt = store.release_cancelled_version_cleanup(authority)?;
    assert_eq!(receipt.manifest_id, first.file.manifest.manifest_id);
    assert_eq!(store.release_cancelled_version_cleanup(authority)?, receipt);
    assert_eq!(
        store.advance_version_reachability_scan(request.operation_id, 1, UnixMicros::new(130))?,
        progress
    );
    let mut republished = following_root_publication(&second, 203, 204, 205, 206, 207)?;
    republished.file.manifest = first.file.manifest;
    republished.file.manifest.manifest_id = ContentManifestId::from_bytes([208; 16])?;
    assert_eq!(
        store.publish_root_file(&republished)?.disposition,
        PublicationDisposition::Applied
    );
    drop(store);

    let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(140))?;
    assert_eq!(
        reopened.release_cancelled_version_cleanup(authority)?,
        receipt
    );
    Ok(())
}

#[test]
fn cancelled_cleanup_release_rejects_conflict_retirement_and_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let policy = eager_retention_policy()?;
    let candidate = retention_candidate(&store, first.file.volume_id, policy)?;
    let roots = vec![publication_root(&second)];
    let request = reachability_request(candidate, policy, &roots, 162)?;
    store.begin_version_reachability_scan(&request)?;
    store.append_version_reachability_roots(&ReachabilityRootPage {
        operation_id: request.operation_id,
        start_ordinal: 0,
        roots,
    })?;
    let progress =
        store.seal_version_reachability_roots(request.operation_id, UnixMicros::new(122))?;
    let progress = finish_reachability_scan(&mut store, request.operation_id, progress, 64)?;
    let proof = progress.proof.ok_or("missing unreachable proof")?;
    let authority = cancellation_authority(proof.operation_id, proof.subject_digest)?;
    store.release_cancelled_version_cleanup(authority)?;
    assert!(matches!(
        store.retire_completed_version_cleanup(retirement_authority(
            proof.operation_id,
            proof.subject_digest,
        )?),
        Err(VersionCleanupRetirementError::Stale | VersionCleanupRetirementError::Conflict)
    ));
    let mut conflicting = authority;
    conflicting.cancellation_revision = Revision::new(32);
    assert!(matches!(
        store.release_cancelled_version_cleanup(conflicting),
        Err(VersionCleanupCancellationError::Conflict)
    ));
    let mut duplicate = authority;
    duplicate.release_operation_id = OperationId::from_bytes([249; 16])?;
    assert!(matches!(
        store.release_cancelled_version_cleanup(duplicate),
        Err(VersionCleanupCancellationError::Conflict)
    ));
    store.connection.execute(
        "UPDATE cancelled_cleanup_releases SET release_digest = ?1",
        [[9_u8; 32].as_slice()],
    )?;
    assert!(matches!(
        store.release_cancelled_version_cleanup(authority),
        Err(VersionCleanupCancellationError::Corrupt)
    ));
    Ok(())
}

#[test]
fn reachable_version_sharing_the_manifest_blocks_physical_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let mut second = next_root_publication(&first)?;
    second.file.manifest = first.file.manifest;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let policy = eager_retention_policy()?;
    let candidate = retention_candidate(&store, first.file.volume_id, policy)?;
    let roots = vec![publication_root(&second)];
    let request = reachability_request(candidate, policy, &roots, 168)?;
    store.begin_version_reachability_scan(&request)?;
    store.append_version_reachability_roots(&ReachabilityRootPage {
        operation_id: request.operation_id,
        start_ordinal: 0,
        roots,
    })?;
    let progress =
        store.seal_version_reachability_roots(request.operation_id, UnixMicros::new(122))?;
    assert_eq!(progress.state, VersionReachabilityState::Reachable);
    assert!(progress.proof.is_none());
    let mut third = following_root_publication(&second, 185, 186, 187, 188, 189)?;
    third.file.manifest = first.file.manifest;
    third.file.manifest.manifest_id = ContentManifestId::from_bytes([190; 16])?;
    assert_eq!(
        store.publish_root_file(&third)?.disposition,
        PublicationDisposition::Applied
    );
    Ok(())
}

#[test]
fn cleanup_reference_fence_rejects_parallel_scan_and_tampered_release()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let policy = eager_retention_policy()?;
    let candidate = retention_candidate(&store, first.file.volume_id, policy)?;
    let roots = vec![publication_root(&second)];
    let request = reachability_request(candidate, policy, &roots, 167)?;
    store.begin_version_reachability_scan(&request)?;

    let mut parallel = request;
    parallel.operation_id = OperationId::from_bytes([166; 16])?;
    assert!(matches!(
        store.begin_version_reachability_scan(&parallel),
        Err(VersionReachabilityError::Conflict)
    ));

    store.connection.execute(
        "UPDATE version_cleanup_reference_fences SET state = 2, released_at = 121
         WHERE operation_id = ?1",
        [request.operation_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        store.begin_version_reachability_scan(&request),
        Err(VersionReachabilityError::Stale)
    ));
    Ok(())
}

#[test]
fn retained_snapshot_root_and_substituted_root_manifest_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let policy = eager_retention_policy()?;
    let candidate = retention_candidate(&store, first.file.volume_id, policy)?;
    let roots = vec![
        publication_root(&second),
        ReachabilityRoot {
            source: ReachabilityRootSource::Snapshot(SnapshotId::from_bytes([199; 16])?),
            namespace_commit_id: first.namespace_commit_id,
            root_object_revision_id: first.root_object_revision_id,
        },
    ];
    let request = reachability_request(candidate, policy, &roots, 171)?;
    store.begin_version_reachability_scan(&request)?;
    let mut substituted = roots.clone();
    substituted[1].namespace_commit_id = second.namespace_commit_id;
    assert!(matches!(
        store.append_version_reachability_roots(&ReachabilityRootPage {
            operation_id: request.operation_id,
            start_ordinal: 0,
            roots: substituted,
        }),
        Err(VersionReachabilityError::Stale)
    ));
    store.append_version_reachability_roots(&ReachabilityRootPage {
        operation_id: request.operation_id,
        start_ordinal: 0,
        roots,
    })?;
    let progress =
        store.seal_version_reachability_roots(request.operation_id, UnixMicros::new(122))?;
    let progress = finish_reachability_scan(&mut store, request.operation_id, progress, 1)?;
    assert_eq!(progress.state, VersionReachabilityState::Reachable);
    assert!(progress.proof.is_none());
    Ok(())
}

#[test]
fn reachability_scan_rejects_corrupt_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let policy = eager_retention_policy()?;
    let candidate = retention_candidate(&store, first.file.volume_id, policy)?;
    let roots = vec![publication_root(&second)];

    let corrupt_request = reachability_request(candidate, policy, &roots, 172)?;
    store.begin_version_reachability_scan(&corrupt_request)?;
    store.append_version_reachability_roots(&ReachabilityRootPage {
        operation_id: corrupt_request.operation_id,
        start_ordinal: 0,
        roots,
    })?;
    store.connection.execute(
        "UPDATE version_reachability_roots SET record_digest = zeroblob(32)
         WHERE operation_id = ?1",
        [corrupt_request.operation_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        store.seal_version_reachability_roots(corrupt_request.operation_id, UnixMicros::new(121)),
        Err(VersionReachabilityError::Corrupt)
    ));
    Ok(())
}

#[test]
fn reachability_scan_rejects_changed_local_roots() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let third = following_root_publication(&second, 180, 181, 182, 183, 184)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let policy = eager_retention_policy()?;
    let candidate = retention_candidate(&store, first.file.volume_id, policy)?;
    let roots = vec![publication_root(&second)];
    let stale_request = reachability_request(candidate, policy, &roots, 173)?;
    store.begin_version_reachability_scan(&stale_request)?;
    store.append_version_reachability_roots(&ReachabilityRootPage {
        operation_id: stale_request.operation_id,
        start_ordinal: 0,
        roots,
    })?;
    assert_eq!(
        store
            .seal_version_reachability_roots(stale_request.operation_id, UnixMicros::new(122))?
            .state,
        VersionReachabilityState::Scanning
    );
    store.publish_root_file(&third)?;
    assert!(matches!(
        store.advance_version_reachability_scan(
            stale_request.operation_id,
            1,
            UnixMicros::new(123)
        ),
        Err(VersionReachabilityError::Stale)
    ));
    Ok(())
}

fn eager_retention_policy() -> Result<VersionRetentionSelectionPolicy, Box<dyn std::error::Error>> {
    Ok(VersionRetentionSelectionPolicy::new(
        7,
        DurationMicros::new(0),
        None,
        None,
        VersionReclaimMode::EagerAfterMinimumAge,
        false,
        DurationMicros::new(0),
    )?)
}

fn retention_candidate(
    store: &VersionPublicationStore,
    volume_id: VolumeId,
    policy: VersionRetentionSelectionPolicy,
) -> Result<VersionRetentionCandidate, Box<dyn std::error::Error>> {
    let page = store.version_retention_candidates(
        volume_id,
        policy,
        VersionRetentionPressure::None,
        UnixMicros::new(120),
        None,
        VersionRetentionPageLimit::new(10)?,
    )?;
    page.items
        .first()
        .copied()
        .ok_or_else(|| "missing candidate".into())
}

fn publication_root(publication: &RootFilePublication) -> ReachabilityRoot {
    ReachabilityRoot {
        source: ReachabilityRootSource::ConvergedHead(publication.file.volume_id),
        namespace_commit_id: publication.namespace_commit_id,
        root_object_revision_id: publication.root_object_revision_id,
    }
}

fn reachability_request(
    candidate: VersionRetentionCandidate,
    policy: VersionRetentionSelectionPolicy,
    roots: &[ReachabilityRoot],
    operation: u8,
) -> Result<VersionReachabilityScanRequest, Box<dyn std::error::Error>> {
    let metadata_revision = Revision::new(42);
    Ok(VersionReachabilityScanRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        candidate,
        policy,
        pressure: VersionRetentionPressure::None,
        selected_at: UnixMicros::new(120),
        metadata_revision,
        root_count: u64::try_from(roots.len())?,
        root_digest: reachability_root_digest(candidate.volume_id, metadata_revision, roots)?,
        root_set_digest: reachability_root_set_digest(candidate.volume_id, roots)?,
    })
}

fn retirement_authority(
    source_scan_operation_id: OperationId,
    reachability_subject_digest: [u8; 32],
) -> Result<VersionCleanupRetirementAuthority, Box<dyn std::error::Error>> {
    Ok(VersionCleanupRetirementAuthority {
        retirement_operation_id: OperationId::from_bytes([240; 16])?,
        cleanup_operation_id: OperationId::from_bytes([241; 16])?,
        source_scan_operation_id,
        reachability_subject_digest,
        completed_item_count: 3,
        completion_digest: [243; 32],
        completion_operation_id: OperationId::from_bytes([244; 16])?,
        completion_revision: Revision::new(30),
        completed_at: UnixMicros::new(125),
        retired_at: UnixMicros::new(126),
    })
}

fn cancellation_authority(
    source_scan_operation_id: OperationId,
    reachability_subject_digest: [u8; 32],
) -> Result<VersionCleanupCancellationAuthority, Box<dyn std::error::Error>> {
    Ok(VersionCleanupCancellationAuthority {
        release_operation_id: OperationId::from_bytes([246; 16])?,
        cleanup_operation_id: OperationId::from_bytes([247; 16])?,
        source_scan_operation_id,
        reachability_subject_digest,
        cancellation_operation_id: OperationId::from_bytes([248; 16])?,
        cancellation_revision: Revision::new(31),
        cancelled_at: UnixMicros::new(125),
        released_at: UnixMicros::new(126),
    })
}

fn finish_reachability_scan(
    store: &mut VersionPublicationStore,
    operation_id: OperationId,
    mut progress: crate::VersionReachabilityProgress,
    maximum_work: usize,
) -> Result<crate::VersionReachabilityProgress, VersionReachabilityError> {
    while progress.state == VersionReachabilityState::Scanning {
        progress = store.advance_version_reachability_scan(
            operation_id,
            maximum_work,
            UnixMicros::new(123),
        )?;
    }
    Ok(progress)
}

fn assert_retention_restart_and_corruption(
    state_directory: &std::path::Path,
    first: &RootFilePublication,
    policy: VersionRetentionSelectionPolicy,
    before_restart: &crate::VersionRetentionCandidatePage,
) -> Result<(), Box<dyn std::error::Error>> {
    let reopened = VersionPublicationStore::open(state_directory, UnixMicros::new(121))?;
    assert_eq!(
        &reopened.version_retention_candidates(
            first.file.volume_id,
            policy,
            VersionRetentionPressure::Pressure,
            UnixMicros::new(120),
            None,
            VersionRetentionPageLimit::new(10)?,
        )?,
        before_restart
    );
    reopened
        .connection
        .pragma_update(None, "ignore_check_constraints", true)?;
    reopened.connection.execute(
        "UPDATE file_version_history SET superseded_by_version_id = version_id
         WHERE version_id = ?1",
        [first.file.version_id.as_bytes().as_slice()],
    )?;
    reopened
        .connection
        .pragma_update(None, "ignore_check_constraints", false)?;
    assert!(matches!(
        reopened.version_retention_candidates(
            first.file.volume_id,
            policy,
            VersionRetentionPressure::None,
            UnixMicros::new(120),
            None,
            VersionRetentionPageLimit::new(10)?,
        ),
        Err(VersionRetentionError::Corrupt)
    ));
    Ok(())
}

fn assert_normal_retention_selection(
    store: &VersionPublicationStore,
    first: &RootFilePublication,
    second: &RootFilePublication,
    current: &RootFilePublication,
    policy: VersionRetentionSelectionPolicy,
) -> Result<(), Box<dyn std::error::Error>> {
    let without_pressure = store.version_retention_candidates(
        first.file.volume_id,
        policy,
        VersionRetentionPressure::None,
        UnixMicros::new(100),
        None,
        VersionRetentionPageLimit::new(10)?,
    )?;
    assert_eq!(without_pressure.items.len(), 1);
    assert_eq!(without_pressure.items[0].version_id, second.file.version_id);
    assert_eq!(
        without_pressure.items[0].reason,
        VersionRetentionCandidateReason::HistoryDisabled
    );
    assert!(without_pressure.next.is_none());

    let first_page = store.version_retention_candidates(
        first.file.volume_id,
        policy,
        VersionRetentionPressure::Pressure,
        UnixMicros::new(120),
        None,
        VersionRetentionPageLimit::new(1)?,
    )?;
    assert_eq!(first_page.items[0].version_id, first.file.version_id);
    assert_eq!(
        first_page.items[0].reason,
        VersionRetentionCandidateReason::ConflictSafetyElapsed
    );
    let second_page = store.version_retention_candidates(
        first.file.volume_id,
        policy,
        VersionRetentionPressure::Pressure,
        UnixMicros::new(120),
        first_page.next,
        VersionRetentionPageLimit::new(1)?,
    )?;
    assert_eq!(second_page.items[0].version_id, second.file.version_id);
    assert!(second_page.next.is_none());
    assert!(
        first_page
            .items
            .iter()
            .chain(&second_page.items)
            .all(|candidate| candidate.policy_sequence == 7
                && candidate.supersession_policy_sequence == 1
                && candidate.version_id != current.file.version_id)
    );
    Ok(())
}

fn assert_critical_retention_selection(
    store: &VersionPublicationStore,
    first: &RootFilePublication,
    second: &RootFilePublication,
    third: &RootFilePublication,
) -> Result<(), Box<dyn std::error::Error>> {
    let critical = VersionRetentionSelectionPolicy::new(
        8,
        DurationMicros::new(40),
        None,
        None,
        VersionReclaimMode::UnderPressure,
        true,
        DurationMicros::new(40),
    )?;
    let critical_page = store.version_retention_candidates(
        first.file.volume_id,
        critical,
        VersionRetentionPressure::Critical,
        UnixMicros::new(100),
        None,
        VersionRetentionPageLimit::new(10)?,
    )?;
    assert_eq!(
        critical_page
            .items
            .iter()
            .map(|candidate| (candidate.version_id, candidate.reason))
            .collect::<Vec<_>>(),
        [
            (
                second.file.version_id,
                VersionRetentionCandidateReason::HistoryDisabled,
            ),
            (
                third.file.version_id,
                VersionRetentionCandidateReason::CriticalPressure,
            ),
        ]
    );
    Ok(())
}

#[test]
fn supersession_history_rolls_back_with_a_failed_namespace_publication()
-> Result<(), Box<dyn std::error::Error>> {
    use super::namespace::NamespaceFaultPoint;

    for fault in [
        NamespaceFaultPoint::FileVersion,
        NamespaceFaultPoint::ObjectRevisions,
        NamespaceFaultPoint::NamespaceCommit,
        NamespaceFaultPoint::Heads,
        NamespaceFaultPoint::Operation,
    ] {
        let directory = tempdir()?;
        let first = initial_root_publication()?;
        let second = next_root_publication(&first)?;
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&first)?;
        assert!(matches!(
            super::namespace::publish(&mut store.connection, &second, Some(fault)),
            Err(PublicationError::InjectedFault)
        ));
        let history: i64 =
            store
                .connection
                .query_row("SELECT count(*) FROM file_version_history", [], |row| {
                    row.get(0)
                })?;
        assert_eq!(history, 0);
        assert_eq!(
            store
                .namespace_head(first.file.branch_id, first.file.volume_id)?
                .ok_or("head missing")?
                .namespace_commit_id,
            first.namespace_commit_id
        );
    }
    Ok(())
}

#[test]
fn snapshot_restore_prepares_off_head_then_activates_idempotently_across_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let restore = snapshot_restore_publication(&first, &second)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;

    let applied = store.prepare_snapshot_restore(restore)?;
    assert_eq!(applied.disposition, PublicationDisposition::Applied);
    assert_eq!(
        store.namespace_head(first.file.branch_id, first.file.volume_id)?,
        Some(super::BranchNamespaceHead {
            branch_id: first.file.branch_id,
            volume_id: first.file.volume_id,
            namespace_commit_id: second.namespace_commit_id,
            sequence: 2,
        })
    );
    drop(store);

    let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(130))?;
    let replayed = reopened
        .resolve_snapshot_restore(restore.operation_id)?
        .ok_or("missing restore receipt")?;
    assert_eq!(replayed.disposition, PublicationDisposition::Replayed);
    assert_eq!(replayed.result_digest, applied.result_digest);
    assert_eq!(
        reopened.prepare_snapshot_restore(restore)?.disposition,
        PublicationDisposition::Replayed
    );
    let activated = reopened.activate_snapshot_restore(replayed, UnixMicros::new(131))?;
    assert_eq!(activated.namespace_commit_id, restore.namespace_commit_id);
    assert_eq!(activated.sequence, 3);
    assert_eq!(
        reopened
            .activate_snapshot_restore(replayed, UnixMicros::new(132))?
            .sequence,
        3
    );
    Ok(())
}

#[test]
fn prepared_restore_is_causal_but_cannot_reconcile_before_authority_commits_it()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let restore = snapshot_restore_publication(&first, &second)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    store.prepare_snapshot_restore(restore)?;

    let uncommitted = ReconciliationFrontier {
        converged_head: Some(second.namespace_commit_id),
        eligible_heads: vec![restore.namespace_commit_id],
    };
    assert!(matches!(
        store.plan_reconciliation(&uncommitted, ReconciliationLimits::DEFAULT),
        Err(crate::ReconciliationStoreError::Planning(
            crate::ReconciliationError::UncommittedRestore
        ))
    ));

    let receipt = store
        .resolve_snapshot_restore(restore.operation_id)?
        .ok_or("missing restore receipt")?;
    store.activate_snapshot_restore(receipt, UnixMicros::new(131))?;
    let committed = ReconciliationFrontier {
        converged_head: Some(restore.namespace_commit_id),
        eligible_heads: vec![second.namespace_commit_id],
    };
    assert!(
        store
            .plan_reconciliation(&committed, ReconciliationLimits::DEFAULT)?
            .ordered_commits()
            .is_empty()
    );
    Ok(())
}

#[test]
fn snapshot_restore_rejects_substitution_stale_activation_and_partial_transactions()
-> Result<(), Box<dyn std::error::Error>> {
    use super::namespace::NamespaceFaultPoint;

    for fault in [
        NamespaceFaultPoint::SnapshotRestoreCommit,
        NamespaceFaultPoint::SnapshotRestoreOperation,
    ] {
        let directory = tempdir()?;
        let first = initial_root_publication()?;
        let second = next_root_publication(&first)?;
        let restore = snapshot_restore_publication(&first, &second)?;
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&first)?;
        store.publish_root_file(&second)?;
        assert!(matches!(
            super::namespace::prepare_snapshot_restore_with_fault(
                &mut store.connection,
                restore,
                fault,
            ),
            Err(PublicationError::InjectedFault)
        ));
        assert_eq!(store.resolve_snapshot_restore(restore.operation_id)?, None);
        let exists: i64 = store.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM namespace_commits WHERE namespace_commit_id = ?1
             )",
            [restore.namespace_commit_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        assert_eq!(exists, 0);
    }

    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let restore = snapshot_restore_publication(&first, &second)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let mut substituted = restore;
    substituted.root_object_revision_id = second.root_object_revision_id;
    assert!(matches!(
        store.prepare_snapshot_restore(substituted),
        Err(PublicationError::InvalidInput)
    ));
    let receipt = store.prepare_snapshot_restore(restore)?;
    store.connection.execute(
        "UPDATE branch_namespace_heads SET namespace_commit_id = ?1
         WHERE branch_id = ?2 AND volume_id = ?3",
        params![
            first.namespace_commit_id.as_bytes().as_slice(),
            first.file.branch_id.as_bytes().as_slice(),
            first.file.volume_id.as_bytes().as_slice(),
        ],
    )?;
    assert!(matches!(
        store.activate_snapshot_restore(receipt, UnixMicros::new(131)),
        Err(PublicationError::StaleHead)
    ));
    Ok(())
}

#[test]
fn real_directory_creates_enable_nested_file_publication_across_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_directory_publication()?;
    let second = nested_directory_publication(&first)?;
    let file = nested_file_publication(&first, &second)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    assert_eq!(store.create_directory(&first)?.head_sequence, 1);
    assert_eq!(store.create_directory(&second)?.head_sequence, 2);
    assert_eq!(store.publish_root_file(&file)?.head_sequence, 3);
    drop(store);

    let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(20))?;
    assert_eq!(
        reopened.create_directory(&first)?.disposition,
        PublicationDisposition::Replayed
    );
    assert_eq!(
        reopened.create_directory(&second)?.disposition,
        PublicationDisposition::Replayed
    );
    assert_eq!(
        reopened.publish_root_file(&file)?.disposition,
        PublicationDisposition::Replayed
    );
    let file_intent = reopened
        .branch_mutation_intent(file.namespace_commit_id)?
        .ok_or("missing nested file intent")?;
    assert_eq!(&file_intent.path, file.path.path());
    assert_eq!(file_intent.ancestors, file.path.ancestors());
    let directory_intent = reopened
        .branch_mutation_intent(second.namespace_commit_id)?
        .ok_or("missing nested directory intent")?;
    assert_eq!(&directory_intent.path, second.path.path());
    assert_eq!(directory_intent.ancestors, second.path.ancestors());
    assert_eq!(
        reopened
            .namespace_head(first.branch_id, first.volume_id)?
            .map(|head| (head.namespace_commit_id, head.sequence)),
        Some((file.namespace_commit_id, 3))
    );
    let root_entry = stored_directory_entry(
        &reopened,
        file.root_object_revision_id,
        &file.path.path().components()[0],
    )?;
    assert_eq!(
        root_entry.object_revision_id(),
        file.path.ancestors()[0].new_revision_id()
    );
    let a_entry = stored_directory_entry(
        &reopened,
        root_entry.object_revision_id(),
        &file.path.path().components()[1],
    )?;
    assert_eq!(
        a_entry.object_revision_id(),
        file.path.ancestors()[1].new_revision_id()
    );
    let file_entry = stored_directory_entry(
        &reopened,
        a_entry.object_revision_id(),
        &file.path.path().components()[2],
    )?;
    assert_eq!(
        file_entry.object_revision_id(),
        file.file_object_revision_id
    );
    assert_eq!(file_entry.object_id(), file.file.object_id);
    reopened.connection.execute(
        "UPDATE namespace_commit_intent_ancestors SET object_id = zeroblob(16)
         WHERE namespace_commit_id = ?1 AND ancestor_ordinal = 0",
        [file.namespace_commit_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        reopened.branch_mutation_intent(file.namespace_commit_id),
        Err(PublicationError::Corrupt)
    ));
    Ok(())
}

#[test]
fn root_file_publication_moves_file_and_volume_heads_once_across_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    let applied = store.publish_root_file(&first)?;
    assert_eq!(applied.disposition, PublicationDisposition::Applied);
    assert_eq!(applied.head_sequence, 1);
    drop(store);

    let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(2))?;
    let replayed = reopened.publish_root_file(&first)?;
    assert_eq!(replayed.disposition, PublicationDisposition::Replayed);
    assert_eq!(replayed.result_digest, applied.result_digest);
    let second = next_root_publication(&first)?;
    let next = reopened.publish_root_file(&second)?;
    assert_eq!(next.head_sequence, 2);
    assert_eq!(
        reopened.resolve_namespace_publication(first.file.operation_id)?,
        Some(NamespacePublicationReceipt {
            disposition: PublicationDisposition::Replayed,
            ..applied
        })
    );
    assert_eq!(
        reopened
            .namespace_head(first.file.branch_id, first.file.volume_id)?
            .map(|head| (head.namespace_commit_id, head.sequence)),
        Some((second.namespace_commit_id, 2))
    );
    assert_eq!(
        reopened.publish_root_file(&first)?.disposition,
        PublicationDisposition::Replayed
    );
    let mut stale = next_root_publication(&first)?;
    stale.file.operation_id = OperationId::from_bytes([80; 16])?;
    stale.file.version_id = FileVersionId::from_bytes([81; 16])?;
    stale.file.manifest.manifest_id = ContentManifestId::from_bytes([82; 16])?;
    stale.file_object_revision_id = ObjectRevisionId::from_bytes([83; 16])?;
    stale.root_object_revision_id = ObjectRevisionId::from_bytes([84; 16])?;
    stale.namespace_commit_id = NamespaceCommitId::from_bytes([85; 16])?;
    assert!(matches!(
        reopened.publish_root_file(&stale),
        Err(PublicationError::StaleHead)
    ));
    assert_eq!(
        reopened
            .namespace_head(first.file.branch_id, first.file.volume_id)?
            .map(|head| (head.namespace_commit_id, head.sequence)),
        Some((second.namespace_commit_id, 2))
    );
    Ok(())
}

#[test]
fn namespace_rename_is_atomic_durable_and_exactly_replayable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = initial_root_publication()?;
    let rename = root_file_rename(&file, "Archive")?;
    let applied = {
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&file)?;
        let receipt = store.rename_namespace(&rename)?;
        assert_eq!(receipt.disposition, PublicationDisposition::Applied);
        assert_eq!(receipt.head_sequence, 2);
        assert_namespace_rename_result(&store, &file, &rename)?;
        assert_eq!(
            store.branch_mutation_intent(rename.namespace_commit_id)?,
            Some(expected_rename_intent(&file, &rename))
        );
        receipt
    };

    let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(2))?;
    let replayed = NamespaceRenameReceipt {
        disposition: PublicationDisposition::Replayed,
        ..applied
    };
    assert_eq!(
        reopened.resolve_namespace_rename(rename.operation_id)?,
        Some(replayed)
    );
    assert_eq!(reopened.rename_namespace(&rename)?, replayed);
    let mut conflicting = rename.clone();
    conflicting.target_entry_generation = 2;
    assert!(matches!(
        reopened.rename_namespace(&conflicting),
        Err(HandleError::OperationConflict)
    ));
    assert_namespace_rename_result(&reopened, &file, &rename)?;
    Ok(())
}

#[test]
fn namespace_rename_supports_display_case_changes_without_aliasing()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = initial_root_publication()?;
    let rename = root_file_rename(&file, "REPORT")?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;
    store.rename_namespace(&rename)?;
    let entry = stored_directory_lookup(
        &store,
        rename.root_object_revision_id,
        &rename.target.path().components()[0],
    )?
    .ok_or("missing renamed entry")?;
    assert_eq!(entry.name().display(), "REPORT");
    assert_eq!(entry.object_id(), file.file.object_id);
    assert_eq!(entry.object_revision_id(), file.file_object_revision_id);
    Ok(())
}

#[test]
fn namespace_rename_moves_directories_and_rejects_descendant_cycles()
-> Result<(), Box<dyn std::error::Error>> {
    let moved_directory = tempdir()?;
    let first = initial_directory_publication()?;
    let rename = root_directory_rename(&first, "Archive")?;
    let mut store = VersionPublicationStore::open(moved_directory.path(), UnixMicros::new(1))?;
    store.create_directory(&first)?;
    store.rename_namespace(&rename)?;
    let target = stored_directory_entry(
        &store,
        rename.root_object_revision_id,
        &rename.target.path().components()[0],
    )?;
    assert_eq!(target.kind(), DirectoryEntryKind::Directory);
    assert_eq!(target.object_id(), first.directory_object_id);
    assert_eq!(
        target.object_revision_id(),
        first.directory_object_revision_id
    );

    let cyclic_directory = tempdir()?;
    let nested = nested_directory_publication(&first)?;
    let mut cyclic_store =
        VersionPublicationStore::open(cyclic_directory.path(), UnixMicros::new(1))?;
    cyclic_store.create_directory(&first)?;
    cyclic_store.create_directory(&nested)?;
    let cycle = descendant_directory_rename(&first, &nested)?;
    assert!(matches!(
        cyclic_store.rename_namespace(&cycle),
        Err(HandleError::Namespace(PublicationError::InvalidInput))
    ));
    assert_eq!(
        cyclic_store
            .namespace_head(first.branch_id, first.volume_id)?
            .map(|head| head.namespace_commit_id),
        Some(nested.namespace_commit_id)
    );
    assert_eq!(
        cyclic_store.resolve_namespace_rename(cycle.operation_id)?,
        None
    );
    Ok(())
}

#[test]
fn namespace_rename_rejects_stale_or_occupied_targets_without_partial_state()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = initial_root_publication()?;
    let sibling = sibling_root_publication(&file)?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;
    store.publish_root_file(&sibling)?;

    let mut occupied = root_file_rename(&file, "Taken")?;
    occupied.expected_namespace_commit_id = sibling.namespace_commit_id;
    assert!(matches!(
        store.rename_namespace(&occupied),
        Err(HandleError::AlreadyExists)
    ));
    assert_rename_was_not_committed(&store, &sibling, &occupied)?;

    let mut stale = root_file_rename(&file, "Archive")?;
    stale.operation_id = OperationId::from_bytes([156; 16])?;
    stale.expected_namespace_commit_id = sibling.namespace_commit_id;
    stale.expected_source_entry_generation = 2;
    stale.intermediate_root_object_revision_id = ObjectRevisionId::from_bytes([157; 16])?;
    stale.root_object_revision_id = ObjectRevisionId::from_bytes([158; 16])?;
    stale.namespace_commit_id = NamespaceCommitId::from_bytes([159; 16])?;
    assert!(matches!(
        store.rename_namespace(&stale),
        Err(HandleError::Namespace(PublicationError::StaleHead))
    ));
    assert_rename_was_not_committed(&store, &sibling, &stale)?;
    Ok(())
}

#[test]
fn every_namespace_rename_fault_rolls_back_both_paths_head_and_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    use super::namespace::NamespaceFaultPoint;

    for fault in [
        NamespaceFaultPoint::RenameSource,
        NamespaceFaultPoint::RenameTarget,
        NamespaceFaultPoint::RenameCommit,
        NamespaceFaultPoint::RenameHandles,
        NamespaceFaultPoint::RenameOperation,
    ] {
        let directory = tempdir()?;
        let file = initial_root_publication()?;
        let rename = root_file_rename(&file, "Archive")?;
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&file)?;
        assert!(matches!(
            super::namespace::rename_namespace(&mut store.connection, &rename, Some(fault)),
            Err(HandleError::Namespace(PublicationError::InjectedFault))
        ));
        assert_rename_was_not_committed(&store, &file, &rename)?;
        assert_eq!(
            store.rename_namespace(&rename)?.disposition,
            PublicationDisposition::Applied
        );
        assert_namespace_rename_result(&store, &file, &rename)?;
    }
    Ok(())
}

#[test]
fn namespace_rename_enforces_delete_sharing_and_relocates_live_handles()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = initial_root_publication()?;
    let mut open = rename_open_request(&file, 160, 161)?;
    open.desired_access = HandleAccess::new(true, false, true)?;
    open.share_access = HandleShare::new(true, true, true);
    let mut rename = root_file_rename(&file, "Archive")?;
    rename.requesting_handle_id = Some(open.handle_id);
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&file)?;
    store.open_handle(&open)?;
    store.rename_namespace(&rename)?;
    assert_eq!(
        store.handle_path(open.handle_id)?,
        rename.target.path().clone()
    );

    let blocked_directory = tempdir()?;
    let mut blocked_store =
        VersionPublicationStore::open(blocked_directory.path(), UnixMicros::new(1))?;
    blocked_store.publish_root_file(&file)?;
    let mut blocker = rename_open_request(&file, 162, 163)?;
    blocker.share_access = HandleShare::new(true, true, false);
    blocked_store.open_handle(&blocker)?;
    let rename_attempt = root_file_rename(&file, "Archive")?;
    assert!(matches!(
        blocked_store.rename_namespace(&rename_attempt),
        Err(HandleError::SharingViolation)
    ));
    assert_rename_was_not_committed(&blocked_store, &file, &rename_attempt)?;

    let denied_directory = tempdir()?;
    let mut denied_store =
        VersionPublicationStore::open(denied_directory.path(), UnixMicros::new(1))?;
    denied_store.publish_root_file(&file)?;
    let mut denied = rename_open_request(&file, 164, 165)?;
    denied.desired_access = HandleAccess::new(true, false, false)?;
    denied.share_access = HandleShare::new(true, true, true);
    denied_store.open_handle(&denied)?;
    let mut denied_rename = root_file_rename(&file, "Archive")?;
    denied_rename.requesting_handle_id = Some(denied.handle_id);
    assert!(matches!(
        denied_store.rename_namespace(&denied_rename),
        Err(HandleError::InvalidInput)
    ));
    assert_rename_was_not_committed(&denied_store, &file, &denied_rename)?;
    Ok(())
}

#[test]
fn durable_affected_base_prepares_exact_replay_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let frontier = ReconciliationFrontier {
        converged_head: Some(first.namespace_commit_id),
        eligible_heads: vec![second.namespace_commit_id],
    };
    {
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&first)?;
        store.publish_root_file(&second)?;
    }

    let reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(2))?;
    let prepared = reopened
        .prepare_namespace_reconciliation(&frontier, ReconciliationLimits::DEFAULT)
        .map_err(|error| format!("prepare authored rename reconciliation: {error:?}"))?;
    assert_eq!(
        prepared.causal_plan().converged_head(),
        Some(first.namespace_commit_id)
    );
    assert_eq!(prepared.causal_plan().volume_id(), first.file.volume_id);
    assert_eq!(
        prepared.causal_plan().root_object_id(),
        first.root_object_id
    );
    assert_eq!(prepared.replay_plan().actions().len(), 1);
    let action = &prepared.replay_plan().actions()[0];
    assert_eq!(action.commit_id, second.namespace_commit_id);
    assert_eq!(action.disposition, NamespaceReplayDisposition::Applied);
    assert_eq!(action.target_path.components()[0].display(), "REPORT");
    assert_eq!(
        prepared.replay_plan().final_root_object_revision_id(),
        Some(second.root_object_revision_id)
    );
    Ok(())
}

#[test]
fn authored_rename_reconciles_atomically_from_its_durable_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = initial_root_publication()?;
    let sibling = sibling_root_publication(&file)?;
    let fork_branch = BranchId::from_bytes([170; 16])?;
    let mut rename = root_file_rename(&file, "Archive")?;
    rename.branch_id = fork_branch;
    {
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&file)?;
        seed_file_branch(&store.connection, &file, fork_branch)?;
        store.rename_namespace(&rename)?;
        store.publish_root_file(&sibling)?;
    }

    let frontier = ReconciliationFrontier {
        converged_head: Some(sibling.namespace_commit_id),
        eligible_heads: vec![rename.namespace_commit_id],
    };
    let application = NamespaceReconciliationApplication {
        operation_id: OperationId::from_bytes([171; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([172; 16])?,
        created_by: file.file.created_by,
        retain_superseded_history: true,
        retention_policy_sequence: 1,
        created_at: UnixMicros::new(171),
    };
    let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(2))?;
    let prepared =
        reopened.prepare_namespace_reconciliation(&frontier, ReconciliationLimits::DEFAULT)?;
    let action = prepared
        .replay_plan()
        .actions()
        .first()
        .ok_or("missing rename replay action")?;
    assert_eq!(action.target_path, rename.target.path().clone());
    assert_eq!(
        action
            .source_removal
            .as_ref()
            .map(|removal| removal.path.clone()),
        Some(rename.source.path().clone())
    );
    assert_eq!(prepared.causal_plan().merge_parents().len(), 2);
    assert!(prepared.causal_plan().converged_branch_id().is_some());
    assert!(
        prepared
            .replay_plan()
            .final_root_object_revision_id()
            .is_some()
    );
    let receipt = reopened
        .apply_namespace_reconciliation(application, &prepared)
        .map_err(|error| format!("apply authored rename reconciliation: {error:?}"))?;
    assert_eq!(receipt.disposition, PublicationDisposition::Applied);
    assert!(
        stored_directory_lookup(
            &reopened,
            receipt.root_object_revision_id,
            &rename.source.path().components()[0],
        )?
        .is_none()
    );
    let target = stored_directory_entry(
        &reopened,
        receipt.root_object_revision_id,
        &rename.target.path().components()[0],
    )?;
    assert_eq!(target.object_id(), file.file.object_id);
    assert_eq!(target.object_revision_id(), file.file_object_revision_id);
    let retained = stored_directory_entry(
        &reopened,
        receipt.root_object_revision_id,
        &sibling.path.path().components()[0],
    )?;
    assert_eq!(retained.object_id(), sibling.file.object_id);
    Ok(())
}

#[test]
fn durable_branch_heads_plan_identically_after_restart() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let mut second = initial_root_publication()?;
    second.file.operation_id = OperationId::from_bytes([80; 16])?;
    second.file.branch_id = BranchId::from_bytes([81; 16])?;
    second.file.object_id = ObjectId::from_bytes([82; 16])?;
    second.file.version_id = FileVersionId::from_bytes([83; 16])?;
    second.file.manifest.manifest_id = ContentManifestId::from_bytes([84; 16])?;
    second.file.manifest.content_digest = [85; 32];
    second.file.manifest.root_digest = [86; 32];
    second.file_object_revision_id = ObjectRevisionId::from_bytes([87; 16])?;
    second.root_object_revision_id = ObjectRevisionId::from_bytes([88; 16])?;
    second.namespace_commit_id = NamespaceCommitId::from_bytes([89; 16])?;
    second.path = NamespacePublicationPath::new(
        NamespacePath::from_components(["Other"], NamespaceLimits::PORTABLE)?,
        Vec::new(),
    )?;
    let frontier = ReconciliationFrontier {
        converged_head: None,
        eligible_heads: vec![first.namespace_commit_id, second.namespace_commit_id],
    };

    let expected = {
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&second)?;
        store.publish_root_file(&first)?;
        store.plan_reconciliation(&frontier, ReconciliationLimits::DEFAULT)?
    };
    let reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(2))?;
    let observed = reopened.plan_reconciliation(&frontier, ReconciliationLimits::DEFAULT)?;
    assert_eq!(observed, expected);
    assert_eq!(
        observed.ordered_commits(),
        [first.namespace_commit_id, second.namespace_commit_id]
    );
    assert_eq!(
        observed.merge_parents(),
        [first.namespace_commit_id, second.namespace_commit_id]
    );
    Ok(())
}

#[test]
fn divergent_roots_apply_one_atomic_merge_and_replay_its_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let mut second = initial_root_publication()?;
    second.file.operation_id = OperationId::from_bytes([80; 16])?;
    second.file.branch_id = BranchId::from_bytes([81; 16])?;
    second.file.object_id = ObjectId::from_bytes([82; 16])?;
    second.file.version_id = FileVersionId::from_bytes([83; 16])?;
    second.file.manifest.manifest_id = ContentManifestId::from_bytes([84; 16])?;
    second.file.manifest.content_digest = [85; 32];
    second.file.manifest.root_digest = [86; 32];
    second.file_object_revision_id = ObjectRevisionId::from_bytes([87; 16])?;
    second.root_object_revision_id = ObjectRevisionId::from_bytes([88; 16])?;
    second.namespace_commit_id = NamespaceCommitId::from_bytes([89; 16])?;
    second.path = NamespacePublicationPath::new(
        NamespacePath::from_components(["Other"], NamespaceLimits::PORTABLE)?,
        Vec::new(),
    )?;
    let frontier = ReconciliationFrontier {
        converged_head: Some(first.namespace_commit_id),
        eligible_heads: vec![second.namespace_commit_id],
    };
    let application = NamespaceReconciliationApplication {
        operation_id: OperationId::from_bytes([120; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([121; 16])?,
        created_by: first.file.created_by,
        retain_superseded_history: true,
        retention_policy_sequence: 1,
        created_at: UnixMicros::new(120),
    };
    let applied = {
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&first)?;
        store.publish_root_file(&second)?;
        let prepared =
            store.prepare_namespace_reconciliation(&frontier, ReconciliationLimits::DEFAULT)?;
        let receipt = store.apply_namespace_reconciliation(application, &prepared)?;
        assert_eq!(receipt.disposition, PublicationDisposition::Applied);
        receipt
    };

    let mut reopened = VersionPublicationStore::open(directory.path(), UnixMicros::new(2))?;
    let replayed = crate::NamespaceReconciliationReceipt {
        disposition: PublicationDisposition::Replayed,
        ..applied
    };
    assert_eq!(
        reopened.resolve_namespace_reconciliation(application.operation_id)?,
        Some(replayed)
    );
    prove_reconciliation_head_verification(&reopened, &first, replayed)?;
    let prepared =
        reopened.prepare_namespace_reconciliation(&frontier, ReconciliationLimits::DEFAULT)?;
    assert_eq!(
        reopened
            .apply_namespace_reconciliation(application, &prepared)?
            .disposition,
        PublicationDisposition::Replayed
    );
    let changed_policy = NamespaceReconciliationApplication {
        retain_superseded_history: false,
        ..application
    };
    assert!(matches!(
        reopened.apply_namespace_reconciliation(changed_policy, &prepared),
        Err(PublicationError::OperationConflict)
    ));
    let report = stored_directory_entry(
        &reopened,
        applied.root_object_revision_id,
        &first.path.path().components()[0],
    )?;
    let other = stored_directory_entry(
        &reopened,
        applied.root_object_revision_id,
        &second.path.path().components()[0],
    )?;
    assert_eq!(report.object_revision_id(), first.file_object_revision_id);
    assert_eq!(other.object_revision_id(), second.file_object_revision_id);

    let after_merge = ReconciliationFrontier {
        converged_head: Some(application.namespace_commit_id),
        eligible_heads: vec![second.namespace_commit_id],
    };
    let observed = reopened.plan_reconciliation(&after_merge, ReconciliationLimits::DEFAULT)?;
    assert!(observed.ordered_commits().is_empty());
    assert_eq!(observed.merge_parents(), [application.namespace_commit_id]);
    reopened.connection.execute(
        "UPDATE namespace_reconciliation_operations SET result_digest = zeroblob(32)
         WHERE operation_id = ?1",
        [application.operation_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        reopened.resolve_namespace_reconciliation(application.operation_id),
        Err(PublicationError::Corrupt)
    ));
    Ok(())
}

fn prove_reconciliation_head_verification(
    store: &VersionPublicationStore,
    first: &RootFilePublication,
    replayed: crate::NamespaceReconciliationReceipt,
) -> Result<(), Box<dyn std::error::Error>> {
    let verified = store.verify_reconciliation_head(
        first.file.volume_id,
        first.namespace_commit_id,
        replayed,
    )?;
    assert_eq!(verified.receipt(), replayed);
    assert_eq!(verified.volume_id(), first.file.volume_id);
    assert!(
        store
            .verify_reconciliation_head(
                first.file.volume_id,
                first.namespace_commit_id,
                crate::NamespaceReconciliationReceipt {
                    disposition: PublicationDisposition::Applied,
                    ..replayed
                },
            )
            .is_ok()
    );
    assert!(matches!(
        store.verify_reconciliation_head(
            VolumeId::from_bytes([122; 16])?,
            first.namespace_commit_id,
            replayed,
        ),
        Err(PublicationError::InvalidInput)
    ));
    assert!(matches!(
        store.verify_reconciliation_head(
            first.file.volume_id,
            NamespaceCommitId::from_bytes([123; 16])?,
            replayed,
        ),
        Err(PublicationError::InvalidInput)
    ));
    let substituted = crate::NamespaceReconciliationReceipt {
        result_digest: [124; 32],
        ..replayed
    };
    assert!(matches!(
        store.verify_reconciliation_head(
            first.file.volume_id,
            first.namespace_commit_id,
            substituted,
        ),
        Err(PublicationError::OperationConflict)
    ));
    Ok(())
}

#[test]
fn every_reconciliation_fault_rolls_back_root_merge_and_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let mut second = initial_root_publication()?;
    second.file.operation_id = OperationId::from_bytes([80; 16])?;
    second.file.branch_id = BranchId::from_bytes([81; 16])?;
    second.file.object_id = ObjectId::from_bytes([82; 16])?;
    second.file.version_id = FileVersionId::from_bytes([83; 16])?;
    second.file.manifest.manifest_id = ContentManifestId::from_bytes([84; 16])?;
    second.file.manifest.content_digest = [85; 32];
    second.file.manifest.root_digest = [86; 32];
    second.file_object_revision_id = ObjectRevisionId::from_bytes([87; 16])?;
    second.root_object_revision_id = ObjectRevisionId::from_bytes([88; 16])?;
    second.namespace_commit_id = NamespaceCommitId::from_bytes([89; 16])?;
    second.path = NamespacePublicationPath::new(
        NamespacePath::from_components(["Other"], NamespaceLimits::PORTABLE)?,
        Vec::new(),
    )?;
    let frontier = ReconciliationFrontier {
        converged_head: Some(first.namespace_commit_id),
        eligible_heads: vec![second.namespace_commit_id],
    };
    let application = NamespaceReconciliationApplication {
        operation_id: OperationId::from_bytes([120; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([121; 16])?,
        created_by: first.file.created_by,
        retain_superseded_history: true,
        retention_policy_sequence: 1,
        created_at: UnixMicros::new(120),
    };
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let prepared =
        store.prepare_namespace_reconciliation(&frontier, ReconciliationLimits::DEFAULT)?;
    let final_root = prepared
        .replay_plan()
        .final_root_object_revision_id()
        .ok_or("missing final root")?;
    for fault in [
        super::namespace::NamespaceFaultPoint::ReconciliationLeaf,
        super::namespace::NamespaceFaultPoint::ReconciliationDirectories,
        super::namespace::NamespaceFaultPoint::ReconciliationCommit,
        super::namespace::NamespaceFaultPoint::ReconciliationOperation,
    ] {
        assert!(matches!(
            super::namespace::apply_reconciliation_with_fault(
                &mut store.connection,
                application,
                &prepared,
                fault,
            ),
            Err(PublicationError::InjectedFault)
        ));
        assert_eq!(
            store.resolve_namespace_reconciliation(application.operation_id)?,
            None
        );
        let durable: i64 = store.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM object_revisions WHERE object_revision_id = ?1)",
            [final_root.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        assert_eq!(durable, 0);
    }
    let intent_digest = store
        .branch_mutation_intent(second.namespace_commit_id)?
        .ok_or("missing branch intent")?
        .digest();
    store.connection.execute(
        "UPDATE namespace_commit_intents SET intent_digest = zeroblob(32)
         WHERE namespace_commit_id = ?1",
        [second.namespace_commit_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        store.apply_namespace_reconciliation(application, &prepared),
        Err(PublicationError::Corrupt)
    ));
    store.connection.execute(
        "UPDATE namespace_commit_intents SET intent_digest = ?1
         WHERE namespace_commit_id = ?2",
        params![
            intent_digest.as_slice(),
            second.namespace_commit_id.as_bytes().as_slice(),
        ],
    )?;
    store.apply_namespace_reconciliation(application, &prepared)?;
    let durable: i64 = store.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM object_revisions WHERE object_revision_id = ?1)",
        [final_root.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(durable, 1);
    Ok(())
}

#[test]
fn concurrent_file_edits_materialise_one_owned_recovered_copy()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let first = initial_root_publication()?;
    let home = next_root_publication(&first)?;
    let fork_branch = BranchId::from_bytes([125; 16])?;
    let mut office = next_root_publication(&first)?;
    office.file.operation_id = OperationId::from_bytes([130; 16])?;
    office.file.branch_id = fork_branch;
    office.file.version_id = FileVersionId::from_bytes([131; 16])?;
    office.file.manifest.manifest_id = ContentManifestId::from_bytes([132; 16])?;
    office.file.manifest.content_digest = [133; 32];
    office.file.manifest.root_digest = [134; 32];
    office.file_object_revision_id = ObjectRevisionId::from_bytes([135; 16])?;
    office.root_object_revision_id = ObjectRevisionId::from_bytes([136; 16])?;
    office.namespace_commit_id = NamespaceCommitId::from_bytes([137; 16])?;
    let frontier = ReconciliationFrontier {
        converged_head: Some(first.namespace_commit_id),
        eligible_heads: vec![home.namespace_commit_id, office.namespace_commit_id],
    };
    let application = NamespaceReconciliationApplication {
        operation_id: OperationId::from_bytes([140; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([141; 16])?,
        created_by: first.file.created_by,
        retain_superseded_history: true,
        retention_policy_sequence: 1,
        created_at: UnixMicros::new(140),
    };
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&first)?;
    store.connection.execute(
        "INSERT INTO branch_namespace_heads(
            branch_id, volume_id, namespace_commit_id, head_sequence
         ) VALUES (?1, ?2, ?3, 1)",
        params![
            fork_branch.as_bytes().as_slice(),
            first.file.volume_id.as_bytes().as_slice(),
            first.namespace_commit_id.as_bytes().as_slice(),
        ],
    )?;
    store.connection.execute(
        "INSERT INTO branch_files(
            branch_id, object_id, volume_id, current_version_id, head_sequence
         ) VALUES (?1, ?2, ?3, ?4, 1)",
        params![
            fork_branch.as_bytes().as_slice(),
            first.file.object_id.as_bytes().as_slice(),
            first.file.volume_id.as_bytes().as_slice(),
            first.file.version_id.as_bytes().as_slice(),
        ],
    )?;
    store
        .publish_root_file(&office)
        .map_err(|error| format!("office publication: {error:?}"))?;
    store
        .publish_root_file(&home)
        .map_err(|error| format!("home publication: {error:?}"))?;
    let prepared = store
        .prepare_namespace_reconciliation(&frontier, ReconciliationLimits::DEFAULT)
        .map_err(|error| format!("prepare reconciliation: {error:?}"))?;
    let recovered = prepared
        .replay_plan()
        .actions()
        .iter()
        .find(|action| action.disposition == NamespaceReplayDisposition::Recovered)
        .ok_or("missing recovered action")?
        .clone();
    let receipt = store
        .apply_namespace_reconciliation(application, &prepared)
        .map_err(|error| format!("apply reconciliation: {error:?}"))?;

    assert_ne!(recovered.target_object_id, recovered.source_object_id);
    let recovered_version = recovered
        .target_file_version_id
        .ok_or("missing recovered file version")?;
    let stored_object: Vec<u8> = store.connection.query_row(
        "SELECT object_id FROM file_versions WHERE version_id = ?1",
        [recovered_version.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(
        stored_object.as_slice(),
        recovered.target_object_id.as_bytes()
    );
    let recovered_entry = stored_directory_entry(
        &store,
        receipt.root_object_revision_id,
        recovered
            .target_path
            .components()
            .last()
            .ok_or("missing recovered component")?,
    )?;
    assert_eq!(recovered_entry.object_id(), recovered.target_object_id);
    assert_eq!(
        recovered_entry.object_revision_id(),
        recovered.target_object_revision_id
    );
    assert_recovered_version_is_conflict_protected(&store, &recovered)?;
    Ok(())
}

fn assert_recovered_version_is_conflict_protected(
    store: &VersionPublicationStore,
    recovered: &crate::NamespaceReplayAction,
) -> Result<(), Box<dyn std::error::Error>> {
    let BranchMutation::File {
        version_id: source_version,
    } = recovered.mutation
    else {
        return Err("recovered action is not a file".into());
    };
    let count: i64 = store.connection.query_row(
        "SELECT count(*) FROM file_version_conflict_protections WHERE version_id = ?1",
        [source_version.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn branch_mutation_intents_round_trip_restart_and_reject_path_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = initial_root_publication()?;
    let expected = BranchMutationIntent {
        commit_id: file.namespace_commit_id,
        path: file.path.path().clone(),
        ancestors: Vec::new(),
        object_id: file.file.object_id,
        object_revision_id: file.file_object_revision_id,
        prior_object_revision_id: None,
        entry_generation: file.entry_generation,
        mutation: BranchMutation::File {
            version_id: file.file.version_id,
        },
        rename: None,
    };
    {
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&file)?;
        assert_eq!(
            store.branch_mutation_intent(file.namespace_commit_id)?,
            Some(expected.clone())
        );
    }
    let store = VersionPublicationStore::open(directory.path(), UnixMicros::new(2))?;
    assert_eq!(
        store.branch_mutation_intent(file.namespace_commit_id)?,
        Some(expected)
    );
    store.connection.execute(
        "UPDATE namespace_commit_path_components SET canonical_name = 'forged'
         WHERE namespace_commit_id = ?1 AND component_ordinal = 0",
        [file.namespace_commit_id.as_bytes().as_slice()],
    )?;
    assert!(matches!(
        store.branch_mutation_intent(file.namespace_commit_id),
        Err(PublicationError::Corrupt)
    ));
    Ok(())
}

#[test]
fn directory_commit_records_a_typed_replay_intent() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let publication = initial_directory_publication()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.create_directory(&publication)?;
    assert_eq!(
        store.branch_mutation_intent(publication.namespace_commit_id)?,
        Some(BranchMutationIntent {
            commit_id: publication.namespace_commit_id,
            path: publication.path.path().clone(),
            ancestors: Vec::new(),
            object_id: publication.directory_object_id,
            object_revision_id: publication.directory_object_revision_id,
            prior_object_revision_id: None,
            entry_generation: publication.entry_generation,
            mutation: BranchMutation::CreateDirectory,
            rename: None,
        })
    );
    Ok(())
}

#[test]
fn corrupt_namespace_receipt_commit_and_object_revision_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    for corrupt_sql in [
        "UPDATE namespace_publication_operations SET result_digest = zeroblob(32)",
        "UPDATE namespace_commits SET commit_digest = zeroblob(32)",
        "UPDATE object_revisions SET revision_digest = zeroblob(32) WHERE object_kind = 1",
    ] {
        let directory = tempdir()?;
        let first = initial_root_publication()?;
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&first)?;
        store.connection.execute(corrupt_sql, [])?;
        let detected = if corrupt_sql.contains("namespace_publication_operations") {
            store
                .resolve_namespace_publication(first.file.operation_id)
                .map(|_| ())
        } else {
            store
                .publish_root_file(&next_root_publication(&first)?)
                .map(|_| ())
        };
        assert!(matches!(detected, Err(PublicationError::Corrupt)));
    }
    Ok(())
}

#[test]
fn every_namespace_transaction_fault_rolls_back_all_heads_and_nodes()
-> Result<(), Box<dyn std::error::Error>> {
    use super::namespace::NamespaceFaultPoint;

    for fault in [
        NamespaceFaultPoint::DirectoryNodes,
        NamespaceFaultPoint::FileVersion,
        NamespaceFaultPoint::ObjectRevisions,
        NamespaceFaultPoint::NamespaceCommit,
        NamespaceFaultPoint::Heads,
        NamespaceFaultPoint::Operation,
    ] {
        let directory = tempdir()?;
        let publication = initial_root_publication()?;
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        assert!(matches!(
            super::namespace::publish(&mut store.connection, &publication, Some(fault)),
            Err(PublicationError::InjectedFault)
        ));
        assert_eq!(
            store.namespace_head(publication.file.branch_id, publication.file.volume_id)?,
            None
        );
        assert_eq!(
            super::load_file_head(
                &store.connection,
                publication.file.branch_id,
                publication.file.object_id,
            )?,
            None
        );
        assert_eq!(
            store.resolve_namespace_publication(publication.file.operation_id)?,
            None
        );
        let node_count: i64 =
            store
                .connection
                .query_row("SELECT COUNT(*) FROM directory_nodes", [], |row| row.get(0))?;
        assert_eq!(node_count, 0);
        assert_eq!(
            store.publish_root_file(&publication)?.disposition,
            PublicationDisposition::Applied
        );
    }
    Ok(())
}

#[test]
fn every_directory_transaction_fault_rolls_back_head_nodes_and_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    use super::namespace::NamespaceFaultPoint;

    for fault in [
        NamespaceFaultPoint::DirectoryNodes,
        NamespaceFaultPoint::ObjectRevisions,
        NamespaceFaultPoint::NamespaceCommit,
        NamespaceFaultPoint::Heads,
        NamespaceFaultPoint::Operation,
    ] {
        let directory = tempdir()?;
        let publication = initial_directory_publication()?;
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        assert!(matches!(
            super::namespace::create_directory(&mut store.connection, &publication, Some(fault)),
            Err(PublicationError::InjectedFault)
        ));
        assert_eq!(
            store.namespace_head(publication.branch_id, publication.volume_id)?,
            None
        );
        assert_eq!(
            store.resolve_directory_publication(publication.operation_id)?,
            None
        );
        let node_count: i64 =
            store
                .connection
                .query_row("SELECT COUNT(*) FROM directory_nodes", [], |row| row.get(0))?;
        assert_eq!(node_count, 0);
        assert_eq!(
            store.create_directory(&publication)?.disposition,
            PublicationDisposition::Applied
        );
    }
    Ok(())
}

#[test]
fn directory_receipt_corruption_and_cross_kind_operation_reuse_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let created = initial_directory_publication()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.create_directory(&created)?;
    store.connection.execute(
        "UPDATE directory_publication_operations SET result_digest = zeroblob(32)",
        [],
    )?;
    assert!(matches!(
        store.resolve_directory_publication(created.operation_id),
        Err(PublicationError::Corrupt)
    ));

    let separate = tempdir()?;
    let mut store = VersionPublicationStore::open(separate.path(), UnixMicros::new(1))?;
    let file = initial_root_publication()?;
    store.publish_root_file(&file)?;
    let mut conflicting = initial_directory_publication()?;
    conflicting.operation_id = file.file.operation_id;
    assert!(matches!(
        store.create_directory(&conflicting),
        Err(PublicationError::OperationConflict)
    ));
    Ok(())
}

#[test]
fn rename_receipt_corruption_and_cross_kind_operation_reuse_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let corrupted_directory = tempdir()?;
    let file = initial_root_publication()?;
    let rename = root_file_rename(&file, "Archive")?;
    let mut corrupted =
        VersionPublicationStore::open(corrupted_directory.path(), UnixMicros::new(1))?;
    corrupted.publish_root_file(&file)?;
    corrupted.rename_namespace(&rename)?;
    corrupted.connection.execute(
        "UPDATE namespace_rename_operations SET result_digest = zeroblob(32)",
        [],
    )?;
    assert!(matches!(
        corrupted.resolve_namespace_rename(rename.operation_id),
        Err(PublicationError::Corrupt)
    ));

    let file_collision_directory = tempdir()?;
    let mut file_collision =
        VersionPublicationStore::open(file_collision_directory.path(), UnixMicros::new(1))?;
    file_collision.publish_root_file(&file)?;
    let mut colliding_rename = rename.clone();
    colliding_rename.operation_id = file.file.operation_id;
    assert!(matches!(
        file_collision.rename_namespace(&colliding_rename),
        Err(HandleError::Namespace(PublicationError::OperationConflict))
    ));

    let rename_collision_directory = tempdir()?;
    let mut rename_collision =
        VersionPublicationStore::open(rename_collision_directory.path(), UnixMicros::new(1))?;
    rename_collision.publish_root_file(&file)?;
    rename_collision.rename_namespace(&rename)?;
    let mut colliding_file = sibling_root_publication(&file)?;
    colliding_file.file.operation_id = rename.operation_id;
    assert!(matches!(
        rename_collision.publish_root_file(&colliding_file),
        Err(PublicationError::OperationConflict)
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
        retain_superseded_history: true,
        retention_policy_sequence: 1,
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

fn mutation_records(
    trie: &DirectoryTrie,
    digests: &[crate::DirectoryNodeDigest],
) -> Result<Vec<DirectoryNodeRecord>, DirectoryTrieError> {
    digests.iter().map(|digest| trie.record(*digest)).collect()
}

fn stored_directory_entry(
    store: &VersionPublicationStore,
    revision_id: ObjectRevisionId,
    name: &NamespaceComponent,
) -> Result<DirectoryEntry, Box<dyn std::error::Error>> {
    stored_directory_lookup(store, revision_id, name)?
        .ok_or_else(|| "missing directory entry".into())
}

fn stored_directory_lookup(
    store: &VersionPublicationStore,
    revision_id: ObjectRevisionId,
    name: &NamespaceComponent,
) -> Result<Option<DirectoryEntry>, Box<dyn std::error::Error>> {
    let root_bytes: Vec<u8> = store.connection.query_row(
        "SELECT directory_root_digest FROM object_revisions
         WHERE object_revision_id = ?1 AND object_kind = 1",
        [revision_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let root = crate::DirectoryNodeDigest::from_bytes(super::copy_array(&root_bytes)?);
    let mut selected = root;
    let mut records = Vec::new();
    for depth in 0..=64 {
        let record = store
            .directory_node(selected)?
            .ok_or("missing directory node")?;
        let child = record.selected_child(name, depth)?;
        records.push(record);
        let Some(child) = child else {
            break;
        };
        selected = child;
    }
    Ok(DirectoryTrie::from_selected_records(root, records, name)?.lookup(name)?)
}

fn initial_directory_publication() -> Result<DirectoryPublication, Box<dyn std::error::Error>> {
    Ok(DirectoryPublication {
        operation_id: OperationId::from_bytes([90; 16])?,
        branch_id: BranchId::from_bytes([91; 16])?,
        volume_id: VolumeId::from_bytes([92; 16])?,
        root_object_id: ObjectId::from_bytes([93; 16])?,
        expected_namespace_commit_id: None,
        directory_object_id: ObjectId::from_bytes([94; 16])?,
        directory_object_revision_id: ObjectRevisionId::from_bytes([95; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([96; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([97; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["a"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
        created_by: PrincipalId::from_bytes([98; 16])?,
        created_at: UnixMicros::new(2),
    })
}

fn nested_directory_publication(
    first: &DirectoryPublication,
) -> Result<DirectoryPublication, Box<dyn std::error::Error>> {
    Ok(DirectoryPublication {
        operation_id: OperationId::from_bytes([99; 16])?,
        branch_id: first.branch_id,
        volume_id: first.volume_id,
        root_object_id: first.root_object_id,
        expected_namespace_commit_id: Some(first.namespace_commit_id),
        directory_object_id: ObjectId::from_bytes([100; 16])?,
        directory_object_revision_id: ObjectRevisionId::from_bytes([101; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([102; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([103; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["a", "b"], NamespaceLimits::PORTABLE)?,
            vec![DirectoryRevisionTransition::new(
                first.directory_object_id,
                first.directory_object_revision_id,
                ObjectRevisionId::from_bytes([104; 16])?,
            )?],
        )?,
        entry_generation: 1,
        created_by: first.created_by,
        created_at: UnixMicros::new(3),
    })
}

fn nested_file_publication(
    first: &DirectoryPublication,
    second: &DirectoryPublication,
) -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    Ok(RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([105; 16])?,
            branch_id: first.branch_id,
            volume_id: first.volume_id,
            object_id: ObjectId::from_bytes([106; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([107; 16])?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes([108; 16])?,
                format_version: 1,
                logical_length: 7,
                content_digest: [109; 32],
                root_digest: [110; 32],
            },
            created_by: first.created_by,
            created_at: UnixMicros::new(4),
        },
        root_object_id: first.root_object_id,
        expected_namespace_commit_id: Some(second.namespace_commit_id),
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([111; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([112; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([113; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["a", "b", "report"], NamespaceLimits::PORTABLE)?,
            vec![
                DirectoryRevisionTransition::new(
                    first.directory_object_id,
                    second.path.ancestors()[0].new_revision_id(),
                    ObjectRevisionId::from_bytes([114; 16])?,
                )?,
                DirectoryRevisionTransition::new(
                    second.directory_object_id,
                    second.directory_object_revision_id,
                    ObjectRevisionId::from_bytes([115; 16])?,
                )?,
            ],
        )?,
        entry_generation: 1,
    })
}

fn root_file_rename(
    file: &RootFilePublication,
    target: &str,
) -> Result<NamespaceRenamePublication, Box<dyn std::error::Error>> {
    Ok(NamespaceRenamePublication {
        operation_id: OperationId::from_bytes([150; 16])?,
        branch_id: file.file.branch_id,
        volume_id: file.file.volume_id,
        root_object_id: file.root_object_id,
        expected_namespace_commit_id: file.namespace_commit_id,
        expected_object_id: file.file.object_id,
        expected_object_revision_id: file.file_object_revision_id,
        expected_source_entry_generation: file.entry_generation,
        source: file.path.clone(),
        intermediate_root_object_revision_id: ObjectRevisionId::from_bytes([151; 16])?,
        target: NamespacePublicationPath::new(
            NamespacePath::from_components([target], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        target_entry_generation: 1,
        root_object_revision_id: ObjectRevisionId::from_bytes([152; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([153; 16])?,
        requesting_handle_id: None,
        created_by: file.file.created_by,
        created_at: UnixMicros::new(150),
    })
}

fn root_directory_rename(
    directory: &DirectoryPublication,
    target: &str,
) -> Result<NamespaceRenamePublication, Box<dyn std::error::Error>> {
    Ok(NamespaceRenamePublication {
        operation_id: OperationId::from_bytes([180; 16])?,
        branch_id: directory.branch_id,
        volume_id: directory.volume_id,
        root_object_id: directory.root_object_id,
        expected_namespace_commit_id: directory.namespace_commit_id,
        expected_object_id: directory.directory_object_id,
        expected_object_revision_id: directory.directory_object_revision_id,
        expected_source_entry_generation: directory.entry_generation,
        source: directory.path.clone(),
        intermediate_root_object_revision_id: ObjectRevisionId::from_bytes([181; 16])?,
        target: NamespacePublicationPath::new(
            NamespacePath::from_components([target], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        target_entry_generation: 1,
        root_object_revision_id: ObjectRevisionId::from_bytes([182; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([183; 16])?,
        requesting_handle_id: None,
        created_by: directory.created_by,
        created_at: UnixMicros::new(180),
    })
}

fn descendant_directory_rename(
    first: &DirectoryPublication,
    nested: &DirectoryPublication,
) -> Result<NamespaceRenamePublication, Box<dyn std::error::Error>> {
    let current_source_revision = nested.path.ancestors()[0].new_revision_id();
    Ok(NamespaceRenamePublication {
        operation_id: OperationId::from_bytes([184; 16])?,
        branch_id: first.branch_id,
        volume_id: first.volume_id,
        root_object_id: first.root_object_id,
        expected_namespace_commit_id: nested.namespace_commit_id,
        expected_object_id: first.directory_object_id,
        expected_object_revision_id: current_source_revision,
        expected_source_entry_generation: first.entry_generation,
        source: first.path.clone(),
        intermediate_root_object_revision_id: ObjectRevisionId::from_bytes([185; 16])?,
        target: NamespacePublicationPath::new(
            NamespacePath::from_components(["a", "b", "moved"], NamespaceLimits::PORTABLE)?,
            vec![
                DirectoryRevisionTransition::new(
                    first.directory_object_id,
                    current_source_revision,
                    ObjectRevisionId::from_bytes([186; 16])?,
                )?,
                DirectoryRevisionTransition::new(
                    nested.directory_object_id,
                    nested.directory_object_revision_id,
                    ObjectRevisionId::from_bytes([187; 16])?,
                )?,
            ],
        )?,
        target_entry_generation: 1,
        root_object_revision_id: ObjectRevisionId::from_bytes([188; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([189; 16])?,
        requesting_handle_id: None,
        created_by: first.created_by,
        created_at: UnixMicros::new(184),
    })
}

fn sibling_root_publication(
    first: &RootFilePublication,
) -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    Ok(RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([140; 16])?,
            branch_id: first.file.branch_id,
            volume_id: first.file.volume_id,
            object_id: ObjectId::from_bytes([141; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([142; 16])?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes([143; 16])?,
                format_version: 1,
                logical_length: 8,
                content_digest: [144; 32],
                root_digest: [145; 32],
            },
            created_by: first.file.created_by,
            created_at: UnixMicros::new(140),
        },
        root_object_id: first.root_object_id,
        expected_namespace_commit_id: Some(first.namespace_commit_id),
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([146; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([147; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([148; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["Taken"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })
}

fn expected_rename_intent(
    file: &RootFilePublication,
    rename: &NamespaceRenamePublication,
) -> BranchMutationIntent {
    BranchMutationIntent {
        commit_id: rename.namespace_commit_id,
        path: rename.target.path().clone(),
        ancestors: rename.target.ancestors().to_vec(),
        object_id: file.file.object_id,
        object_revision_id: file.file_object_revision_id,
        prior_object_revision_id: None,
        entry_generation: rename.target_entry_generation,
        mutation: BranchMutation::File {
            version_id: file.file.version_id,
        },
        rename: Some(BranchRenameIntent {
            source_path: rename.source.path().clone(),
            source_ancestors: rename.source.ancestors().to_vec(),
            source_entry_generation: rename.expected_source_entry_generation,
            intermediate_root_object_revision_id: rename.intermediate_root_object_revision_id,
        }),
    }
}

fn assert_namespace_rename_result(
    store: &VersionPublicationStore,
    file: &RootFilePublication,
    rename: &NamespaceRenamePublication,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        store
            .namespace_head(rename.branch_id, rename.volume_id)?
            .map(|head| (head.namespace_commit_id, head.sequence)),
        Some((rename.namespace_commit_id, 2))
    );
    assert!(
        stored_directory_lookup(
            store,
            rename.root_object_revision_id,
            &rename.source.path().components()[0],
        )?
        .is_none()
    );
    let target = stored_directory_lookup(
        store,
        rename.root_object_revision_id,
        &rename.target.path().components()[0],
    )?
    .ok_or("missing rename target")?;
    assert_eq!(target.object_id(), file.file.object_id);
    assert_eq!(target.object_revision_id(), file.file_object_revision_id);
    assert_eq!(target.generation(), rename.target_entry_generation);
    Ok(())
}

fn assert_rename_was_not_committed(
    store: &VersionPublicationStore,
    base: &RootFilePublication,
    rename: &NamespaceRenamePublication,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        store
            .namespace_head(rename.branch_id, rename.volume_id)?
            .map(|head| head.namespace_commit_id),
        Some(base.namespace_commit_id)
    );
    let source = stored_directory_entry(
        store,
        base.root_object_revision_id,
        &rename.source.path().components()[0],
    )?;
    assert_eq!(source.object_id(), rename.expected_object_id);
    assert_eq!(store.resolve_namespace_rename(rename.operation_id)?, None);
    for revision_id in [
        rename.intermediate_root_object_revision_id,
        rename.root_object_revision_id,
    ] {
        let exists: i64 = store.connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM object_revisions WHERE object_revision_id = ?1
             )",
            [revision_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        assert_eq!(exists, 0);
    }
    Ok(())
}

fn rename_open_request(
    file: &RootFilePublication,
    operation: u8,
    handle: u8,
) -> Result<OpenHandleRequest, Box<dyn std::error::Error>> {
    Ok(OpenHandleRequest {
        operation_id: OperationId::from_bytes([operation; 16])?,
        handle_id: HandleId::from_bytes([handle; 16])?,
        branch_id: file.file.branch_id,
        volume_id: file.file.volume_id,
        path: file.path.path().clone(),
        principal_id: file.file.created_by,
        authorization_revision: Revision::new(1),
        gateway_node_id: NodeId::from_bytes([166; 16])?,
        desired_access: HandleAccess::new(true, false, false)?,
        share_access: HandleShare::new(true, true, true),
        create_disposition: CreateDisposition::OpenExisting,
        delete_on_close: false,
        lease_expires_at: UnixMicros::new(1_000),
        opened_at: UnixMicros::new(10),
    })
}

fn seed_file_branch(
    connection: &Connection,
    file: &RootFilePublication,
    branch_id: BranchId,
) -> Result<(), Box<dyn std::error::Error>> {
    connection.execute(
        "INSERT INTO branch_namespace_heads(
            branch_id, volume_id, namespace_commit_id, head_sequence
         ) VALUES (?1, ?2, ?3, 1)",
        params![
            branch_id.as_bytes().as_slice(),
            file.file.volume_id.as_bytes().as_slice(),
            file.namespace_commit_id.as_bytes().as_slice(),
        ],
    )?;
    connection.execute(
        "INSERT INTO branch_files(
            branch_id, object_id, volume_id, current_version_id, head_sequence
         ) VALUES (?1, ?2, ?3, ?4, 1)",
        params![
            branch_id.as_bytes().as_slice(),
            file.file.object_id.as_bytes().as_slice(),
            file.file.volume_id.as_bytes().as_slice(),
            file.file.version_id.as_bytes().as_slice(),
        ],
    )?;
    Ok(())
}

fn initial_root_publication() -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    Ok(RootFilePublication {
        file: make_publication(60, None, 61)?,
        root_object_id: ObjectId::from_bytes([62; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([63; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([64; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([65; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["Report"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })
}

fn next_root_publication(
    previous: &RootFilePublication,
) -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    let mut file = make_publication(70, Some(previous.file.version_id), 71)?;
    file.created_at = UnixMicros::new(70);
    Ok(RootFilePublication {
        file,
        root_object_id: previous.root_object_id,
        expected_namespace_commit_id: Some(previous.namespace_commit_id),
        expected_file_object_revision_id: Some(previous.file_object_revision_id),
        file_object_revision_id: ObjectRevisionId::from_bytes([72; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([73; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([74; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["REPORT"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })
}

fn following_root_publication(
    previous: &RootFilePublication,
    operation: u8,
    version: u8,
    file_revision: u8,
    root_revision: u8,
    commit_id: u8,
) -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    let mut file = make_publication(operation, Some(previous.file.version_id), version)?;
    file.created_at = UnixMicros::new(i64::from(operation));
    Ok(RootFilePublication {
        file,
        root_object_id: previous.root_object_id,
        expected_namespace_commit_id: Some(previous.namespace_commit_id),
        expected_file_object_revision_id: Some(previous.file_object_revision_id),
        file_object_revision_id: ObjectRevisionId::from_bytes([file_revision; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([root_revision; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([commit_id; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["report"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })
}

fn snapshot_restore_publication(
    snapshot: &RootFilePublication,
    current: &RootFilePublication,
) -> Result<SnapshotRestorePublication, Box<dyn std::error::Error>> {
    Ok(SnapshotRestorePublication {
        operation_id: OperationId::from_bytes([120; 16])?,
        branch_id: current.file.branch_id,
        volume_id: current.file.volume_id,
        snapshot_id: SnapshotId::from_bytes([121; 16])?,
        snapshot_namespace_commit_id: snapshot.namespace_commit_id,
        expected_namespace_commit_id: current.namespace_commit_id,
        root_object_id: current.root_object_id,
        root_object_revision_id: snapshot.root_object_revision_id,
        namespace_commit_id: NamespaceCommitId::from_bytes([122; 16])?,
        created_by: current.file.created_by,
        created_at: UnixMicros::new(130),
    })
}
