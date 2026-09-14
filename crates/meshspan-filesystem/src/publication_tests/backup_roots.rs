// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn backup_root_schema_migration_preserves_existing_scan() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let connection = Connection::open(directory.path().join(DATABASE_FILE))?;
    configure(&connection)?;
    for migration in &MIGRATIONS[..44] {
        connection.execute_batch(migration.sql)?;
        let digest = blake3::hash(migration.sql.as_bytes());
        connection.execute(
            "INSERT INTO schema_migrations VALUES (?1, ?2, 1)",
            params![migration.version, digest.as_bytes().as_slice()],
        )?;
    }
    connection.pragma_update(None, "user_version", 44)?;
    let mut store = VersionPublicationStore { connection };
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let policy = eager_retention_policy()?;
    let candidate = retention_candidate(&store, first.file.volume_id, policy)?;
    let roots = vec![publication_root(&second)];
    let request = reachability_request(candidate, policy, &roots, 171)?;
    store.begin_version_reachability_scan(&request)?;
    store.append_version_reachability_roots(&ReachabilityRootPage {
        operation_id: request.operation_id,
        start_ordinal: 0,
        roots,
    })?;
    drop(store);
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(122))?;
    let progress =
        store.seal_version_reachability_roots(request.operation_id, UnixMicros::new(122))?;
    let progress = finish_reachability_scan(&mut store, request.operation_id, progress, 1)?;
    assert_eq!(progress.state, VersionReachabilityState::Unreachable);
    assert!(progress.proof.is_some());
    Ok(())
}

#[test]
fn backup_root_prevents_cleanup_after_restart() -> Result<(), Box<dyn std::error::Error>> {
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
            source: ReachabilityRootSource::Backup(first.namespace_commit_id),
            namespace_commit_id: first.namespace_commit_id,
            root_object_revision_id: first.root_object_revision_id,
        },
    ];
    let request = reachability_request(candidate, policy, &roots, 171)?;
    store.begin_version_reachability_scan(&request)?;
    let mut substituted = roots.clone();
    substituted[1].source = ReachabilityRootSource::Backup(second.namespace_commit_id);
    assert!(matches!(
        store.append_version_reachability_roots(&ReachabilityRootPage {
            operation_id: request.operation_id,
            start_ordinal: 0,
            roots: substituted,
        }),
        Err(VersionReachabilityError::InvalidInput)
    ));
    store.append_version_reachability_roots(&ReachabilityRootPage {
        operation_id: request.operation_id,
        start_ordinal: 0,
        roots,
    })?;
    drop(store);
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(122))?;
    let progress =
        store.seal_version_reachability_roots(request.operation_id, UnixMicros::new(122))?;
    let progress = finish_reachability_scan(&mut store, request.operation_id, progress, 1)?;
    assert_eq!(progress.state, VersionReachabilityState::Reachable);
    assert!(progress.proof.is_none());
    Ok(())
}
