// SPDX-License-Identifier: GPL-2.0-only

//! Restored roots transfer as immutable evidence, never as a new restore authorisation.

use super::*;

#[test]
fn restored_history_round_trips_without_activating_the_destination()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let destination = tempdir()?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    let restore = snapshot_restore_publication(&first, &second)?;
    let mut source = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    source.publish_root_file(&first)?;
    source.publish_root_file(&second)?;
    let receipt = source.prepare_snapshot_restore(restore)?;
    source.activate_snapshot_restore(receipt, UnixMicros::new(131))?;
    let bundle = source.export_namespace_history(
        first.file.volume_id,
        &[restore.namespace_commit_id],
        &[],
        NamespaceHistoryLimits::DEFAULT,
    )?;
    let mut target = VersionPublicationStore::open(destination.path(), UnixMicros::new(140))?;
    assert_eq!(
        target
            .import_namespace_history(&bundle, NamespaceHistoryLimits::DEFAULT)?
            .imported_commits,
        3
    );
    assert_eq!(
        target.namespace_head(first.file.branch_id, first.file.volume_id)?,
        None
    );
    drop(target);
    let mut target = VersionPublicationStore::open(destination.path(), UnixMicros::new(141))?;
    let retained = target
        .resolve_snapshot_restore(restore.operation_id)?
        .ok_or("restore evidence missing")?;
    assert_eq!(retained.result_digest, receipt.result_digest);
    assert_eq!(
        target
            .import_namespace_history(&bundle, NamespaceHistoryLimits::DEFAULT)?
            .imported_commits,
        0
    );
    assert_eq!(
        target
            .export_namespace_history(
                first.file.volume_id,
                &[restore.namespace_commit_id],
                &[],
                NamespaceHistoryLimits::DEFAULT
            )?
            .commit_records()?,
        bundle.commit_records()?
    );
    for record in bundle.commit_records()? {
        if record.decoded()?.commit.commit_id != restore.namespace_commit_id {
            continue;
        }
        assert!(record.mutation_authority().is_err());
        assert!(record.mutation_digest().is_err());
        assert_eq!(record.federated_acknowledgement()?, None);
        let mut bytes = record.canonical_bytes().to_vec();
        *bytes.last_mut().ok_or("empty restore record")? ^= 1;
        assert!(super::super::NamespaceHistoryCommitRecord::from_canonical_bytes(bytes).is_err());
    }
    Ok(())
}

#[test]
fn paged_restore_includes_non_ancestor_snapshot_and_remains_writable()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = isolated_history_fixture()?;
    let destination = tempdir()?;
    let remote = fixture.open_office()?.export_namespace_history(
        fixture.first.file.volume_id,
        &[fixture.office.namespace_commit_id],
        &[fixture.first.namespace_commit_id],
        NamespaceHistoryLimits::DEFAULT,
    )?;
    let mut source = fixture.open_home()?;
    source.import_namespace_history(&remote, NamespaceHistoryLimits::DEFAULT)?;
    let restore = snapshot_restore_publication(&fixture.office, &fixture.home)?;
    let receipt = source.prepare_snapshot_restore(restore)?;
    source.activate_snapshot_restore(receipt, UnixMicros::new(131))?;
    drop(source);
    transfer_pages(&fixture.home_directory, &destination, restore)?;
    let mut target = VersionPublicationStore::open(destination.path(), UnixMicros::new(150))?;
    let branch = BranchId::from_bytes([180; 16])?;
    assert_eq!(target.namespace_head(branch, restore.volume_id)?, None);
    // Import cannot turn an off-head prepared restore into an ordinary local edit.
    assert!(matches!(
        target.plan_reconciliation(
            &crate::ReconciliationFrontier {
                converged_head: Some(fixture.home.namespace_commit_id),
                eligible_heads: vec![restore.namespace_commit_id],
            },
            crate::ReconciliationLimits::DEFAULT
        ),
        Err(crate::ReconciliationStoreError::Planning(
            crate::ReconciliationError::UncommittedRestore
        ))
    ));
    target.adopt_imported_namespace_head(
        branch,
        restore.volume_id,
        restore.namespace_commit_id,
        restore.root_object_revision_id,
    )?;
    let mut directory = initial_directory_publication()?;
    directory.branch_id = branch;
    directory.volume_id = restore.volume_id;
    directory.root_object_id = restore.root_object_id;
    directory.expected_namespace_commit_id = Some(restore.namespace_commit_id);
    let created = target.create_directory(&directory)?;
    target.plan_reconciliation(
        &crate::ReconciliationFrontier {
            converged_head: Some(restore.namespace_commit_id),
            eligible_heads: vec![created.namespace_commit_id],
        },
        crate::ReconciliationLimits::DEFAULT,
    )?;
    drop(target);
    let target = VersionPublicationStore::open(destination.path(), UnixMicros::new(151))?;
    assert_eq!(
        target
            .namespace_head(branch, restore.volume_id)?
            .ok_or("head missing")?
            .namespace_commit_id,
        created.namespace_commit_id
    );
    assert_eq!(
        stored_directory_entry(
            &target,
            directory.root_object_revision_id,
            &fixture.office.path.path().components()[0]
        )?
        .object_revision_id(),
        fixture.office.file_object_revision_id
    );
    Ok(())
}

fn transfer_pages(
    source: &TempDir,
    destination: &TempDir,
    restore: SnapshotRestorePublication,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = NamespaceHistoryReceiveRequest {
        session_id: [230; 32],
        scope_binding: [231; 32],
        volume_id: restore.volume_id,
        requested_heads: vec![restore.namespace_commit_id],
        limits: NamespaceHistoryLimits::DEFAULT,
        now: UnixMicros::new(140),
        expires_at: UnixMicros::new(200),
    };
    VersionPublicationStore::open(destination.path(), request.now)?
        .begin_namespace_history_receive(&request)?;
    let mut cursor = Vec::new();
    loop {
        // Reopen both ends on every page: durable continuation, not retained process state.
        let mut source = VersionPublicationStore::open(source.path(), request.now)?;
        let page = source.namespace_history_page(NamespaceHistoryPageRequest {
            scope_binding: request.scope_binding,
            volume_id: request.volume_id,
            requested_heads: request.requested_heads.clone(),
            known_commits: Vec::new(),
            cursor: cursor.clone(),
            limit: 2,
            now: request.now,
            expires_at: request.expires_at,
        })?;
        let mut target = VersionPublicationStore::open(destination.path(), request.now)?;
        let accepted = target.receive_namespace_history_page(
            request.session_id,
            &cursor,
            &page,
            request.now,
        )?;
        for digest in page.immutable_object_digests {
            let object = source.namespace_history_object(NamespaceHistoryObjectRequest {
                scope_binding: request.scope_binding,
                export_token: page.export_token,
                object_digest: digest,
                now: request.now,
            })?;
            target.receive_namespace_history_object(request.session_id, &object, request.now)?;
        }
        cursor = accepted.next_cursor;
        if accepted.terminal {
            break;
        }
    }
    let completed = VersionPublicationStore::open(destination.path(), request.now)?
        .complete_namespace_history_receive(request.session_id, request.now)?;
    assert_eq!(completed.import.imported_commits, 4);
    Ok(())
}

#[test]
fn missing_restore_snapshot_dependency_rolls_back_the_entire_import()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = isolated_history_fixture()?;
    let destination = tempdir()?;
    let mut source = fixture.open_home()?;
    let remote = fixture.open_office()?.export_namespace_history(
        fixture.first.file.volume_id,
        &[fixture.office.namespace_commit_id],
        &[fixture.first.namespace_commit_id],
        NamespaceHistoryLimits::DEFAULT,
    )?;
    source.import_namespace_history(&remote, NamespaceHistoryLimits::DEFAULT)?;
    let restore = snapshot_restore_publication(&fixture.office, &fixture.home)?;
    source.prepare_snapshot_restore(restore)?;
    let mut bundle = source.export_namespace_history(
        restore.volume_id,
        &[restore.namespace_commit_id],
        &[],
        NamespaceHistoryLimits::DEFAULT,
    )?;
    bundle
        .commits
        .retain(|record| record.commit.commit_id != fixture.office.namespace_commit_id);
    let mut target = VersionPublicationStore::open(destination.path(), UnixMicros::new(140))?;
    assert!(matches!(
        target.import_namespace_history(&bundle, NamespaceHistoryLimits::DEFAULT),
        Err(PublicationError::InvalidInput)
    ));
    drop(target);
    let target = VersionPublicationStore::open(destination.path(), UnixMicros::new(141))?;
    for commit in [
        fixture.first.namespace_commit_id,
        fixture.home.namespace_commit_id,
        restore.namespace_commit_id,
    ] {
        assert!(!commit_exists(&target.connection, commit)?);
    }
    assert!(!file_version_exists(
        &target.connection,
        fixture.office.file.version_id
    )?);
    Ok(())
}
