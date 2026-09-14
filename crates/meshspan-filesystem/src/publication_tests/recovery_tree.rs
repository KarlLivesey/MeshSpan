// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn recovery_tree_selects_current_files_without_ancestral_versions()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let manifests = collect_tree_manifests(&mut store, &second)?;
    assert_eq!(manifests, vec![second.file.manifest]);
    // A separately retained older root still selects its older version.
    assert_eq!(
        collect_tree_manifests(&mut store, &first)?,
        vec![first.file.manifest]
    );
    Ok(())
}

#[test]
fn recovery_tree_cursor_survives_restart_and_cannot_resume_causal_history()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let publication = initial_root_publication()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    store.publish_root_file(&publication)?;
    let request = tree_request(&publication, Vec::new());
    let first = store.namespace_retained_tree_page(request.clone())?;
    assert!(!first.next_cursor.is_empty());
    assert_eq!(store.namespace_retained_tree_page(request.clone())?, first);
    let ordinary = store.namespace_history_page(request)?;
    assert_ne!(ordinary.export_token, first.export_token);
    assert!(
        store
            .namespace_history_page(tree_request(&publication, first.next_cursor.clone()))
            .is_err()
    );
    assert!(
        store
            .namespace_retained_tree_page(tree_request(&publication, ordinary.next_cursor))
            .is_err()
    );
    drop(store);
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(101))?;
    let resumed = store
        .namespace_retained_tree_page(tree_request(&publication, first.next_cursor.clone()))?;
    assert_eq!(resumed.export_token, first.export_token);
    assert!(resumed.commits.is_empty());
    assert!(!resumed.immutable_object_digests.is_empty());
    let mut changed = tree_request(&publication, first.next_cursor.clone());
    changed.scope_binding = [92; 32];
    assert!(store.namespace_retained_tree_page(changed).is_err());
    let mut changed = tree_request(&publication, first.next_cursor);
    changed.known_commits.push(publication.namespace_commit_id);
    assert!(matches!(
        store.namespace_retained_tree_page(changed),
        Err(PublicationError::InvalidInput)
    ));
    let mut wrong_volume = tree_request(&publication, Vec::new());
    wrong_volume.volume_id = VolumeId::from_bytes([90; 16])?;
    assert!(store.namespace_retained_tree_page(wrong_volume).is_err());
    Ok(())
}

#[test]
fn recovery_tree_does_not_require_an_unselected_ancestor_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    let first = initial_root_publication()?;
    let second = next_root_publication(&first)?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    store
        .connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")?;
    store.connection.execute(
        "UPDATE content_manifests SET root_digest = zeroblob(33) WHERE manifest_id = ?1",
        [first.file.manifest.manifest_id.as_bytes().as_slice()],
    )?;
    store
        .connection
        .execute_batch("PRAGMA ignore_check_constraints = OFF;")?;
    assert_eq!(
        collect_tree_manifests(&mut store, &second)?,
        vec![second.file.manifest]
    );
    assert!(collect_tree_manifests(&mut store, &first).is_err());
    let mut causal = tree_request(&second, Vec::new());
    causal.limit = 4096;
    assert!(store.namespace_history_page(causal).is_err());
    Ok(())
}

fn collect_tree_manifests(
    store: &mut VersionPublicationStore,
    publication: &RootFilePublication,
) -> Result<Vec<ManifestPublication>, Box<dyn std::error::Error>> {
    let mut cursor = Vec::new();
    let mut manifests = Vec::new();
    loop {
        let page = store.namespace_retained_tree_page(tree_request(publication, cursor))?;
        assert!(page.commits.is_empty());
        for object_digest in page.immutable_object_digests {
            let object = store.namespace_history_object(NamespaceHistoryObjectRequest {
                scope_binding: [91; 32],
                export_token: page.export_token,
                object_digest,
                now: UnixMicros::new(100),
            })?;
            if let Some(manifest) = object.as_manifest()? {
                manifests.push(manifest);
            }
        }
        if page.next_cursor.is_empty() {
            return Ok(manifests);
        }
        cursor = page.next_cursor;
    }
}

fn tree_request(publication: &RootFilePublication, cursor: Vec<u8>) -> NamespaceHistoryPageRequest {
    NamespaceHistoryPageRequest {
        scope_binding: [91; 32],
        volume_id: publication.file.volume_id,
        requested_heads: vec![publication.namespace_commit_id],
        known_commits: Vec::new(),
        cursor,
        limit: 8,
        now: UnixMicros::new(100),
        expires_at: UnixMicros::new(1_000_000),
    }
}
