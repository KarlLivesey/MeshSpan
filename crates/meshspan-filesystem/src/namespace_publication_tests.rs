// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId,
    OperationId, PrincipalId, UnixMicros, VolumeId,
};

use super::{LoadedDirectory, mutate_directory_path, remove_namespace_path, validate};
use crate::{
    DirectoryEntry, DirectoryEntryKind, DirectoryRevisionTransition, DirectoryTrie,
    FilePublication, ManifestPublication, NamespaceLimits, NamespacePath, NamespacePublicationPath,
    RootFilePublication,
};

#[test]
fn nested_file_mutation_rebuilds_every_directory_back_to_root()
-> Result<(), Box<dyn std::error::Error>> {
    let root_object = ObjectId::from_bytes([1; 16])?;
    let directory_a = ObjectId::from_bytes([2; 16])?;
    let directory_b = ObjectId::from_bytes([3; 16])?;
    let root_old = ObjectRevisionId::from_bytes([11; 16])?;
    let root_new = ObjectRevisionId::from_bytes([12; 16])?;
    let a_old = ObjectRevisionId::from_bytes([13; 16])?;
    let a_new = ObjectRevisionId::from_bytes([14; 16])?;
    let b_old = ObjectRevisionId::from_bytes([15; 16])?;
    let b_new = ObjectRevisionId::from_bytes([16; 16])?;
    let path = NamespacePath::from_components(["a", "b", "file"], NamespaceLimits::PORTABLE)?;
    let mut root = DirectoryTrie::empty();
    root.upsert(
        DirectoryEntry::new(
            path.components()[0].clone(),
            directory_a,
            a_old,
            DirectoryEntryKind::Directory,
            4,
        )?,
        None,
    )?;
    let mut a = DirectoryTrie::empty();
    a.upsert(
        DirectoryEntry::new(
            path.components()[1].clone(),
            directory_b,
            b_old,
            DirectoryEntryKind::Directory,
            5,
        )?,
        None,
    )?;
    let b = DirectoryTrie::empty();
    let publication = publication(
        root_object,
        root_new,
        NamespacePublicationPath::new(
            path.clone(),
            vec![
                DirectoryRevisionTransition::new(directory_a, a_old, a_new)?,
                DirectoryRevisionTransition::new(directory_b, b_old, b_new)?,
            ],
        )?,
    )?;
    validate(&publication)?;
    let mutation = mutate_directory_path(
        vec![
            LoadedDirectory {
                editor: root,
                object_id: root_object,
                prior_revision_id: Some(root_old),
                new_revision_id: root_new,
            },
            LoadedDirectory {
                editor: a,
                object_id: directory_a,
                prior_revision_id: Some(a_old),
                new_revision_id: a_new,
            },
            LoadedDirectory {
                editor: b,
                object_id: directory_b,
                prior_revision_id: Some(b_old),
                new_revision_id: b_new,
            },
        ],
        &publication,
    )?;

    assert_eq!(mutation.directories.len(), 3);
    assert_eq!(mutation.directories[0].new_revision_id, root_new);
    assert_eq!(mutation.directories[1].new_revision_id, a_new);
    assert_eq!(mutation.directories[2].new_revision_id, b_new);
    assert_selected_revision(
        mutation.directories[0].directory_root,
        &mutation.created_nodes,
        &path.components()[0],
        a_new,
    )?;
    assert_selected_revision(
        mutation.directories[1].directory_root,
        &mutation.created_nodes,
        &path.components()[1],
        b_new,
    )?;
    assert_selected_revision(
        mutation.directories[2].directory_root,
        &mutation.created_nodes,
        &path.components()[2],
        publication.file_object_revision_id,
    )?;
    Ok(())
}

#[test]
fn nested_removal_rebuilds_the_source_path_without_touching_siblings()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = nested_removal_fixture()?;
    let mutation =
        remove_namespace_path(fixture.directories, &fixture.path, fixture.file_revision)?;

    assert_eq!(mutation.directories.len(), 2);
    assert_selected_revision(
        mutation.directories[0].directory_root,
        &mutation.created_nodes,
        &fixture.path.path().components()[0],
        fixture.directory_new,
    )?;
    fixture
        .retained_child_nodes
        .extend(mutation.created_nodes.iter().cloned());
    let child = DirectoryTrie::from_selected_records(
        mutation.directories[1].directory_root,
        fixture.retained_child_nodes,
        &fixture.path.path().components()[1],
    )?;
    assert_eq!(child.lookup(&fixture.path.path().components()[1])?, None);
    assert_eq!(
        child
            .lookup(&fixture.sibling_name)?
            .map(|entry| entry.object_id()),
        Some(fixture.sibling)
    );
    Ok(())
}

struct NestedRemovalFixture {
    directories: Vec<LoadedDirectory>,
    path: NamespacePublicationPath,
    file_revision: ObjectRevisionId,
    directory_new: ObjectRevisionId,
    sibling_name: crate::NamespaceComponent,
    sibling: ObjectId,
    retained_child_nodes: Vec<crate::DirectoryNodeRecord>,
}

fn nested_removal_fixture() -> Result<NestedRemovalFixture, Box<dyn std::error::Error>> {
    let root_object = ObjectId::from_bytes([41; 16])?;
    let directory = ObjectId::from_bytes([42; 16])?;
    let file = ObjectId::from_bytes([43; 16])?;
    let sibling = ObjectId::from_bytes([44; 16])?;
    let root_old = ObjectRevisionId::from_bytes([45; 16])?;
    let root_new = ObjectRevisionId::from_bytes([46; 16])?;
    let directory_old = ObjectRevisionId::from_bytes([47; 16])?;
    let directory_new = ObjectRevisionId::from_bytes([48; 16])?;
    let file_revision = ObjectRevisionId::from_bytes([49; 16])?;
    let sibling_revision = ObjectRevisionId::from_bytes([50; 16])?;
    let path = NamespacePath::from_components(["a", "file"], NamespaceLimits::PORTABLE)?;
    let mut root = DirectoryTrie::empty();
    root.upsert(
        DirectoryEntry::new(
            path.components()[0].clone(),
            directory,
            directory_old,
            DirectoryEntryKind::Directory,
            3,
        )?,
        None,
    )?;
    let mut child = DirectoryTrie::empty();
    let file_nodes = child.upsert(
        DirectoryEntry::new(
            path.components()[1].clone(),
            file,
            file_revision,
            DirectoryEntryKind::File,
            4,
        )?,
        None,
    )?;
    let mut retained_child_nodes = file_nodes
        .created_nodes
        .iter()
        .map(|digest| child.record(*digest))
        .collect::<Result<Vec<_>, _>>()?;
    let sibling_name = crate::NamespaceComponent::new("sibling", NamespaceLimits::PORTABLE)?;
    let sibling_nodes = child.upsert(
        DirectoryEntry::new(
            sibling_name.clone(),
            sibling,
            sibling_revision,
            DirectoryEntryKind::File,
            5,
        )?,
        None,
    )?;
    retained_child_nodes.extend(
        sibling_nodes
            .created_nodes
            .iter()
            .map(|digest| child.record(*digest))
            .collect::<Result<Vec<_>, _>>()?,
    );
    let publication_path = NamespacePublicationPath::new(
        path.clone(),
        vec![DirectoryRevisionTransition::new(
            directory,
            directory_old,
            directory_new,
        )?],
    )?;
    Ok(NestedRemovalFixture {
        directories: vec![
            LoadedDirectory {
                editor: root,
                object_id: root_object,
                prior_revision_id: Some(root_old),
                new_revision_id: root_new,
            },
            LoadedDirectory {
                editor: child,
                object_id: directory,
                prior_revision_id: Some(directory_old),
                new_revision_id: directory_new,
            },
        ],
        path: publication_path,
        file_revision,
        directory_new,
        sibling_name,
        sibling,
        retained_child_nodes,
    })
}

fn assert_selected_revision(
    root: crate::DirectoryNodeDigest,
    records: &[crate::DirectoryNodeRecord],
    name: &crate::NamespaceComponent,
    expected: ObjectRevisionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let trie = DirectoryTrie::from_selected_records(root, records.iter().cloned(), name)?;
    assert_eq!(
        trie.lookup(name)?.map(|entry| entry.object_revision_id()),
        Some(expected)
    );
    Ok(())
}

fn publication(
    root_object_id: ObjectId,
    root_object_revision_id: ObjectRevisionId,
    path: NamespacePublicationPath,
) -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    Ok(RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([21; 16])?,
            branch_id: BranchId::from_bytes([22; 16])?,
            volume_id: VolumeId::from_bytes([23; 16])?,
            object_id: ObjectId::from_bytes([24; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([25; 16])?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes([26; 16])?,
                format_version: 1,
                logical_length: 7,
                content_digest: [27; 32],
                root_digest: [28; 32],
            },
            created_by: PrincipalId::from_bytes([29; 16])?,
            created_at: UnixMicros::new(30),
        },
        root_object_id,
        expected_namespace_commit_id: Some(NamespaceCommitId::from_bytes([31; 16])?),
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([32; 16])?,
        root_object_revision_id,
        namespace_commit_id: NamespaceCommitId::from_bytes([33; 16])?,
        path,
        entry_generation: 1,
    })
}
