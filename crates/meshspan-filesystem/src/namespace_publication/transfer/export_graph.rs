// SPDX-License-Identifier: GPL-2.0-only

//! Exact immutable-object closure for one exported namespace history.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, ObjectId, ObjectRevisionId, OperationId,
    PrincipalId, UnixMicros, VolumeId,
};
use rusqlite::Connection;

use super::super::repository::{ObjectRevisionInsert, load_object_revision};
use super::{TransferredFileVersion, TransferredMutationCommit};
use crate::directory::DirectoryReachabilityReference;
use crate::publication::{copy_array, decode_identifier, from_i64, load_directory_node};
use crate::{
    BranchMutation, DirectoryNodeDigest, DirectoryNodeRecord, ManifestPublication,
    NamespaceHistoryLimits, PublicationError,
};

pub(super) struct HistoryObjects {
    pub directory_nodes: Vec<DirectoryNodeRecord>,
    pub manifests: Vec<ManifestPublication>,
    pub file_versions: Vec<TransferredFileVersion>,
    pub object_revisions: Vec<ObjectRevisionInsert>,
}

pub(in crate::publication) struct CommitReferences {
    pub revisions: BTreeSet<ObjectRevisionId>,
    pub versions: BTreeSet<FileVersionId>,
}

pub(in crate::publication) fn commit_references(
    record: &TransferredMutationCommit,
) -> CommitReferences {
    let mut revisions = BTreeSet::from([record.commit.root_object_revision_id]);
    let mut versions = BTreeSet::new();
    let intent = &record.intent;
    revisions.insert(intent.object_revision_id);
    revisions.extend(intent.prior_object_revision_id);
    add_transitions(&mut revisions, &intent.ancestors);
    match intent.mutation {
        BranchMutation::File { version_id } | BranchMutation::DeleteFile { version_id } => {
            versions.insert(version_id);
        }
        BranchMutation::CreateDirectory | BranchMutation::DeleteDirectory => {}
    }
    if let Some(rename) = &intent.rename {
        revisions.insert(rename.intermediate_root_object_revision_id);
        add_transitions(&mut revisions, &rename.source_ancestors);
    }
    CommitReferences {
        revisions,
        versions,
    }
}

pub(super) fn collect(
    connection: &Connection,
    volume_id: VolumeId,
    commits: &[TransferredMutationCommit],
    limits: NamespaceHistoryLimits,
) -> Result<HistoryObjects, PublicationError> {
    let mut collector = GraphCollector::new(connection, volume_id, limits);
    collector.seed_commits(commits);
    collector.collect()
}

struct GraphCollector<'a> {
    connection: &'a Connection,
    volume_id: VolumeId,
    maximum_records: usize,
    pending_revisions: BTreeSet<ObjectRevisionId>,
    pending_nodes: BTreeSet<DirectoryNodeDigest>,
    pending_versions: BTreeSet<FileVersionId>,
    revisions: BTreeMap<ObjectRevisionId, ObjectRevisionInsert>,
    nodes: BTreeMap<DirectoryNodeDigest, DirectoryNodeRecord>,
    versions: BTreeMap<FileVersionId, TransferredFileVersion>,
    manifests: BTreeMap<ContentManifestId, ManifestPublication>,
}

impl<'a> GraphCollector<'a> {
    fn new(
        connection: &'a Connection,
        volume_id: VolumeId,
        limits: NamespaceHistoryLimits,
    ) -> Self {
        Self {
            connection,
            volume_id,
            maximum_records: limits.maximum_immutable_records,
            pending_revisions: BTreeSet::new(),
            pending_nodes: BTreeSet::new(),
            pending_versions: BTreeSet::new(),
            revisions: BTreeMap::new(),
            nodes: BTreeMap::new(),
            versions: BTreeMap::new(),
            manifests: BTreeMap::new(),
        }
    }

    fn seed_commits(&mut self, commits: &[TransferredMutationCommit]) {
        for record in commits {
            let references = commit_references(record);
            self.pending_revisions.extend(references.revisions);
            self.pending_versions.extend(references.versions);
        }
    }

    fn collect(mut self) -> Result<HistoryObjects, PublicationError> {
        while self.has_pending() {
            if let Some(revision_id) = self.pending_revisions.pop_first() {
                self.collect_revision(revision_id)?;
            } else if let Some(node_digest) = self.pending_nodes.pop_first() {
                self.collect_node(node_digest)?;
            } else if let Some(version_id) = self.pending_versions.pop_first() {
                self.collect_version(version_id)?;
            }
        }
        Ok(HistoryObjects {
            directory_nodes: self.nodes.into_values().collect(),
            manifests: self.manifests.into_values().collect(),
            file_versions: self.versions.into_values().collect(),
            object_revisions: self.revisions.into_values().collect(),
        })
    }

    fn has_pending(&self) -> bool {
        !(self.pending_revisions.is_empty()
            && self.pending_nodes.is_empty()
            && self.pending_versions.is_empty())
    }

    fn collect_revision(&mut self, revision_id: ObjectRevisionId) -> Result<(), PublicationError> {
        if self.revisions.contains_key(&revision_id) {
            return Ok(());
        }
        let revision = load_object_revision(self.connection, revision_id)?;
        if revision.volume_id != self.volume_id {
            return Err(PublicationError::Corrupt);
        }
        self.ensure_capacity()?;
        self.pending_revisions.extend(revision.prior_revision_id);
        self.pending_nodes.extend(revision.directory_root);
        self.pending_versions.extend(revision.file_version_id);
        self.revisions.insert(revision_id, revision);
        Ok(())
    }

    fn collect_node(&mut self, digest: DirectoryNodeDigest) -> Result<(), PublicationError> {
        if self.nodes.contains_key(&digest) {
            return Ok(());
        }
        let record =
            load_directory_node(self.connection, digest)?.ok_or(PublicationError::Corrupt)?;
        self.ensure_capacity()?;
        for reference in record.reachability_references() {
            match reference {
                DirectoryReachabilityReference::Node(child) => {
                    self.pending_nodes.insert(child);
                }
                DirectoryReachabilityReference::ObjectRevision(revision) => {
                    self.pending_revisions.insert(revision);
                }
            }
        }
        self.nodes.insert(digest, record);
        Ok(())
    }

    fn collect_version(&mut self, version_id: FileVersionId) -> Result<(), PublicationError> {
        if self.versions.contains_key(&version_id) {
            return Ok(());
        }
        let version = load_file_version(self.connection, version_id)?;
        if version.volume_id != self.volume_id {
            return Err(PublicationError::Corrupt);
        }
        self.ensure_capacity()?;
        self.pending_versions.extend(version.parent_version_id);
        self.versions.insert(version_id, version);
        self.collect_manifest(version.manifest_id)
    }

    fn collect_manifest(&mut self, manifest_id: ContentManifestId) -> Result<(), PublicationError> {
        if self.manifests.contains_key(&manifest_id) {
            return Ok(());
        }
        self.ensure_capacity()?;
        let manifest = load_manifest(self.connection, manifest_id)?;
        self.manifests.insert(manifest_id, manifest);
        Ok(())
    }

    fn ensure_capacity(&self) -> Result<(), PublicationError> {
        let count = self
            .revisions
            .len()
            .checked_add(self.nodes.len())
            .and_then(|value| value.checked_add(self.versions.len()))
            .and_then(|value| value.checked_add(self.manifests.len()));
        if count.is_some_and(|value| value < self.maximum_records) {
            Ok(())
        } else {
            Err(PublicationError::InvalidInput)
        }
    }
}

fn add_transitions(
    revisions: &mut BTreeSet<ObjectRevisionId>,
    transitions: &[crate::DirectoryRevisionTransition],
) {
    for transition in transitions {
        revisions.insert(transition.expected_revision_id());
        revisions.insert(transition.new_revision_id());
    }
}

pub(in crate::publication) fn load_file_version(
    connection: &Connection,
    version_id: FileVersionId,
) -> Result<TransferredFileVersion, PublicationError> {
    type Stored = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Option<Vec<u8>>,
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        i64,
        Vec<u8>,
    );
    let stored: Stored = connection.query_row(
        "SELECT branch_id, volume_id, object_id, parent_version_id, manifest_id, logical_length,
                content_digest, created_by, created_at, publication_operation_id
         FROM file_versions WHERE version_id = ?1",
        [version_id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
            ))
        },
    )?;
    Ok(TransferredFileVersion {
        version_id,
        branch_id: decode_identifier(&stored.0, BranchId::from_bytes)?,
        volume_id: decode_identifier(&stored.1, VolumeId::from_bytes)?,
        object_id: decode_identifier(&stored.2, ObjectId::from_bytes)?,
        parent_version_id: stored
            .3
            .as_deref()
            .map(|value| decode_identifier(value, FileVersionId::from_bytes))
            .transpose()?,
        manifest_id: decode_identifier(&stored.4, ContentManifestId::from_bytes)?,
        logical_length: from_i64(stored.5)?,
        content_digest: copy_array(&stored.6)?,
        created_by: decode_identifier(&stored.7, PrincipalId::from_bytes)?,
        created_at: UnixMicros::new(stored.8),
        operation_id: decode_identifier(&stored.9, OperationId::from_bytes)?,
    })
}

pub(in crate::publication) fn load_manifest(
    connection: &Connection,
    manifest_id: ContentManifestId,
) -> Result<ManifestPublication, PublicationError> {
    let stored: (i64, i64, Vec<u8>, Vec<u8>, i64) = connection.query_row(
        "SELECT format_version, logical_length, content_digest, root_digest, state
         FROM content_manifests WHERE manifest_id = ?1",
        [manifest_id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    if stored.4 != 1 {
        return Err(PublicationError::Corrupt);
    }
    Ok(ManifestPublication {
        manifest_id,
        format_version: u16::try_from(stored.0).map_err(|_| PublicationError::Corrupt)?,
        logical_length: from_i64(stored.1)?,
        content_digest: copy_array(&stored.2)?,
        root_digest: copy_array(&stored.3)?,
    })
}
