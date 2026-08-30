// SPDX-License-Identifier: GPL-2.0-only

//! Disconnected namespace publication, restart and deterministic reconciliation proof.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;

use ed25519_dalek::SigningKey;
use meshspan_cluster::{FederationMutationAcceptor, MetadataFederationMutationAcceptanceAuthority};
use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId,
    OperationId, PrincipalId, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    BranchMutation, FilePublication, ManifestPublication, NamespaceLimits, NamespacePath,
    NamespacePublicationPath, NamespaceReconciliationApplication, NamespaceReplayEffect,
    PreparedNamespaceReconciliation, ReconciliationFrontier, ReconciliationLimits,
    RootFilePublication, VersionPublicationStore,
};
use meshspan_metadata::AuthoritativeRepository;

use super::metadata::{FederationFixture, VOLUME_SEED};

#[derive(Clone, Copy)]
pub(super) struct EditIdentity {
    operation: u8,
    version: u8,
    manifest: u8,
    file_revision: u8,
    root_revision: u8,
    commit: u8,
}

impl EditIdentity {
    pub(super) const fn new(seed: u8) -> Self {
        Self {
            operation: seed,
            version: seed.saturating_add(1),
            manifest: seed.saturating_add(2),
            file_revision: seed.saturating_add(3),
            root_revision: seed.saturating_add(4),
            commit: seed.saturating_add(5),
        }
    }
}

pub(super) fn base_publication(
    created_by: PrincipalId,
) -> Result<RootFilePublication, Box<dyn Error>> {
    Ok(RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([60; 16])?,
            branch_id: BranchId::from_bytes([61; 16])?,
            volume_id: VolumeId::from_bytes([VOLUME_SEED; 16])?,
            object_id: ObjectId::from_bytes([62; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([63; 16])?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: manifest(64, b"base")?,
            created_by,
            created_at: UnixMicros::new(9),
        },
        root_object_id: ObjectId::from_bytes([65; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([66; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([67; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([68; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["report.txt"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })
}

pub(super) fn next_publication(
    parent: &RootFilePublication,
    branch_id: BranchId,
    created_by: PrincipalId,
    identity: EditIdentity,
    content: &[u8],
) -> Result<RootFilePublication, Box<dyn Error>> {
    Ok(RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([identity.operation; 16])?,
            branch_id,
            volume_id: parent.file.volume_id,
            object_id: parent.file.object_id,
            expected_current_version_id: Some(parent.file.version_id),
            version_id: FileVersionId::from_bytes([identity.version; 16])?,
            parent_version_id: Some(parent.file.version_id),
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: manifest(identity.manifest, content)?,
            created_by,
            created_at: UnixMicros::new(i64::from(identity.operation)),
        },
        root_object_id: parent.root_object_id,
        expected_namespace_commit_id: Some(parent.namespace_commit_id),
        expected_file_object_revision_id: Some(parent.file_object_revision_id),
        file_object_revision_id: ObjectRevisionId::from_bytes([identity.file_revision; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([identity.root_revision; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([identity.commit; 16])?,
        path: parent.path.clone(),
        entry_generation: parent.entry_generation,
    })
}

fn manifest(seed: u8, content: &[u8]) -> Result<ManifestPublication, Box<dyn Error>> {
    Ok(ManifestPublication {
        manifest_id: ContentManifestId::from_bytes([seed; 16])?,
        format_version: 1,
        logical_length: u64::try_from(content.len())?,
        content_digest: blake3::hash(content).into(),
        root_digest: blake3::hash(&[content, &[seed]].concat()).into(),
    })
}

pub(super) struct HomeMutationAcceptance<'a> {
    federation: &'a FederationFixture,
    key: &'a SigningKey,
    repository: &'a AuthoritativeRepository,
    gateway: meshspan_domain::NodeId,
}

impl<'a> HomeMutationAcceptance<'a> {
    pub(super) const fn new(
        federation: &'a FederationFixture,
        key: &'a SigningKey,
        repository: &'a AuthoritativeRepository,
        gateway: meshspan_domain::NodeId,
    ) -> Self {
        Self {
            federation,
            key,
            repository,
            gateway,
        }
    }

    fn publish(
        &self,
        store: &mut VersionPublicationStore,
        publication: &RootFilePublication,
        accepted_at: i64,
    ) -> Result<(), Box<dyn Error>> {
        let proposal = VersionPublicationStore::root_file_federated_mutation_proposal(publication)?;
        let acknowledgement = FederationMutationAcceptor::new(
            MetadataFederationMutationAcceptanceAuthority::new(
                self.repository,
                &self.federation.server_cache,
            ),
            self.key,
        )
        .acknowledge(
            self.federation
                .acceptance_request(accepted_at, self.gateway),
            &proposal,
        )?;
        store.publish_federated_root_file(publication, &acknowledgement)?;
        Ok(())
    }
}

pub(super) fn seed_disconnected_edits(
    source_directory: &Path,
    owner_directory: &Path,
    base: &RootFilePublication,
    owner: &RootFilePublication,
    source: &RootFilePublication,
    acceptance: &HomeMutationAcceptance<'_>,
) -> Result<(), Box<dyn Error>> {
    let mut source_store = VersionPublicationStore::open(source_directory, UnixMicros::new(1))?;
    source_store.publish_root_file(base)?;
    source_store.ensure_namespace_branch(
        source.file.branch_id,
        source.file.volume_id,
        base.namespace_commit_id,
    )?;
    acceptance.publish(&mut source_store, source, 120)?;

    let mut owner_store = VersionPublicationStore::open(owner_directory, UnixMicros::new(1))?;
    owner_store.publish_root_file(base)?;
    owner_store.publish_root_file(owner)?;
    drop(source_store);
    drop(owner_store);
    prove_heads_survive_restart(source_directory, owner_directory, source, owner)
}

fn prove_heads_survive_restart(
    source_directory: &Path,
    owner_directory: &Path,
    source: &RootFilePublication,
    owner: &RootFilePublication,
) -> Result<(), Box<dyn Error>> {
    let reopened_source = VersionPublicationStore::open(source_directory, UnixMicros::new(121))?;
    let reopened_owner = VersionPublicationStore::open(owner_directory, UnixMicros::new(121))?;
    assert_eq!(
        reopened_source
            .namespace_head(source.file.branch_id, source.file.volume_id)?
            .ok_or("source head missing after restart")?
            .namespace_commit_id,
        source.namespace_commit_id
    );
    assert_eq!(
        reopened_owner
            .namespace_head(owner.file.branch_id, owner.file.volume_id)?
            .ok_or("owner head missing after restart")?
            .namespace_commit_id,
        owner.namespace_commit_id
    );
    Ok(())
}

pub(super) fn publish_before_home_suspension(
    source_directory: &Path,
    publication: &RootFilePublication,
    acceptance: &HomeMutationAcceptance<'_>,
) -> Result<(), Box<dyn Error>> {
    let mut store = VersionPublicationStore::open(source_directory, UnixMicros::new(129))?;
    acceptance.publish(&mut store, publication, 130)?;
    drop(store);
    VersionPublicationStore::open(source_directory, UnixMicros::new(131))?;
    Ok(())
}

pub(super) struct FirstMerge {
    commit_id: NamespaceCommitId,
    source_commit_id: NamespaceCommitId,
    source_version_id: FileVersionId,
    visible_versions: BTreeSet<FileVersionId>,
}

pub(super) fn reconcile_visible_edits(
    owner_directory: &Path,
    base: &RootFilePublication,
    owner: &RootFilePublication,
    source: &RootFilePublication,
    administrator: PrincipalId,
) -> Result<FirstMerge, Box<dyn Error>> {
    let mut store = VersionPublicationStore::open(owner_directory, UnixMicros::new(150))?;
    let prepared = store.prepare_namespace_reconciliation(
        &ReconciliationFrontier {
            converged_head: Some(base.namespace_commit_id),
            eligible_heads: vec![owner.namespace_commit_id, source.namespace_commit_id],
        },
        ReconciliationLimits::DEFAULT,
    )?;
    let receipt = store.apply_namespace_reconciliation(
        reconciliation_application(150, 151, administrator)?,
        &prepared,
    )?;
    let visible_versions = upserted_file_versions(&prepared);
    assert_eq!(
        visible_versions,
        BTreeSet::from([owner.file.version_id, source.file.version_id])
    );
    Ok(FirstMerge {
        commit_id: receipt.namespace_commit_id,
        source_commit_id: source.namespace_commit_id,
        source_version_id: source.file.version_id,
        visible_versions,
    })
}

pub(super) fn prove_quarantined_edit_stays_invisible(
    owner_directory: &Path,
    first: &FirstMerge,
    rejected: &RootFilePublication,
    administrator: PrincipalId,
) -> Result<(), Box<dyn Error>> {
    let mut store = VersionPublicationStore::open(owner_directory, UnixMicros::new(160))?;
    let prepared = store.prepare_namespace_reconciliation(
        &ReconciliationFrontier {
            converged_head: Some(first.source_commit_id),
            eligible_heads: vec![first.commit_id, rejected.namespace_commit_id],
        },
        ReconciliationLimits::DEFAULT,
    )?;
    let replay = prepared.replay_plan();
    assert_eq!(replay.quarantined_commits(), [rejected.namespace_commit_id]);
    let mut visible_versions = upserted_file_versions(&prepared);
    // The converged source head is the immutable replay base and needs no replay action.
    visible_versions.insert(first.source_version_id);
    assert_eq!(visible_versions, first.visible_versions);
    assert!(!visible_versions.contains(&rejected.file.version_id));
    store.apply_namespace_reconciliation(
        reconciliation_application(160, 161, administrator)?,
        &prepared,
    )?;
    Ok(())
}

fn upserted_file_versions(prepared: &PreparedNamespaceReconciliation) -> BTreeSet<FileVersionId> {
    prepared
        .replay_plan()
        .actions()
        .iter()
        .filter(|action| action.effect == NamespaceReplayEffect::Upsert)
        .filter_map(|action| match action.mutation {
            BranchMutation::File { version_id } => Some(version_id),
            BranchMutation::CreateDirectory
            | BranchMutation::DeleteFile { .. }
            | BranchMutation::DeleteDirectory => None,
        })
        .collect()
}

fn reconciliation_application(
    operation: u8,
    commit: u8,
    administrator: PrincipalId,
) -> Result<NamespaceReconciliationApplication, Box<dyn Error>> {
    Ok(NamespaceReconciliationApplication {
        operation_id: OperationId::from_bytes([operation; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([commit; 16])?,
        created_by: administrator,
        retain_superseded_history: true,
        retention_policy_sequence: 1,
        created_at: UnixMicros::new(i64::from(operation)),
    })
}
