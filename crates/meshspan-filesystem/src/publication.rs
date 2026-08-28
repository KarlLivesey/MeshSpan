// SPDX-License-Identifier: GPL-2.0-only

//! Immutable manifest/version publication with one atomic branch-file head transition.

#[path = "namespace_publication.rs"]
mod namespace;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId,
    OperationId, PrincipalId, SnapshotId, UnixMicros, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;

use crate::{DirectoryNodeDigest, DirectoryNodeRecord, DirectoryTrieError, NamespacePath};
use crate::{
    PreparedNamespaceReconciliation, ReconciliationCommit, ReconciliationCommitPayload,
    ReconciliationFrontier, ReconciliationLimits, ReconciliationPlan, ReconciliationStoreError,
};

const DATABASE_FILE: &str = "filesystem-branch.sqlite3";
const MAXIMUM_SQLITE_INTEGER: u64 = 9_223_372_036_854_775_807;
const MAXIMUM_NODES_PER_DIRECTORY_MUTATION: usize = 65;
const MIGRATIONS: [Migration; 8] = [
    Migration {
        version: 1,
        sql: include_str!("../schema/branch/001_initial.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("../schema/branch/002_directory_nodes.sql"),
    },
    Migration {
        version: 3,
        sql: include_str!("../schema/branch/003_namespace_heads.sql"),
    },
    Migration {
        version: 4,
        sql: include_str!("../schema/branch/004_directory_operations.sql"),
    },
    Migration {
        version: 5,
        sql: include_str!("../schema/branch/005_reconciliation_intents.sql"),
    },
    Migration {
        version: 6,
        sql: include_str!("../schema/branch/006_reconciliation_ancestor_lineage.sql"),
    },
    Migration {
        version: 7,
        sql: include_str!("../schema/branch/007_reconciliation_receipts.sql"),
    },
    Migration {
        version: 8,
        sql: include_str!("../schema/branch/008_snapshot_restore_operations.sql"),
    },
];
const SCHEMA_VERSION: u32 = 8;

#[derive(Clone, Copy)]
struct Migration {
    version: u32,
    sql: &'static str,
}

/// One complete, independently verified immutable content-manifest root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestPublication {
    /// Stable identity of the manifest root.
    pub manifest_id: ContentManifestId,
    /// On-disk manifest encoding version.
    pub format_version: u16,
    /// Exact logical file length represented by the manifest.
    pub logical_length: u64,
    /// Digest of the reconstructed plaintext file content.
    pub content_digest: [u8; 32],
    /// Digest of the complete immutable manifest graph.
    pub root_digest: [u8; 32],
}

/// Exact immutable version and expected branch-file head transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilePublication {
    /// Idempotency identity for the whole publication transaction.
    pub operation_id: OperationId,
    /// Writable local/cell branch receiving the version.
    pub branch_id: BranchId,
    /// Volume containing the stable file object.
    pub volume_id: VolumeId,
    /// Stable file identity, independent of names and versions.
    pub object_id: ObjectId,
    /// Exact current version required before publication, or no version for a new file.
    pub expected_current_version_id: Option<FileVersionId>,
    /// New globally stable immutable version identity.
    pub version_id: FileVersionId,
    /// Causal prior file version; must equal the expected current version.
    pub parent_version_id: Option<FileVersionId>,
    /// Complete verified content manifest selected by the version.
    pub manifest: ManifestPublication,
    /// Principal responsible for publication.
    pub created_by: PrincipalId,
    /// Authoritative publication instant.
    pub created_at: UnixMicros,
}

/// One existing child directory whose immutable revision must change during path copying.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryRevisionTransition {
    object: ObjectId,
    expected_revision: ObjectRevisionId,
    new_revision: ObjectRevisionId,
}

impl DirectoryRevisionTransition {
    /// Binds a stable directory object to distinct old and new immutable revisions.
    ///
    /// # Errors
    ///
    /// Rejects an attempted in-place revision update.
    pub fn new(
        object_id: ObjectId,
        expected_revision_id: ObjectRevisionId,
        new_revision_id: ObjectRevisionId,
    ) -> Result<Self, PublicationPathError> {
        if expected_revision_id == new_revision_id {
            Err(PublicationPathError::ReusedRevision)
        } else {
            Ok(Self {
                object: object_id,
                expected_revision: expected_revision_id,
                new_revision: new_revision_id,
            })
        }
    }

    /// Stable directory identity selected by its parent entry.
    #[must_use]
    pub const fn object_id(self) -> ObjectId {
        self.object
    }

    /// Exact existing immutable revision selected by the current path.
    #[must_use]
    pub const fn expected_revision_id(self) -> ObjectRevisionId {
        self.expected_revision
    }

    /// New immutable revision installed while copying the path back to the root.
    #[must_use]
    pub const fn new_revision_id(self) -> ObjectRevisionId {
        self.new_revision
    }
}

/// Validated namespace path paired with every existing directory below the volume root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespacePublicationPath {
    path: NamespacePath,
    ancestors: Vec<DirectoryRevisionTransition>,
}

impl NamespacePublicationPath {
    /// Creates an exact root-to-leaf chain for one namespace publication.
    ///
    /// A one-component path has no child-directory transitions. Every additional component before
    /// the leaf requires exactly one transition in the same root-to-leaf order.
    ///
    /// # Errors
    ///
    /// Rejects missing or extra directory transitions.
    pub fn new(
        path: NamespacePath,
        ancestors: Vec<DirectoryRevisionTransition>,
    ) -> Result<Self, PublicationPathError> {
        if ancestors.len().checked_add(1) == Some(path.components().len()) {
            Ok(Self { path, ancestors })
        } else {
            Err(PublicationPathError::TransitionCount)
        }
    }

    /// Complete validated root-relative namespace path.
    #[must_use]
    pub const fn path(&self) -> &NamespacePath {
        &self.path
    }

    /// Existing child-directory transitions in root-to-leaf order.
    #[must_use]
    pub fn ancestors(&self) -> &[DirectoryRevisionTransition] {
        &self.ancestors
    }

    /// Leaf object name selected by the path.
    #[must_use]
    pub fn leaf_name(&self) -> Option<&crate::NamespaceComponent> {
        self.path.components().last()
    }
}

/// Stable construction failures for an exact namespace-publication path.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PublicationPathError {
    /// The path and child-directory transition counts do not describe the same hierarchy.
    #[error("namespace publication path has missing or extra directory transitions")]
    TransitionCount,
    /// Immutable object revision identity was reused for an in-place update.
    #[error("namespace publication path reuses an immutable directory revision")]
    ReusedRevision,
}

/// One root-directory file mutation that must advance a verified volume branch head atomically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootFilePublication {
    /// File manifest/version and per-file causal base.
    pub file: FilePublication,
    /// Stable volume-root directory identity.
    pub root_object_id: ObjectId,
    /// Exact namespace commit required before mutation, or no commit for initial creation.
    pub expected_namespace_commit_id: Option<NamespaceCommitId>,
    /// Exact prior file object revision selected by the old directory root, or absent for create.
    pub expected_file_object_revision_id: Option<ObjectRevisionId>,
    /// New immutable file object revision selecting `file.version_id`.
    pub file_object_revision_id: ObjectRevisionId,
    /// New immutable root-directory object revision selecting the path-copied directory root.
    pub root_object_revision_id: ObjectRevisionId,
    /// New immutable namespace commit that becomes the branch head.
    pub namespace_commit_id: NamespaceCommitId,
    /// Validated root-relative path and exact existing child-directory transitions.
    pub path: NamespacePublicationPath,
    /// Stable name-reuse generation.
    pub entry_generation: u64,
}

/// One atomic creation of a new empty directory at an exact namespace path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryPublication {
    /// Idempotency identity for the complete namespace transaction.
    pub operation_id: OperationId,
    /// Writable local/cell branch receiving the directory.
    pub branch_id: BranchId,
    /// Volume containing the directory hierarchy.
    pub volume_id: VolumeId,
    /// Stable volume-root directory identity.
    pub root_object_id: ObjectId,
    /// Exact namespace commit required before creation, or none for a new volume.
    pub expected_namespace_commit_id: Option<NamespaceCommitId>,
    /// New stable directory object identity selected by the leaf entry.
    pub directory_object_id: ObjectId,
    /// New immutable empty directory revision.
    pub directory_object_revision_id: ObjectRevisionId,
    /// New immutable volume-root directory revision after path copying.
    pub root_object_revision_id: ObjectRevisionId,
    /// New immutable namespace commit that becomes current.
    pub namespace_commit_id: NamespaceCommitId,
    /// Validated root-relative path and exact existing child-directory transitions.
    pub path: NamespacePublicationPath,
    /// Stable generation for this canonical leaf-name incarnation.
    pub entry_generation: u64,
    /// Principal responsible for creation.
    pub created_by: PrincipalId,
    /// Authoritative creation instant.
    pub created_at: UnixMicros,
}

/// Current immutable namespace commit selected by one branch/volume pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchNamespaceHead {
    /// Writable branch identity.
    pub branch_id: BranchId,
    /// Volume identity.
    pub volume_id: VolumeId,
    /// Current immutable namespace commit.
    pub namespace_commit_id: NamespaceCommitId,
    /// Monotonic successful volume-head transition sequence.
    pub sequence: u64,
}

/// Durable result of one atomic file-version and volume-branch-head publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespacePublicationReceipt {
    /// Whether this call applied or replayed the exact operation.
    pub disposition: PublicationDisposition,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Digest of every mutation input and expected base.
    pub request_digest: [u8; 32],
    /// Newly published immutable file version.
    pub file_version_id: FileVersionId,
    /// Namespace commit made current.
    pub namespace_commit_id: NamespaceCommitId,
    /// Resulting volume branch-head sequence.
    pub head_sequence: u64,
    /// Digest binding the exact durable result.
    pub result_digest: [u8; 32],
}

/// Durable result of one atomic directory creation and namespace-head transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryPublicationReceipt {
    /// Whether this call applied or replayed the exact operation.
    pub disposition: PublicationDisposition,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Digest of every mutation input and expected base.
    pub request_digest: [u8; 32],
    /// Newly created immutable directory revision.
    pub directory_object_revision_id: ObjectRevisionId,
    /// Namespace commit made current.
    pub namespace_commit_id: NamespaceCommitId,
    /// Resulting volume branch-head sequence.
    pub head_sequence: u64,
    /// Digest binding the exact durable result.
    pub result_digest: [u8; 32],
}

/// One immutable whole-volume restore commit prepared for authoritative publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotRestorePublication {
    /// Idempotency identity for the complete restore preparation.
    pub operation_id: OperationId,
    /// Writable authoritative branch that owns the current converged head.
    pub branch_id: BranchId,
    /// Volume restored by the operation.
    pub volume_id: VolumeId,
    /// Authoritative snapshot selected by the user.
    pub snapshot_id: SnapshotId,
    /// Exact namespace commit pinned by the selected snapshot.
    pub snapshot_namespace_commit_id: NamespaceCommitId,
    /// Exact current converged commit required before restore.
    pub expected_namespace_commit_id: NamespaceCommitId,
    /// Stable volume-root directory identity shared by both commits.
    pub root_object_id: ObjectId,
    /// Exact immutable root revision pinned by the selected snapshot.
    pub root_object_revision_id: ObjectRevisionId,
    /// New immutable commit selecting the snapshot root without rewinding history.
    pub namespace_commit_id: NamespaceCommitId,
    /// Principal responsible for restore.
    pub created_by: PrincipalId,
    /// Authoritative preparation instant.
    pub created_at: UnixMicros,
}

/// Durable prepared restore outcome safe to present to replicated metadata authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotRestoreReceipt {
    /// Whether this call prepared or replayed the exact operation.
    pub disposition: PublicationDisposition,
    /// Stable local operation identity.
    pub operation_id: OperationId,
    /// Digest binding every restore input and expected base.
    pub request_digest: [u8; 32],
    /// Authoritative snapshot selected by the request.
    pub snapshot_id: SnapshotId,
    /// Exact immutable snapshot commit used as the content source.
    pub snapshot_namespace_commit_id: NamespaceCommitId,
    /// Current converged head that must still pass replicated compare-and-swap.
    pub expected_namespace_commit_id: NamespaceCommitId,
    /// Newly prepared immutable restore commit.
    pub namespace_commit_id: NamespaceCommitId,
    /// Snapshot root selected by the new commit.
    pub root_object_revision_id: ObjectRevisionId,
    /// Digest binding the complete durable result.
    pub result_digest: [u8; 32],
}

/// Stable identities supplied when committing one prepared reconciliation plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceReconciliationApplication {
    /// Idempotency identity for the complete reconciliation transaction.
    pub operation_id: OperationId,
    /// New immutable multi-parent namespace commit.
    pub namespace_commit_id: NamespaceCommitId,
    /// Principal responsible for the automatic reconciliation.
    pub created_by: PrincipalId,
    /// Authoritative commit instant.
    pub created_at: UnixMicros,
}

/// Durable outcome proving one exact replay plan and merge commit were stored atomically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceReconciliationReceipt {
    /// Whether this call applied or replayed the exact operation.
    pub disposition: PublicationDisposition,
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Digest of application identities and both validated plans.
    pub request_digest: [u8; 32],
    /// Exact causal plan committed by the merge.
    pub causal_plan_digest: [u8; 32],
    /// Exact affected-path replay plan applied transactionally.
    pub replay_plan_digest: [u8; 32],
    /// Durable multi-parent merge commit.
    pub namespace_commit_id: NamespaceCommitId,
    /// Immutable converged root selected by the merge commit.
    pub root_object_revision_id: ObjectRevisionId,
    /// Digest binding the complete durable outcome.
    pub result_digest: [u8; 32],
}

/// Locally revalidated reconciliation outcome safe to present at the replicated-head boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedReconciliationHead {
    receipt: NamespaceReconciliationReceipt,
    volume_id: VolumeId,
    expected_namespace_commit_id: NamespaceCommitId,
}

impl VerifiedReconciliationHead {
    pub(crate) const fn new(
        receipt: NamespaceReconciliationReceipt,
        volume_id: VolumeId,
        expected_namespace_commit_id: NamespaceCommitId,
    ) -> Self {
        Self {
            receipt,
            volume_id,
            expected_namespace_commit_id,
        }
    }

    /// Exact durable reconciliation receipt reloaded from the local store.
    #[must_use]
    pub const fn receipt(self) -> NamespaceReconciliationReceipt {
        self.receipt
    }

    /// Volume bound by the independently validated immutable merge commit.
    #[must_use]
    pub const fn volume_id(self) -> VolumeId {
        self.volume_id
    }

    /// Replicated head that must still be current when consensus commits the transition.
    #[must_use]
    pub const fn expected_namespace_commit_id(self) -> NamespaceCommitId {
        self.expected_namespace_commit_id
    }
}

/// Current branch-local version pointer for one stable file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchFileHead {
    /// Branch containing this head.
    pub branch_id: BranchId,
    /// Stable file identity.
    pub object_id: ObjectId,
    /// Volume containing the file.
    pub volume_id: VolumeId,
    /// Current immutable version, if any.
    pub current_version_id: Option<FileVersionId>,
    /// Monotonic successful head-transition sequence.
    pub sequence: u64,
}

/// Whether a publication created state or resolved an exact durable retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationDisposition {
    /// The new immutable records and file head were committed.
    Applied,
    /// The exact operation had already committed and returned its original receipt.
    Replayed,
}

/// SQLite-compatible branch store for immutable versions and atomic file heads.
pub struct VersionPublicationStore {
    connection: Connection,
}

impl VersionPublicationStore {
    /// Opens, migrates and verifies one daemon-local branch publication database.
    ///
    /// # Errors
    ///
    /// Rejects migration drift/newer schemas, integrity failure and IO/SQLite errors.
    pub fn open(state_directory: &Path, opened_at: UnixMicros) -> Result<Self, PublicationError> {
        fs::create_dir_all(state_directory)?;
        let mut connection = Connection::open(state_directory.join(DATABASE_FILE))?;
        configure(&connection)?;
        migrate(&mut connection, opened_at)?;
        verify_database(&connection)?;
        Ok(Self { connection })
    }

    /// Persists one bounded path-copy node set before a later namespace-head transaction.
    ///
    /// Immutable nodes may safely exist without a reachable head. Exact retries coalesce by
    /// content identity; different bytes under one digest fail closed.
    ///
    /// # Errors
    ///
    /// Rejects empty/excessive batches, malformed node encodings, digest collisions and SQLite
    /// failure. The whole node batch commits or rolls back together.
    pub fn persist_directory_nodes(
        &mut self,
        records: &[DirectoryNodeRecord],
        recorded_at: UnixMicros,
    ) -> Result<(), PublicationError> {
        if records.is_empty() || records.len() > MAXIMUM_NODES_PER_DIRECTORY_MUTATION {
            return Err(PublicationError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for record in records {
            persist_directory_node(&transaction, record, recorded_at)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Loads and revalidates one immutable directory node by content identity.
    ///
    /// # Errors
    ///
    /// Rejects unsupported format, excessive/truncated encoding, digest mismatch and SQLite
    /// failure.
    pub fn directory_node(
        &self,
        digest: DirectoryNodeDigest,
    ) -> Result<Option<DirectoryNodeRecord>, PublicationError> {
        load_directory_node(&self.connection, digest)
    }

    /// Atomically publishes one root-directory file mutation and advances the volume branch head.
    ///
    /// The store independently loads the selected old directory path, recomputes its immutable
    /// path-copy, verifies every new node, publishes both object revisions and one namespace
    /// commit, then advances the file and volume pointers in the same SQLite transaction.
    ///
    /// # Errors
    ///
    /// Rejects stale heads, inconsistent file/directory bases, identity reuse, malformed graph
    /// state and persistence failure. Exact retries return the original immutable receipt.
    pub fn publish_root_file(
        &mut self,
        publication: &RootFilePublication,
    ) -> Result<NamespacePublicationReceipt, PublicationError> {
        namespace::publish(&mut self.connection, publication, None)
    }

    /// Atomically creates one empty directory and path-copies every selected ancestor.
    ///
    /// # Errors
    ///
    /// Rejects malformed paths, existing leaves, stale heads/ancestors, identity reuse,
    /// corruption and persistence failure. Exact retries return the original receipt.
    pub fn create_directory(
        &mut self,
        publication: &DirectoryPublication,
    ) -> Result<DirectoryPublicationReceipt, PublicationError> {
        namespace::create_directory(&mut self.connection, publication, None)
    }

    /// Loads the exact current namespace commit for one branch and volume.
    ///
    /// # Errors
    ///
    /// Rejects malformed stored identities/counters and SQLite failure.
    pub fn namespace_head(
        &self,
        branch_id: BranchId,
        volume_id: VolumeId,
    ) -> Result<Option<BranchNamespaceHead>, PublicationError> {
        namespace::load_head(&self.connection, branch_id, volume_id)
    }

    /// Resolves an atomic namespace publication outcome after a lost response.
    ///
    /// # Errors
    ///
    /// Rejects malformed or digest-inconsistent durable records and SQLite failure.
    pub fn resolve_namespace_publication(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<NamespacePublicationReceipt>, PublicationError> {
        namespace::load_operation(
            &self.connection,
            operation_id,
            PublicationDisposition::Replayed,
        )
    }

    /// Resolves an atomic directory-publication outcome after a lost response.
    ///
    /// # Errors
    ///
    /// Rejects malformed or digest-inconsistent durable records and SQLite failure.
    pub fn resolve_directory_publication(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<DirectoryPublicationReceipt>, PublicationError> {
        namespace::load_directory_operation(
            &self.connection,
            operation_id,
            PublicationDisposition::Replayed,
        )
    }

    /// Prepares a whole-volume restore commit without exposing it as the local branch head.
    ///
    /// Replicated metadata must first compare-and-swap the converged head using the returned
    /// receipt. Only then may `activate_snapshot_restore` expose the commit locally. A lost race
    /// therefore leaves an unreachable immutable preparation rather than an uncommitted branch
    /// tail.
    ///
    /// # Errors
    ///
    /// Rejects stale heads, substituted snapshot roots, mixed namespace identities, identity
    /// collisions, corrupt immutable records and SQLite failure.
    pub fn prepare_snapshot_restore(
        &mut self,
        publication: SnapshotRestorePublication,
    ) -> Result<SnapshotRestoreReceipt, PublicationError> {
        namespace::prepare_snapshot_restore(&mut self.connection, publication, None)
    }

    /// Activates one prepared restore after its replicated head transition has committed.
    ///
    /// Exact retries are idempotent. A branch that moved independently is left untouched for
    /// normal reconciliation against the now-authoritative restore root.
    ///
    /// # Errors
    ///
    /// Rejects missing/substituted receipts, stale branch heads, corrupt state and SQLite failure.
    pub fn activate_snapshot_restore(
        &mut self,
        receipt: SnapshotRestoreReceipt,
        activated_at: UnixMicros,
    ) -> Result<BranchNamespaceHead, PublicationError> {
        namespace::activate_snapshot_restore(&mut self.connection, receipt, activated_at)
    }

    /// Resolves an exact prepared restore outcome after restart or a lost response.
    ///
    /// # Errors
    ///
    /// Rejects malformed or digest-inconsistent durable records and SQLite failure.
    pub fn resolve_snapshot_restore(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<SnapshotRestoreReceipt>, PublicationError> {
        namespace::load_snapshot_restore(
            &self.connection,
            operation_id,
            PublicationDisposition::Replayed,
        )
    }

    /// Loads and validates the complete durable causal closure for one reconciliation frontier.
    ///
    /// # Errors
    ///
    /// Rejects missing/corrupt commits, cycles, mixed namespaces, conflicting operation reuse and
    /// any closure that exceeds the selected bounded page.
    pub fn plan_reconciliation(
        &self,
        frontier: &ReconciliationFrontier,
        limits: ReconciliationLimits,
    ) -> Result<ReconciliationPlan, ReconciliationStoreError> {
        let commits = load_reconciliation_commits(&self.connection, frontier, limits)?;
        crate::plan_reconciliation(&commits, frontier, limits).map_err(Into::into)
    }

    /// Loads the exact affected namespace base and produces a deterministic replay plan.
    ///
    /// # Errors
    ///
    /// Rejects incomplete/corrupt causal state, missing or substituted mutation intents,
    /// malformed directory graphs and an affected base that cannot safely replay every action.
    pub fn prepare_namespace_reconciliation(
        &self,
        frontier: &ReconciliationFrontier,
        limits: ReconciliationLimits,
    ) -> Result<PreparedNamespaceReconciliation, ReconciliationStoreError> {
        let commits = load_reconciliation_commits(&self.connection, frontier, limits)?;
        let causal = crate::plan_reconciliation(&commits, frontier, limits)?;
        let mut intents = Vec::new();
        for commit_id in causal.ordered_commits() {
            let commit = commits
                .iter()
                .find(|commit| commit.commit_id == *commit_id)
                .ok_or(crate::ReconciliationError::MissingCommit)?;
            if matches!(commit.payload, ReconciliationCommitPayload::Mutation { .. }) {
                intents.push(
                    namespace::load_branch_intent(&self.connection, *commit_id)?
                        .ok_or(crate::ReconciliationError::MissingIntent)?,
                );
            }
        }
        let base = if let Some(converged_head) = causal.converged_head() {
            let converged = commits
                .iter()
                .find(|commit| commit.commit_id == converged_head)
                .ok_or(crate::ReconciliationError::MissingCommit)?;
            namespace::load_replay_base(&self.connection, converged, &intents)?
        } else {
            crate::NamespaceReplayBase {
                root_object_revision_id: None,
                entries: Vec::new(),
            }
        };
        let replay = crate::plan_namespace_replay(&causal, &commits, &intents, &base)?;
        Ok(PreparedNamespaceReconciliation::new(causal, replay))
    }

    /// Applies every prepared namespace action and records one immutable merge receipt atomically.
    ///
    /// # Errors
    ///
    /// Rejects stale roots, substituted plans, missing immutable source records, identity
    /// collisions and any action whose exact target transition no longer matches durable state.
    pub fn apply_namespace_reconciliation(
        &mut self,
        application: NamespaceReconciliationApplication,
        prepared: &PreparedNamespaceReconciliation,
    ) -> Result<NamespaceReconciliationReceipt, PublicationError> {
        namespace::apply_reconciliation(&mut self.connection, application, prepared)
    }

    /// Resolves an exact reconciliation outcome after a lost response.
    ///
    /// # Errors
    ///
    /// Rejects malformed or digest-inconsistent durable receipts and SQLite failure.
    pub fn resolve_namespace_reconciliation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<NamespaceReconciliationReceipt>, PublicationError> {
        namespace::load_reconciliation_receipt(&self.connection, operation_id)
    }

    /// Reloads and verifies one reconciliation receipt, merge commit, volume and current-head base.
    ///
    /// # Errors
    ///
    /// Rejects a lost, substituted or corrupt receipt, a non-merge commit, the wrong volume, or a
    /// claimed current head that is not one of the immutable merge parents.
    pub fn verify_reconciliation_head(
        &self,
        volume_id: VolumeId,
        expected_namespace_commit_id: NamespaceCommitId,
        receipt: NamespaceReconciliationReceipt,
    ) -> Result<VerifiedReconciliationHead, PublicationError> {
        namespace::verify_reconciliation_head(
            &self.connection,
            volume_id,
            expected_namespace_commit_id,
            receipt,
        )
    }

    /// Loads and revalidates the canonical replay intent attached to one branch commit.
    ///
    /// # Errors
    ///
    /// Rejects malformed paths, digest mismatch, missing immutable leaf records and database
    /// failure. A legacy commit without a recorded intent returns `None`.
    pub fn branch_mutation_intent(
        &self,
        commit_id: NamespaceCommitId,
    ) -> Result<Option<crate::BranchMutationIntent>, PublicationError> {
        namespace::load_branch_intent(&self.connection, commit_id)
    }
}

fn load_reconciliation_commits(
    connection: &Connection,
    frontier: &ReconciliationFrontier,
    limits: ReconciliationLimits,
) -> Result<Vec<ReconciliationCommit>, ReconciliationStoreError> {
    let mut pending = frontier
        .converged_head
        .into_iter()
        .chain(frontier.eligible_heads.iter().copied())
        .collect::<Vec<_>>();
    let mut visited = BTreeSet::new();
    let mut commits = Vec::new();
    while let Some(commit_id) = pending.pop() {
        if !visited.insert(commit_id) {
            continue;
        }
        if visited.len() > limits.commit_page_limit() {
            return Err(crate::ReconciliationError::BoundsExceeded.into());
        }
        let Some(commit) = namespace::load_reconciliation_commit(connection, commit_id)? else {
            continue;
        };
        pending.extend(commit.parents.iter().copied());
        commits.push(commit);
    }
    Ok(commits)
}

/// Stable publication failure categories.
#[derive(Debug, Error)]
pub enum PublicationError {
    /// A field, relationship, size or digest is invalid.
    #[error("file publication input is invalid")]
    InvalidInput,
    /// The presented current version no longer matches the branch file.
    #[error("file publication base is stale")]
    StaleHead,
    /// An immutable or idempotency identity already belongs to different content.
    #[error("file publication identity conflicts with durable state")]
    OperationConflict,
    /// Durable state violates an identity, digest or transition invariant.
    #[error("file publication state is corrupt")]
    Corrupt,
    /// Deterministic test-only transaction interruption.
    #[error("file publication transaction fault injected")]
    InjectedFault,
    /// Immutable directory-node encoding or graph validation failed.
    #[error("file publication directory node is invalid")]
    Directory(#[from] DirectoryTrieError),
    /// State-directory IO failed.
    #[error("file publication filesystem operation failed")]
    Io(#[from] std::io::Error),
    /// SQLite persistence failed.
    #[error("file publication database operation failed")]
    Sqlite(#[from] rusqlite::Error),
}

fn validate_publication(publication: FilePublication) -> Result<(), PublicationError> {
    if publication.parent_version_id != publication.expected_current_version_id
        || publication.manifest.format_version == 0
        || publication.manifest.logical_length > MAXIMUM_SQLITE_INTEGER
    {
        return Err(PublicationError::InvalidInput);
    }
    Ok(())
}

fn prepare_file(
    transaction: &Transaction<'_>,
    publication: FilePublication,
) -> Result<BranchFileHead, PublicationError> {
    let existing = load_file_head(transaction, publication.branch_id, publication.object_id)?;
    if let Some(head) = existing {
        if head.volume_id != publication.volume_id
            || head.current_version_id != publication.expected_current_version_id
        {
            return Err(PublicationError::StaleHead);
        }
        return Ok(head);
    }
    if publication.expected_current_version_id.is_some() {
        return Err(PublicationError::StaleHead);
    }
    transaction.execute(
        "INSERT INTO branch_files(
            branch_id, object_id, volume_id, current_version_id, head_sequence
         ) VALUES (?1, ?2, ?3, NULL, 0)",
        params![
            publication.branch_id.as_bytes().as_slice(),
            publication.object_id.as_bytes().as_slice(),
            publication.volume_id.as_bytes().as_slice()
        ],
    )?;
    Ok(BranchFileHead {
        branch_id: publication.branch_id,
        object_id: publication.object_id,
        volume_id: publication.volume_id,
        current_version_id: None,
        sequence: 0,
    })
}

fn persist_manifest(
    transaction: &Transaction<'_>,
    manifest: ManifestPublication,
) -> Result<(), PublicationError> {
    let identifier = manifest.manifest_id.as_bytes();
    let existing: Option<(i64, i64, Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT format_version, logical_length, content_digest, root_digest
             FROM content_manifests WHERE manifest_id = ?1 AND state = 1",
            [identifier.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let expected = (
        i64::from(manifest.format_version),
        to_i64(manifest.logical_length)?,
        manifest.content_digest,
        manifest.root_digest,
    );
    if let Some(existing) = existing {
        return if existing.0 == expected.0
            && existing.1 == expected.1
            && existing.2.as_slice() == expected.2
            && existing.3.as_slice() == expected.3
        {
            Ok(())
        } else {
            Err(PublicationError::OperationConflict)
        };
    }
    transaction.execute(
        "INSERT INTO content_manifests(
            manifest_id, format_version, logical_length, content_digest, root_digest, state
         ) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
        params![
            identifier.as_slice(),
            expected.0,
            expected.1,
            expected.2.as_slice(),
            expected.3.as_slice()
        ],
    )?;
    Ok(())
}

fn persist_version(
    transaction: &Transaction<'_>,
    publication: FilePublication,
) -> Result<(), PublicationError> {
    let version = publication.version_id.as_bytes();
    let collision: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM file_versions WHERE version_id = ?1)",
        [version.as_slice()],
        |row| row.get(0),
    )?;
    if collision != 0 {
        return Err(PublicationError::OperationConflict);
    }
    let parent = publication.parent_version_id.map(FileVersionId::as_bytes);
    transaction.execute(
        "INSERT INTO file_versions(
            version_id, branch_id, volume_id, object_id, parent_version_id, manifest_id,
            logical_length, content_digest, created_by, created_at, publication_operation_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            version.as_slice(),
            publication.branch_id.as_bytes().as_slice(),
            publication.volume_id.as_bytes().as_slice(),
            publication.object_id.as_bytes().as_slice(),
            parent.as_ref().map(<[u8; 16]>::as_slice),
            publication.manifest.manifest_id.as_bytes().as_slice(),
            to_i64(publication.manifest.logical_length)?,
            publication.manifest.content_digest.as_slice(),
            publication.created_by.as_bytes().as_slice(),
            publication.created_at.get(),
            publication.operation_id.as_bytes().as_slice()
        ],
    )?;
    Ok(())
}

fn advance_file_head(
    transaction: &Transaction<'_>,
    publication: FilePublication,
    previous_sequence: u64,
) -> Result<u64, PublicationError> {
    let sequence = previous_sequence
        .checked_add(1)
        .ok_or(PublicationError::InvalidInput)?;
    let updated = transaction.execute(
        "UPDATE branch_files
         SET current_version_id = ?1, head_sequence = ?2
         WHERE branch_id = ?3 AND object_id = ?4 AND head_sequence = ?5",
        params![
            publication.version_id.as_bytes().as_slice(),
            to_i64(sequence)?,
            publication.branch_id.as_bytes().as_slice(),
            publication.object_id.as_bytes().as_slice(),
            to_i64(previous_sequence)?
        ],
    )?;
    if updated == 1 {
        Ok(sequence)
    } else {
        Err(PublicationError::StaleHead)
    }
}

fn persist_directory_node(
    transaction: &Transaction<'_>,
    record: &DirectoryNodeRecord,
    recorded_at: UnixMicros,
) -> Result<(), PublicationError> {
    let encoded = record.encode();
    let verified = DirectoryNodeRecord::decode(record.digest(), &encoded)?;
    if &verified != record {
        return Err(PublicationError::Corrupt);
    }
    let digest = record.digest().as_bytes();
    let existing: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT format_version, encoded_node FROM directory_nodes WHERE node_digest = ?1",
            [digest.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((format, existing)) = existing {
        let stored = DirectoryNodeRecord::decode(record.digest(), &existing)?;
        return if format == 1 && &stored == record {
            Ok(())
        } else {
            Err(PublicationError::Corrupt)
        };
    }
    transaction.execute(
        "INSERT INTO directory_nodes(node_digest, format_version, encoded_node, recorded_at)
         VALUES (?1, 1, ?2, ?3)",
        params![digest.as_slice(), encoded, recorded_at.get()],
    )?;
    Ok(())
}

fn load_directory_node(
    connection: &Connection,
    digest: DirectoryNodeDigest,
) -> Result<Option<DirectoryNodeRecord>, PublicationError> {
    let identifier = digest.as_bytes();
    let stored: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT format_version, encoded_node FROM directory_nodes WHERE node_digest = ?1",
            [identifier.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    stored
        .map(|(format, encoded)| {
            if format != 1 {
                return Err(PublicationError::Corrupt);
            }
            DirectoryNodeRecord::decode(digest, &encoded).map_err(Into::into)
        })
        .transpose()
}

fn load_file_head(
    connection: &Connection,
    branch_id: BranchId,
    object_id: ObjectId,
) -> Result<Option<BranchFileHead>, PublicationError> {
    let branch = branch_id.as_bytes();
    let object = object_id.as_bytes();
    let stored: Option<(Vec<u8>, Option<Vec<u8>>, i64)> = connection
        .query_row(
            "SELECT volume_id, current_version_id, head_sequence
             FROM branch_files WHERE branch_id = ?1 AND object_id = ?2",
            params![branch.as_slice(), object.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    stored
        .map(|values| {
            Ok(BranchFileHead {
                branch_id,
                object_id,
                volume_id: decode_identifier(&values.0, VolumeId::from_bytes)?,
                current_version_id: values
                    .1
                    .as_deref()
                    .map(|bytes| decode_identifier(bytes, FileVersionId::from_bytes))
                    .transpose()?,
                sequence: from_i64(values.2)?,
            })
        })
        .transpose()
}

fn publication_request_digest(publication: FilePublication) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.file-publication.v1\0");
    digest.update(&publication.operation_id.as_bytes());
    digest.update(&publication.branch_id.as_bytes());
    digest.update(&publication.volume_id.as_bytes());
    digest.update(&publication.object_id.as_bytes());
    update_optional_identifier(&mut digest, publication.expected_current_version_id);
    digest.update(&publication.version_id.as_bytes());
    update_optional_identifier(&mut digest, publication.parent_version_id);
    digest.update(&publication.manifest.manifest_id.as_bytes());
    digest.update(&publication.manifest.format_version.to_be_bytes());
    digest.update(&publication.manifest.logical_length.to_be_bytes());
    digest.update(&publication.manifest.content_digest);
    digest.update(&publication.manifest.root_digest);
    digest.update(&publication.created_by.as_bytes());
    digest.update(&publication.created_at.get().to_be_bytes());
    digest.finalize().into()
}

fn update_optional_identifier(digest: &mut blake3::Hasher, value: Option<FileVersionId>) {
    if let Some(value) = value {
        digest.update(&[1]);
        digest.update(&value.as_bytes());
    } else {
        digest.update(&[0]);
    }
}

fn configure(connection: &Connection) -> Result<(), PublicationError> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA recursive_triggers = OFF;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )?;
    Ok(())
}

fn migrate(connection: &mut Connection, applied_at: UnixMicros) -> Result<(), PublicationError> {
    let migration_table_exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'schema_migrations' LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let current: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current > SCHEMA_VERSION || (current == 0 && migration_table_exists) {
        return Err(PublicationError::Corrupt);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for migration in MIGRATIONS {
        let digest: [u8; 32] = blake3::hash(migration.sql.as_bytes()).into();
        if migration.version <= current {
            let stored: Vec<u8> = transaction.query_row(
                "SELECT migration_digest FROM schema_migrations WHERE version = ?1",
                [migration.version],
                |row| row.get(0),
            )?;
            if stored.as_slice() != digest {
                return Err(PublicationError::Corrupt);
            }
            continue;
        }
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, migration_digest, applied_at)
             VALUES (?1, ?2, ?3)",
            params![migration.version, digest.as_slice(), applied_at.get()],
        )?;
        transaction.pragma_update(None, "user_version", migration.version)?;
    }
    transaction.commit()?;
    Ok(())
}

fn verify_database(connection: &Connection) -> Result<(), PublicationError> {
    let quick: String = connection.pragma_query_value(None, "quick_check", |row| row.get(0))?;
    let foreign_key_violation = connection
        .prepare("PRAGMA foreign_key_check")?
        .query([])?
        .next()?
        .is_some();
    if quick == "ok" && !foreign_key_violation {
        Ok(())
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn decode_identifier<T, E>(
    bytes: &[u8],
    constructor: impl FnOnce([u8; 16]) -> Result<T, E>,
) -> Result<T, PublicationError> {
    constructor(bytes.try_into().map_err(|_| PublicationError::Corrupt)?)
        .map_err(|_| PublicationError::Corrupt)
}

fn copy_array(bytes: &[u8]) -> Result<[u8; 32], PublicationError> {
    bytes.try_into().map_err(|_| PublicationError::Corrupt)
}

fn to_i64(value: u64) -> Result<i64, PublicationError> {
    i64::try_from(value).map_err(|_| PublicationError::InvalidInput)
}

fn from_i64(value: i64) -> Result<u64, PublicationError> {
    u64::try_from(value).map_err(|_| PublicationError::Corrupt)
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod tests;
