// SPDX-License-Identifier: GPL-2.0-only

//! Canonical, independently validated records for private history transport.

#[path = "history_records/decode.rs"]
mod decode;
#[path = "history_records/encode.rs"]
mod encode;
#[path = "history_records/immutable.rs"]
pub(in crate::publication) mod immutable;

use meshspan_domain::{
    FederationResourceScope, NamespaceCommitId, ObjectId, OperationId, PrincipalId, Rights,
    UnixMicros, VolumeId,
};
use thiserror::Error;

use self::decode::decode_commit;
use self::encode::encode_commit;
pub use self::immutable::{NamespaceHistoryImmutableKind, NamespaceHistoryImmutableRecord};
use super::transfer::TransferredMutationCommit;
use crate::NamespaceHistoryBundle;

const MAXIMUM_COMMIT_RECORD_BYTES: usize = 2 * 1_024 * 1_024;
const COMMIT_DOMAIN: &[u8] = b"meshspan.filesystem.history-commit\0";
const COMMIT_FORMAT_VERSION: u8 = 1;

/// One canonical immutable mutation record suitable for a bounded control page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryCommitRecord {
    canonical_bytes: Vec<u8>,
    digest: [u8; 32],
}

/// Authority-relevant facts independently decoded from one immutable history record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceHistoryMutationAuthority {
    commit_id: NamespaceCommitId,
    operation_id: OperationId,
    volume_id: VolumeId,
    object_id: ObjectId,
    target_ancestors: Vec<ObjectId>,
    source_ancestors: Option<Vec<ObjectId>>,
    created_by: PrincipalId,
    created_at: UnixMicros,
    required_rights: Rights,
}

impl NamespaceHistoryMutationAuthority {
    /// Returns the immutable namespace commit identity.
    #[must_use]
    pub const fn commit_id(&self) -> NamespaceCommitId {
        self.commit_id
    }

    /// Returns the source operation bound into the commit.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the unqualified principal identity; federation admission supplies its home swarm.
    #[must_use]
    pub const fn created_by(&self) -> PrincipalId {
        self.created_by
    }

    /// Returns when the source committed the mutation.
    #[must_use]
    pub const fn created_at(&self) -> UnixMicros {
        self.created_at
    }

    /// Returns the exact rights exercised by this mutation shape.
    #[must_use]
    pub const fn required_rights(&self) -> Rights {
        self.required_rights
    }

    /// Reports whether the mutation stays completely inside the declared namespace resource.
    #[must_use]
    pub fn is_within(&self, resource: FederationResourceScope) -> bool {
        match resource {
            FederationResourceScope::Volume { volume_id, .. } => self.volume_id == volume_id,
            FederationResourceScope::File {
                volume_id,
                object_id,
                ..
            } => self.volume_id == volume_id && self.object_id == object_id,
            FederationResourceScope::Subtree {
                volume_id,
                root_object_id,
                ..
            } => {
                self.volume_id == volume_id
                    && self.target_ancestors.contains(&root_object_id)
                    && self
                        .source_ancestors
                        .as_ref()
                        .is_none_or(|ancestors| ancestors.contains(&root_object_id))
            }
            FederationResourceScope::StorageCapacity { .. } => false,
        }
    }
}

impl NamespaceHistoryCommitRecord {
    /// Revalidates untrusted canonical bytes and derives their stable content identity.
    ///
    /// # Errors
    ///
    /// Rejects oversized, truncated, trailing, non-canonical or internally inconsistent records.
    pub fn from_canonical_bytes(
        canonical_bytes: Vec<u8>,
    ) -> Result<Self, NamespaceHistoryRecordError> {
        decode_commit(&canonical_bytes)?;
        Ok(Self::new_validated(canonical_bytes))
    }

    /// Exact versioned bytes carried by a private federation control page.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// BLAKE3 identity of the complete domain-separated canonical record.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Decodes only the facts required for federation admission from the canonical record.
    ///
    /// # Errors
    ///
    /// Rejects any malformed or internally inconsistent record.
    pub fn mutation_authority(
        &self,
    ) -> Result<NamespaceHistoryMutationAuthority, NamespaceHistoryRecordError> {
        let record = self.decoded()?;
        let intent = &record.intent;
        let required_rights = mutation_rights(intent);
        Ok(NamespaceHistoryMutationAuthority {
            commit_id: record.commit.commit_id,
            operation_id: record.commit.operation_id,
            volume_id: record.commit.volume_id,
            object_id: intent.object_id,
            target_ancestors: intent
                .ancestors
                .iter()
                .map(|transition| transition.object_id())
                .collect(),
            source_ancestors: intent.rename.as_ref().map(|rename| {
                rename
                    .source_ancestors
                    .iter()
                    .map(|transition| transition.object_id())
                    .collect()
            }),
            created_by: record.created_by,
            created_at: record.created_at,
            required_rights,
        })
    }

    pub(in crate::publication) fn from_commit(
        commit: &TransferredMutationCommit,
    ) -> Result<Self, NamespaceHistoryRecordError> {
        let canonical_bytes = encode_commit(commit)?;
        if canonical_bytes.len() > MAXIMUM_COMMIT_RECORD_BYTES {
            return Err(NamespaceHistoryRecordError::BoundsExceeded);
        }
        Ok(Self::new_validated(canonical_bytes))
    }

    fn new_validated(canonical_bytes: Vec<u8>) -> Self {
        let digest = blake3::hash(&canonical_bytes).into();
        Self {
            canonical_bytes,
            digest,
        }
    }

    pub(in crate::publication) fn decoded(
        &self,
    ) -> Result<TransferredMutationCommit, NamespaceHistoryRecordError> {
        decode_commit(&self.canonical_bytes)
    }
}

fn mutation_rights(intent: &crate::BranchMutationIntent) -> Rights {
    let traverse = Rights::TRAVERSE;
    if intent.rename.is_some() {
        return traverse.union(Rights::RENAME).union(Rights::CREATE_CHILD);
    }
    match intent.mutation {
        crate::BranchMutation::File { .. } if intent.prior_object_revision_id.is_none() => traverse
            .union(Rights::CREATE_CHILD)
            .union(Rights::WRITE_DATA),
        crate::BranchMutation::File { .. } => traverse.union(Rights::WRITE_DATA),
        crate::BranchMutation::CreateDirectory => traverse.union(Rights::CREATE_CHILD),
        crate::BranchMutation::DeleteFile { .. } | crate::BranchMutation::DeleteDirectory => {
            traverse.union(Rights::DELETE)
        }
    }
}

impl NamespaceHistoryBundle {
    /// Encodes each mutation commit independently without embedding immutable object bytes.
    ///
    /// # Errors
    ///
    /// Rejects a record whose path or collection sizes exceed the canonical transfer format.
    pub fn commit_records(
        &self,
    ) -> Result<Vec<NamespaceHistoryCommitRecord>, NamespaceHistoryRecordError> {
        self.commits
            .iter()
            .map(NamespaceHistoryCommitRecord::from_commit)
            .collect()
    }

    /// Encodes every referenced immutable body as one independently content-addressed record.
    ///
    /// # Errors
    ///
    /// Rejects invalid object shape or any canonical body exceeding its fixed allocation bound.
    pub fn immutable_records(
        &self,
    ) -> Result<Vec<NamespaceHistoryImmutableRecord>, NamespaceHistoryRecordError> {
        let mut records = Vec::with_capacity(self.immutable_record_count());
        for node in &self.directory_nodes {
            records.push(NamespaceHistoryImmutableRecord::directory(node)?);
        }
        for manifest in &self.manifests {
            records.push(NamespaceHistoryImmutableRecord::manifest(*manifest)?);
        }
        for version in &self.file_versions {
            records.push(NamespaceHistoryImmutableRecord::file_version(*version)?);
        }
        for revision in &self.object_revisions {
            records.push(NamespaceHistoryImmutableRecord::object_revision(*revision)?);
        }
        Ok(records)
    }
}

/// Closed failures while encoding or validating one canonical history record.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum NamespaceHistoryRecordError {
    /// A record exceeded a fixed allocation or collection bound.
    #[error("namespace history record exceeds its bounds")]
    BoundsExceeded,
    /// A record was truncated, trailing, non-canonical or internally contradictory.
    #[error("namespace history record is invalid")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{
        BranchId, FederationResourceScope, FileVersionId, MeshId, NamespaceCommitId, ObjectId,
        ObjectRevisionId, OperationId, PrincipalId, Rights, UnixMicros, VolumeId,
    };

    use super::super::repository::{StoredCommit, stored_commit_digest};
    use super::super::transfer::TransferredMutationCommit;
    use super::{NamespaceHistoryCommitRecord, NamespaceHistoryRecordError};
    use crate::{
        BranchMutation, BranchMutationIntent, BranchRenameIntent, DirectoryRevisionTransition,
        NamespaceLimits, NamespacePath, ReconciliationCommit, ReconciliationCommitPayload,
    };

    #[test]
    fn every_mutation_shape_round_trips_with_optional_rename()
    -> Result<(), Box<dyn std::error::Error>> {
        let version = FileVersionId::from_bytes([20; 16])?;
        let mutations = [
            BranchMutation::File {
                version_id: version,
            },
            BranchMutation::CreateDirectory,
            BranchMutation::DeleteFile {
                version_id: version,
            },
            BranchMutation::DeleteDirectory,
        ];
        for (index, mutation) in mutations.into_iter().enumerate() {
            let seed = u8::try_from(index)?.saturating_add(30);
            let original = record(seed, mutation, index == 0)?;
            let encoded = NamespaceHistoryCommitRecord::from_commit(&original)?;
            assert_eq!(encoded.decoded()?, original);
        }
        Ok(())
    }

    #[test]
    fn altered_bound_fields_and_excess_input_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let original = record(40, BranchMutation::CreateDirectory, false)?;
        let encoded = NamespaceHistoryCommitRecord::from_commit(&original)?;
        let mut altered = encoded.canonical_bytes().to_vec();
        let position = find_subslice(&altered, &original.commit.request_digest)
            .ok_or(NamespaceHistoryRecordError::Invalid)?;
        altered[position] ^= 1;
        assert!(NamespaceHistoryCommitRecord::from_canonical_bytes(altered).is_err());
        assert!(matches!(
            NamespaceHistoryCommitRecord::from_canonical_bytes(vec![0; 2 * 1_024 * 1_024 + 1]),
            Err(NamespaceHistoryRecordError::BoundsExceeded)
        ));
        Ok(())
    }

    #[test]
    fn mutation_authority_derives_exact_rights_and_resource_containment()
    -> Result<(), Box<dyn std::error::Error>> {
        let seed = 70;
        let original = record(
            seed,
            BranchMutation::File {
                version_id: FileVersionId::from_bytes([90; 16])?,
            },
            true,
        )?;
        let encoded = NamespaceHistoryCommitRecord::from_commit(&original)?;
        let authority = encoded.mutation_authority()?;
        assert_eq!(authority.commit_id(), original.commit.commit_id);
        assert_eq!(authority.operation_id(), original.commit.operation_id);
        assert_eq!(authority.created_by(), original.created_by);
        assert_eq!(authority.created_at(), original.created_at);
        assert_eq!(
            authority.required_rights(),
            Rights::TRAVERSE
                .union(Rights::RENAME)
                .union(Rights::CREATE_CHILD)
        );

        let owner = MeshId::from_bytes([91; 16])?;
        assert!(authority.is_within(FederationResourceScope::Volume {
            owner_mesh_id: owner,
            volume_id: original.commit.volume_id,
        }));
        assert!(authority.is_within(FederationResourceScope::File {
            owner_mesh_id: owner,
            volume_id: original.commit.volume_id,
            object_id: original.intent.object_id,
        }));
        assert!(!authority.is_within(FederationResourceScope::Subtree {
            owner_mesh_id: owner,
            volume_id: original.commit.volume_id,
            root_object_id: original.intent.ancestors[0].object_id(),
        }));
        assert!(
            !authority.is_within(FederationResourceScope::StorageCapacity {
                provider_mesh_id: owner,
            })
        );
        Ok(())
    }

    #[test]
    fn mutation_authority_distinguishes_create_write_and_delete()
    -> Result<(), Box<dyn std::error::Error>> {
        let version_id = FileVersionId::from_bytes([100; 16])?;
        let mut create = record(80, BranchMutation::File { version_id }, false)?;
        create.intent.prior_object_revision_id = None;
        create.commit.payload = ReconciliationCommitPayload::Mutation {
            intent_digest: create.intent.digest(),
        };
        assert_eq!(
            NamespaceHistoryCommitRecord::from_commit(&create)?
                .mutation_authority()?
                .required_rights(),
            Rights::TRAVERSE
                .union(Rights::CREATE_CHILD)
                .union(Rights::WRITE_DATA)
        );
        assert_eq!(
            NamespaceHistoryCommitRecord::from_commit(&record(
                81,
                BranchMutation::File { version_id },
                false,
            )?)?
            .mutation_authority()?
            .required_rights(),
            Rights::TRAVERSE.union(Rights::WRITE_DATA)
        );
        assert_eq!(
            NamespaceHistoryCommitRecord::from_commit(&record(
                82,
                BranchMutation::DeleteFile { version_id },
                false,
            )?)?
            .mutation_authority()?
            .required_rights(),
            Rights::TRAVERSE.union(Rights::DELETE)
        );
        Ok(())
    }

    fn record(
        seed: u8,
        mutation: BranchMutation,
        with_rename: bool,
    ) -> Result<TransferredMutationCommit, Box<dyn std::error::Error>> {
        let commit_id = NamespaceCommitId::from_bytes([seed; 16])?;
        let branch_id = BranchId::from_bytes([seed.saturating_add(1); 16])?;
        let volume_id = VolumeId::from_bytes([seed.saturating_add(2); 16])?;
        let root_object_id = ObjectId::from_bytes([seed.saturating_add(3); 16])?;
        let root_revision = ObjectRevisionId::from_bytes([seed.saturating_add(4); 16])?;
        let created_by = PrincipalId::from_bytes([seed.saturating_add(5); 16])?;
        let operation_id = OperationId::from_bytes([seed.saturating_add(6); 16])?;
        let created_at = UnixMicros::new(i64::from(seed));
        let intent = intent(seed, commit_id, mutation, with_rename)?;
        let request_digest = [seed.saturating_add(7); 32];
        let stored = StoredCommit {
            commit_id,
            branch_id,
            volume_id,
            root_object_id,
            root_object_revision_id: root_revision,
            parent_id: None,
            created_by,
            operation_id,
            created_at,
        };
        let commit = ReconciliationCommit {
            commit_id,
            branch_id,
            volume_id,
            root_object_id,
            root_object_revision_id: root_revision,
            parents: Vec::new(),
            operation_id,
            request_digest,
            payload: ReconciliationCommitPayload::Mutation {
                intent_digest: intent.digest(),
            },
        };
        Ok(TransferredMutationCommit {
            commit,
            created_by,
            created_at,
            commit_digest: stored_commit_digest(&stored, request_digest),
            intent,
        })
    }

    fn intent(
        seed: u8,
        commit_id: NamespaceCommitId,
        mutation: BranchMutation,
        with_rename: bool,
    ) -> Result<BranchMutationIntent, Box<dyn std::error::Error>> {
        let transition = DirectoryRevisionTransition::new(
            ObjectId::from_bytes([seed.saturating_add(8); 16])?,
            ObjectRevisionId::from_bytes([seed.saturating_add(9); 16])?,
            ObjectRevisionId::from_bytes([seed.saturating_add(10); 16])?,
        )?;
        let rename = with_rename.then(|| rename_intent(seed)).transpose()?;
        Ok(BranchMutationIntent {
            commit_id,
            path: NamespacePath::from_components(
                ["destination", "file"],
                NamespaceLimits::PORTABLE,
            )?,
            ancestors: vec![transition],
            object_id: ObjectId::from_bytes([seed.saturating_add(11); 16])?,
            object_revision_id: ObjectRevisionId::from_bytes([seed.saturating_add(12); 16])?,
            prior_object_revision_id: Some(ObjectRevisionId::from_bytes(
                [seed.saturating_add(13); 16],
            )?),
            entry_generation: 2,
            mutation,
            rename,
        })
    }

    fn rename_intent(seed: u8) -> Result<BranchRenameIntent, Box<dyn std::error::Error>> {
        Ok(BranchRenameIntent {
            source_path: NamespacePath::from_components(
                ["source", "file"],
                NamespaceLimits::PORTABLE,
            )?,
            source_ancestors: vec![DirectoryRevisionTransition::new(
                ObjectId::from_bytes([seed.saturating_add(14); 16])?,
                ObjectRevisionId::from_bytes([seed.saturating_add(15); 16])?,
                ObjectRevisionId::from_bytes([seed.saturating_add(16); 16])?,
            )?],
            source_entry_generation: 1,
            intermediate_root_object_revision_id: ObjectRevisionId::from_bytes(
                [seed.saturating_add(17); 16],
            )?,
        })
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|candidate| candidate == needle)
    }
}
