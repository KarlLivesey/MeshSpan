// SPDX-License-Identifier: GPL-2.0-only

//! Fail-closed admission of signed remote mutation history before filesystem import.

use meshspan_domain::{
    FederatedMutationAcknowledgement, FederatedMutationAdmission, FederatedPrincipal,
    NamespaceCommitId, UnixMicros,
};
use meshspan_filesystem::{
    NamespaceHistoryCommitRecord, NamespaceHistoryMutationAuthority, NamespaceHistoryRecordError,
};
use meshspan_metadata::{AuthoritativeRepository, RepositoryError};
use thiserror::Error;

/// A structurally bound remote mutation and its authoritative admission decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederatedHistoryMutationAdmission {
    commit_id: NamespaceCommitId,
    actor: FederatedPrincipal,
    admission: FederatedMutationAdmission,
}

impl FederatedHistoryMutationAdmission {
    /// Returns the exact immutable commit which was classified.
    #[must_use]
    pub const fn commit_id(&self) -> NamespaceCommitId {
        self.commit_id
    }

    /// Returns the globally qualified remote actor.
    #[must_use]
    pub const fn actor(&self) -> FederatedPrincipal {
        self.actor
    }

    /// Returns whether the mutation may enter history or must remain invisible in quarantine.
    #[must_use]
    pub const fn admission(&self) -> FederatedMutationAdmission {
        self.admission
    }
}

/// Classifies signed remote history only after binding it to the exact immutable mutation shape.
///
/// Cheap structural checks precede signature and retained-authority verification. A mismatch is
/// rejected as hostile input; only an authentic acknowledgement can produce a quarantine result.
///
/// # Errors
///
/// Rejects malformed records, payload/operation/actor/resource/right substitution, impossible
/// time ordering, invalid signatures, unknown principals, or corrupt authoritative metadata.
pub fn classify_federated_history_mutation(
    repository: &AuthoritativeRepository,
    record: &NamespaceHistoryCommitRecord,
    acknowledgement: &FederatedMutationAcknowledgement,
    now: UnixMicros,
) -> Result<FederatedHistoryMutationAdmission, FederatedHistoryMutationAdmissionError> {
    let authority = record.mutation_authority()?;
    validate_binding(record, &authority, acknowledgement, now)?;
    let admission = repository.classify_federated_mutation_acknowledgement(acknowledgement)?;
    Ok(FederatedHistoryMutationAdmission {
        commit_id: authority.commit_id(),
        actor: acknowledgement.evidence.subject(),
        admission,
    })
}

fn validate_binding(
    record: &NamespaceHistoryCommitRecord,
    authority: &NamespaceHistoryMutationAuthority,
    acknowledgement: &FederatedMutationAcknowledgement,
    now: UnixMicros,
) -> Result<(), FederatedHistoryMutationAdmissionError> {
    let evidence = acknowledgement.evidence;
    if acknowledgement.source_operation_id != authority.operation_id()
        || acknowledgement.payload_digest != record.mutation_digest()?
        || evidence.subject().principal_id() != authority.created_by()
        || evidence.accepted_at() < authority.created_at()
        || evidence.accepted_at() > now
        || evidence.required_rights() != authority.required_rights()
        || evidence.storage_bytes() != 0
        || !authority.is_within(evidence.resource())
    {
        return Err(FederatedHistoryMutationAdmissionError::BindingMismatch);
    }
    Ok(())
}

/// Closed rejection classes for one remote history admission attempt.
#[derive(Debug, Error)]
pub enum FederatedHistoryMutationAdmissionError {
    /// The canonical history record was malformed or internally contradictory.
    #[error("federated history mutation record is invalid")]
    InvalidRecord(#[from] NamespaceHistoryRecordError),
    /// Signed evidence did not exactly describe the immutable mutation being presented.
    #[error("federated mutation acknowledgement does not match its history record")]
    BindingMismatch,
    /// The authoritative metadata proof was absent, invalid, or corrupt.
    #[error("federated mutation authority is unavailable")]
    Authority(#[from] RepositoryError),
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{
        BranchId, ContentManifestId, FederatedMutationAcknowledgement, FederatedMutationEvidence,
        FederatedPrincipal, FederationGrantId, FederationRelationshipId, FederationResourceScope,
        FileVersionId, MeshId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId,
        PrincipalId, Rights, UnixMicros, VolumeId,
    };
    use meshspan_filesystem::{
        FilePublication, ManifestPublication, NamespaceHistoryLimits, NamespaceLimits,
        NamespacePath, NamespacePublicationPath, RootFilePublication, VersionPublicationStore,
    };
    use tempfile::tempdir;

    use super::{FederatedHistoryMutationAdmissionError, validate_binding};

    #[test]
    fn immutable_record_binding_rejects_every_substitutable_dimension()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let publication = publication()?;
        let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
        store.publish_root_file(&publication)?;
        let bundle = store.export_namespace_history(
            publication.file.volume_id,
            &[publication.namespace_commit_id],
            &[],
            NamespaceHistoryLimits::DEFAULT,
        )?;
        let record = bundle
            .commit_records()?
            .into_iter()
            .next()
            .ok_or("history record missing")?;
        let authority = record.mutation_authority()?;
        let acknowledgement = acknowledgement(&publication, record.digest())?;
        validate_binding(&record, &authority, &acknowledgement, UnixMicros::new(30))?;

        let substitutions = [
            substitute_operation(acknowledgement)?,
            substitute_payload(acknowledgement),
            substitute_principal(acknowledgement)?,
            substitute_time(acknowledgement),
            substitute_rights(acknowledgement),
            substitute_storage(acknowledgement),
            substitute_resource(acknowledgement)?,
        ];
        for substituted in substitutions {
            assert!(matches!(
                validate_binding(&record, &authority, &substituted, UnixMicros::new(30)),
                Err(FederatedHistoryMutationAdmissionError::BindingMismatch)
            ));
        }
        Ok(())
    }

    fn acknowledgement(
        publication: &RootFilePublication,
        payload_digest: [u8; 32],
    ) -> Result<FederatedMutationAcknowledgement, Box<dyn std::error::Error>> {
        Ok(FederatedMutationAcknowledgement {
            source_operation_id: publication.file.operation_id,
            evidence: FederatedMutationEvidence::new(
                FederationGrantId::from_bytes([40; 16])?,
                FederationRelationshipId::from_bytes([41; 16])?,
                FederatedPrincipal::new(MeshId::from_bytes([42; 16])?, publication.file.created_by),
                FederationResourceScope::Volume {
                    owner_mesh_id: MeshId::from_bytes([43; 16])?,
                    volume_id: publication.file.volume_id,
                },
                1,
                publication.file.created_at,
                Rights::TRAVERSE
                    .union(Rights::CREATE_CHILD)
                    .union(Rights::WRITE_DATA),
                0,
            ),
            payload_digest,
            signer_generation: 1,
            signature: [0; 64],
        })
    }

    fn substitute_operation(
        mut value: FederatedMutationAcknowledgement,
    ) -> Result<FederatedMutationAcknowledgement, Box<dyn std::error::Error>> {
        value.source_operation_id = OperationId::from_bytes([50; 16])?;
        Ok(value)
    }

    const fn substitute_payload(
        mut value: FederatedMutationAcknowledgement,
    ) -> FederatedMutationAcknowledgement {
        value.payload_digest[0] ^= 1;
        value
    }

    fn substitute_principal(
        mut value: FederatedMutationAcknowledgement,
    ) -> Result<FederatedMutationAcknowledgement, Box<dyn std::error::Error>> {
        value.evidence = FederatedMutationEvidence::new(
            value.evidence.grant_id(),
            value.evidence.relationship_id(),
            FederatedPrincipal::new(
                value.evidence.subject().home_mesh_id(),
                PrincipalId::from_bytes([51; 16])?,
            ),
            value.evidence.resource(),
            value.evidence.authority_epoch(),
            value.evidence.accepted_at(),
            value.evidence.required_rights(),
            value.evidence.storage_bytes(),
        );
        Ok(value)
    }

    const fn substitute_time(
        mut value: FederatedMutationAcknowledgement,
    ) -> FederatedMutationAcknowledgement {
        value.evidence = FederatedMutationEvidence::new(
            value.evidence.grant_id(),
            value.evidence.relationship_id(),
            value.evidence.subject(),
            value.evidence.resource(),
            value.evidence.authority_epoch(),
            UnixMicros::new(31),
            value.evidence.required_rights(),
            value.evidence.storage_bytes(),
        );
        value
    }

    const fn substitute_rights(
        mut value: FederatedMutationAcknowledgement,
    ) -> FederatedMutationAcknowledgement {
        value.evidence = FederatedMutationEvidence::new(
            value.evidence.grant_id(),
            value.evidence.relationship_id(),
            value.evidence.subject(),
            value.evidence.resource(),
            value.evidence.authority_epoch(),
            value.evidence.accepted_at(),
            Rights::DELETE,
            value.evidence.storage_bytes(),
        );
        value
    }

    const fn substitute_storage(
        mut value: FederatedMutationAcknowledgement,
    ) -> FederatedMutationAcknowledgement {
        value.evidence = FederatedMutationEvidence::new(
            value.evidence.grant_id(),
            value.evidence.relationship_id(),
            value.evidence.subject(),
            value.evidence.resource(),
            value.evidence.authority_epoch(),
            value.evidence.accepted_at(),
            value.evidence.required_rights(),
            1,
        );
        value
    }

    fn substitute_resource(
        mut value: FederatedMutationAcknowledgement,
    ) -> Result<FederatedMutationAcknowledgement, Box<dyn std::error::Error>> {
        value.evidence = FederatedMutationEvidence::new(
            value.evidence.grant_id(),
            value.evidence.relationship_id(),
            value.evidence.subject(),
            FederationResourceScope::Volume {
                owner_mesh_id: value.evidence.resource().authority_mesh_id(),
                volume_id: VolumeId::from_bytes([52; 16])?,
            },
            value.evidence.authority_epoch(),
            value.evidence.accepted_at(),
            value.evidence.required_rights(),
            value.evidence.storage_bytes(),
        );
        Ok(value)
    }

    fn publication() -> Result<RootFilePublication, Box<dyn std::error::Error>> {
        Ok(RootFilePublication {
            file: FilePublication {
                operation_id: OperationId::from_bytes([20; 16])?,
                branch_id: BranchId::from_bytes([21; 16])?,
                volume_id: VolumeId::from_bytes([22; 16])?,
                object_id: ObjectId::from_bytes([23; 16])?,
                expected_current_version_id: None,
                version_id: FileVersionId::from_bytes([24; 16])?,
                parent_version_id: None,
                retain_superseded_history: true,
                retention_policy_sequence: 1,
                manifest: ManifestPublication {
                    manifest_id: ContentManifestId::from_bytes([25; 16])?,
                    format_version: 1,
                    logical_length: 4,
                    content_digest: [26; 32],
                    root_digest: [27; 32],
                },
                created_by: PrincipalId::from_bytes([28; 16])?,
                created_at: UnixMicros::new(20),
            },
            root_object_id: ObjectId::from_bytes([29; 16])?,
            expected_namespace_commit_id: None,
            expected_file_object_revision_id: None,
            file_object_revision_id: ObjectRevisionId::from_bytes([30; 16])?,
            root_object_revision_id: ObjectRevisionId::from_bytes([31; 16])?,
            namespace_commit_id: NamespaceCommitId::from_bytes([32; 16])?,
            path: NamespacePublicationPath::new(
                NamespacePath::from_components(["report"], NamespaceLimits::PORTABLE)?,
                Vec::new(),
            )?,
            entry_generation: 1,
        })
    }
}
