// SPDX-License-Identifier: GPL-2.0-only

//! Immutable branch-local persistence for signed federated mutation acknowledgements.

use meshspan_domain::{
    FederatedMutationAcknowledgement, FederatedMutationEvidence, FederatedPrincipal,
    FederationGrantId, FederationRelationshipId, FederationResourceScope, MeshId, ObjectId,
    OperationId, PrincipalId, Rights, UnixMicros, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::NamespaceIntent;
use super::history_records::NamespaceHistoryCommitRecord;
use super::repository::{StoredCommit, stored_commit_digest};
use super::transfer::TransferredMutationCommit;
use super::transfer::export::load_bare_commit_record;
use crate::{
    BranchMutationIntent, FederatedNamespaceMutationProposal, PublicationError,
    ReconciliationCommit, ReconciliationCommitPayload,
};

pub(super) fn mutation_digest(
    namespace: NamespaceIntent<'_>,
    request_digest: [u8; 32],
    intent: BranchMutationIntent,
) -> Result<[u8; 32], PublicationError> {
    Ok(mutation_proposal(namespace, request_digest, intent)?.payload_digest())
}

pub(super) fn mutation_proposal(
    namespace: NamespaceIntent<'_>,
    request_digest: [u8; 32],
    intent: BranchMutationIntent,
) -> Result<FederatedNamespaceMutationProposal, PublicationError> {
    let stored = StoredCommit {
        commit_id: namespace.commit_id,
        branch_id: namespace.branch_id,
        volume_id: namespace.volume_id,
        root_object_id: namespace.root_object_id,
        root_object_revision_id: namespace.root_revision_id,
        parent_id: namespace.expected_commit_id,
        created_by: namespace.created_by,
        operation_id: namespace.operation_id,
        created_at: namespace.created_at,
    };
    let record = TransferredMutationCommit {
        commit: ReconciliationCommit {
            commit_id: namespace.commit_id,
            branch_id: namespace.branch_id,
            volume_id: namespace.volume_id,
            root_object_id: namespace.root_object_id,
            root_object_revision_id: namespace.root_revision_id,
            parents: namespace.expected_commit_id.into_iter().collect(),
            operation_id: namespace.operation_id,
            request_digest,
            payload: ReconciliationCommitPayload::Mutation {
                intent_digest: intent.digest(),
            },
        },
        created_by: namespace.created_by,
        created_at: namespace.created_at,
        commit_digest: stored_commit_digest(&stored, request_digest),
        intent,
        acknowledgement: None,
    };
    let record = NamespaceHistoryCommitRecord::from_commit(&record)
        .map_err(|_| PublicationError::InvalidInput)?;
    FederatedNamespaceMutationProposal::from_record(&record)
        .map_err(|_| PublicationError::InvalidInput)
}

pub(super) fn ensure_exact(
    connection: &Connection,
    namespace_commit_id: meshspan_domain::NamespaceCommitId,
    expected: Option<&FederatedMutationAcknowledgement>,
) -> Result<(), PublicationError> {
    let stored = load(connection, namespace_commit_id)?;
    if stored.as_ref() == expected {
        Ok(())
    } else {
        Err(PublicationError::OperationConflict)
    }
}

pub(super) fn persist(
    transaction: &Transaction<'_>,
    namespace_commit_id: meshspan_domain::NamespaceCommitId,
    acknowledgement: &FederatedMutationAcknowledgement,
) -> Result<(), PublicationError> {
    let record = load_bare_commit_record(
        transaction,
        volume_id(acknowledgement.evidence.resource())?,
        namespace_commit_id,
    )?;
    let canonical = NamespaceHistoryCommitRecord::from_commit(&record)
        .map_err(|_| PublicationError::Corrupt)?;
    validate(&canonical, acknowledgement)?;
    if let Some(existing) = load_row(transaction, namespace_commit_id)? {
        return if existing == *acknowledgement {
            Ok(())
        } else {
            Err(PublicationError::OperationConflict)
        };
    }
    let evidence = acknowledgement.evidence;
    let (resource_kind, authority_mesh_id, volume_id, object_id) =
        resource_columns(evidence.resource())?;
    let acknowledgement_digest: [u8; 32] = blake3::hash(&acknowledgement.signing_payload()).into();
    transaction.execute(
        "INSERT INTO federated_namespace_mutation_acknowledgements(
            namespace_commit_id, source_operation_id, grant_id, relationship_id,
            subject_home_mesh_id, subject_principal_id, resource_kind, authority_mesh_id,
            volume_id, object_id, authority_epoch, accepted_at, required_rights, storage_bytes,
            payload_digest, signer_generation, signature, acknowledgement_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                   ?15, ?16, ?17, ?18)",
        params![
            namespace_commit_id.as_bytes().as_slice(),
            acknowledgement.source_operation_id.as_bytes().as_slice(),
            evidence.grant_id().as_bytes().as_slice(),
            evidence.relationship_id().as_bytes().as_slice(),
            evidence.subject().home_mesh_id().as_bytes().as_slice(),
            evidence.subject().principal_id().as_bytes().as_slice(),
            resource_kind,
            authority_mesh_id.as_bytes().as_slice(),
            volume_id.as_bytes().as_slice(),
            object_id
                .map(ObjectId::as_bytes)
                .as_ref()
                .map(<[u8; 16]>::as_slice),
            to_i64(evidence.authority_epoch())?,
            evidence.accepted_at().get(),
            i64::from(evidence.required_rights().bits()),
            to_i64(evidence.storage_bytes())?,
            acknowledgement.payload_digest.as_slice(),
            to_i64(acknowledgement.signer_generation)?,
            acknowledgement.signature.as_slice(),
            acknowledgement_digest.as_slice(),
        ],
    )?;
    Ok(())
}

pub(super) fn load(
    connection: &Connection,
    namespace_commit_id: meshspan_domain::NamespaceCommitId,
) -> Result<Option<FederatedMutationAcknowledgement>, PublicationError> {
    let acknowledgement = load_row(connection, namespace_commit_id)?;
    if let Some(acknowledgement) = acknowledgement {
        let record = load_bare_commit_record(
            connection,
            volume_id(acknowledgement.evidence.resource())?,
            namespace_commit_id,
        )?;
        let canonical = NamespaceHistoryCommitRecord::from_commit(&record)
            .map_err(|_| PublicationError::Corrupt)?;
        validate(&canonical, &acknowledgement).map_err(|_| PublicationError::Corrupt)?;
        Ok(Some(acknowledgement))
    } else {
        Ok(None)
    }
}

fn validate(
    record: &NamespaceHistoryCommitRecord,
    acknowledgement: &FederatedMutationAcknowledgement,
) -> Result<(), PublicationError> {
    let authority = record
        .mutation_authority()
        .map_err(|_| PublicationError::Corrupt)?;
    let evidence = acknowledgement.evidence;
    if acknowledgement.signer_generation == 0
        || acknowledgement.signature == [0; 64]
        || acknowledgement.source_operation_id != authority.operation_id()
        || acknowledgement.payload_digest != record.digest()
        || evidence.subject().principal_id() != authority.created_by()
        || evidence.accepted_at() < authority.created_at()
        || evidence.required_rights() != authority.required_rights()
        || evidence.storage_bytes() != 0
        || !authority.is_within(evidence.resource())
    {
        return Err(PublicationError::InvalidInput);
    }
    Ok(())
}

fn load_row(
    connection: &Connection,
    namespace_commit_id: meshspan_domain::NamespaceCommitId,
) -> Result<Option<FederatedMutationAcknowledgement>, PublicationError> {
    let row = connection
        .query_row(
            "SELECT source_operation_id, grant_id, relationship_id, subject_home_mesh_id,
                    subject_principal_id, resource_kind, authority_mesh_id, volume_id, object_id,
                    authority_epoch, accepted_at, required_rights, storage_bytes, payload_digest,
                    signer_generation, signature, acknowledgement_digest
             FROM federated_namespace_mutation_acknowledgements
             WHERE namespace_commit_id = ?1",
            [namespace_commit_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredRow {
                    source_operation_id: row.get(0)?,
                    grant_id: row.get(1)?,
                    relationship_id: row.get(2)?,
                    subject_home_mesh_id: row.get(3)?,
                    subject_principal_id: row.get(4)?,
                    resource_kind: row.get(5)?,
                    authority_mesh_id: row.get(6)?,
                    volume_id: row.get(7)?,
                    object_id: row.get(8)?,
                    authority_epoch: row.get(9)?,
                    accepted_at: row.get(10)?,
                    required_rights: row.get(11)?,
                    storage_bytes: row.get(12)?,
                    payload_digest: row.get(13)?,
                    signer_generation: row.get(14)?,
                    signature: row.get(15)?,
                    acknowledgement_digest: row.get(16)?,
                })
            },
        )
        .optional()?;
    row.map(parse_row).transpose()
}

fn parse_row(row: StoredRow) -> Result<FederatedMutationAcknowledgement, PublicationError> {
    let evidence = FederatedMutationEvidence::new(
        identifier(&row.grant_id, FederationGrantId::from_bytes)?,
        identifier(&row.relationship_id, FederationRelationshipId::from_bytes)?,
        FederatedPrincipal::new(
            identifier(&row.subject_home_mesh_id, MeshId::from_bytes)?,
            identifier(&row.subject_principal_id, PrincipalId::from_bytes)?,
        ),
        parse_resource(&row)?,
        positive(row.authority_epoch)?,
        UnixMicros::new(row.accepted_at),
        Rights::from_bits(
            u32::try_from(row.required_rights).map_err(|_| PublicationError::Corrupt)?,
        )
        .map_err(|_| PublicationError::Corrupt)?,
        nonnegative(row.storage_bytes)?,
    );
    let acknowledgement = FederatedMutationAcknowledgement {
        source_operation_id: identifier(&row.source_operation_id, OperationId::from_bytes)?,
        evidence,
        payload_digest: array(&row.payload_digest)?,
        signer_generation: positive(row.signer_generation)?,
        signature: row
            .signature
            .try_into()
            .map_err(|_| PublicationError::Corrupt)?,
    };
    let digest: [u8; 32] = blake3::hash(&acknowledgement.signing_payload()).into();
    if row.acknowledgement_digest.as_slice() != digest {
        return Err(PublicationError::Corrupt);
    }
    Ok(acknowledgement)
}

struct StoredRow {
    source_operation_id: Vec<u8>,
    grant_id: Vec<u8>,
    relationship_id: Vec<u8>,
    subject_home_mesh_id: Vec<u8>,
    subject_principal_id: Vec<u8>,
    resource_kind: i64,
    authority_mesh_id: Vec<u8>,
    volume_id: Vec<u8>,
    object_id: Option<Vec<u8>>,
    authority_epoch: i64,
    accepted_at: i64,
    required_rights: i64,
    storage_bytes: i64,
    payload_digest: Vec<u8>,
    signer_generation: i64,
    signature: Vec<u8>,
    acknowledgement_digest: Vec<u8>,
}

fn parse_resource(row: &StoredRow) -> Result<FederationResourceScope, PublicationError> {
    let authority = identifier(&row.authority_mesh_id, MeshId::from_bytes)?;
    let volume = identifier(&row.volume_id, VolumeId::from_bytes)?;
    match (row.resource_kind, row.object_id.as_deref()) {
        (1, None) => Ok(FederationResourceScope::Volume {
            owner_mesh_id: authority,
            volume_id: volume,
        }),
        (2, Some(object)) => Ok(FederationResourceScope::Subtree {
            owner_mesh_id: authority,
            volume_id: volume,
            root_object_id: identifier(object, ObjectId::from_bytes)?,
        }),
        (3, Some(object)) => Ok(FederationResourceScope::File {
            owner_mesh_id: authority,
            volume_id: volume,
            object_id: identifier(object, ObjectId::from_bytes)?,
        }),
        _ => Err(PublicationError::Corrupt),
    }
}

fn resource_columns(
    resource: FederationResourceScope,
) -> Result<(i64, MeshId, VolumeId, Option<ObjectId>), PublicationError> {
    match resource {
        FederationResourceScope::Volume {
            owner_mesh_id,
            volume_id,
        } => Ok((1, owner_mesh_id, volume_id, None)),
        FederationResourceScope::Subtree {
            owner_mesh_id,
            volume_id,
            root_object_id,
        } => Ok((2, owner_mesh_id, volume_id, Some(root_object_id))),
        FederationResourceScope::File {
            owner_mesh_id,
            volume_id,
            object_id,
        } => Ok((3, owner_mesh_id, volume_id, Some(object_id))),
        FederationResourceScope::StorageCapacity { .. } => Err(PublicationError::InvalidInput),
    }
}

fn volume_id(resource: FederationResourceScope) -> Result<VolumeId, PublicationError> {
    match resource {
        FederationResourceScope::Volume { volume_id, .. }
        | FederationResourceScope::Subtree { volume_id, .. }
        | FederationResourceScope::File { volume_id, .. } => Ok(volume_id),
        FederationResourceScope::StorageCapacity { .. } => Err(PublicationError::InvalidInput),
    }
}

fn identifier<T, E>(
    bytes: &[u8],
    parse: impl FnOnce([u8; 16]) -> Result<T, E>,
) -> Result<T, PublicationError> {
    parse(bytes.try_into().map_err(|_| PublicationError::Corrupt)?)
        .map_err(|_| PublicationError::Corrupt)
}

fn array(bytes: &[u8]) -> Result<[u8; 32], PublicationError> {
    bytes.try_into().map_err(|_| PublicationError::Corrupt)
}

fn positive(value: i64) -> Result<u64, PublicationError> {
    let value = u64::try_from(value).map_err(|_| PublicationError::Corrupt)?;
    if value == 0 {
        Err(PublicationError::Corrupt)
    } else {
        Ok(value)
    }
}

fn nonnegative(value: i64) -> Result<u64, PublicationError> {
    u64::try_from(value).map_err(|_| PublicationError::Corrupt)
}

fn to_i64(value: u64) -> Result<i64, PublicationError> {
    i64::try_from(value).map_err(|_| PublicationError::InvalidInput)
}
