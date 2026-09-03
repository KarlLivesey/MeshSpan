// SPDX-License-Identifier: GPL-2.0-only

//! Canonical publication identities, catalogue records and receipt validation.

use meshspan_backup::BackupFileEvidence;
use meshspan_contracts::{
    BackupObjectIdentity, BackupObjectReceipt, ContractVersion, RequestContext,
};
use meshspan_domain::{
    AuditEventId, BackupDestinationId, OperationId, PrincipalId, Revision, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, BackupCopyRecord, BackupCopyState, CommandContext, CommandReceipt,
    EntityKind, InitialBackupCopy, MetadataBackupRecord, MetadataBackupState, RecordMetadataBackup,
};
use sha2::{Digest, Sha256};

use super::BackupPublicationError;

#[derive(Clone, Copy)]
pub(super) enum PublicationStep {
    RecordBackup,
    StoreProvider,
    VerifyProvider,
    VerifyCopy,
}

impl PublicationStep {
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::RecordBackup => b"meshspan.backup-publication.record-backup.v1\0",
            Self::StoreProvider => b"meshspan.backup-publication.store-provider.v1\0",
            Self::VerifyProvider => b"meshspan.backup-publication.verify-provider.v1\0",
            Self::VerifyCopy => b"meshspan.backup-publication.verify-copy.v1\0",
        }
    }
}

pub(super) fn record_backup(
    evidence: BackupFileEvidence,
    receipt: &BackupObjectReceipt,
) -> RecordMetadataBackup {
    RecordMetadataBackup {
        backup_id: evidence.source.backup_id,
        partition_id: evidence.source.partition_id,
        mesh_id: evidence.source.mesh_id,
        last_log_index: evidence.source.last_log_index,
        last_log_term: evidence.source.last_log_term,
        state_revision: Revision::new(evidence.source.state_revision),
        schema_version: evidence.source.schema_version,
        source_byte_length: evidence.source.byte_length,
        source_digest: evidence.source.digest,
        manifest_digest: evidence.source.catalogue_digest(),
        encrypted_byte_length: evidence.byte_length,
        encrypted_digest: evidence.digest,
        initial_copy: InitialBackupCopy {
            destination_id: receipt.object.destination_id,
            provider_generation: receipt.object.provider_generation,
            object_reference: receipt.object_reference.as_str().to_owned(),
            byte_length: receipt.object.byte_length,
            copy_digest: receipt.object.digest,
        },
    }
}

pub(super) fn object_identity(
    evidence: BackupFileEvidence,
    destination_id: BackupDestinationId,
    provider_generation: u64,
) -> BackupObjectIdentity {
    BackupObjectIdentity {
        backup_id: evidence.source.backup_id,
        destination_id,
        provider_generation,
        byte_length: evidence.byte_length,
        digest: evidence.digest,
    }
}

pub(super) fn validate_backup(
    backup: MetadataBackupRecord,
    evidence: BackupFileEvidence,
) -> Result<MetadataBackupRecord, BackupPublicationError> {
    let source = evidence.source;
    if backup.backup_id == source.backup_id
        && backup.partition_id == source.partition_id
        && backup.mesh_id == source.mesh_id
        && backup.last_log_index == source.last_log_index
        && backup.last_log_term == source.last_log_term
        && backup.state_revision == Revision::new(source.state_revision)
        && backup.schema_version == source.schema_version
        && backup.source_byte_length == source.byte_length
        && backup.source_digest == source.digest
        && backup.manifest_digest == source.catalogue_digest()
        && backup.encrypted_byte_length == evidence.byte_length
        && backup.encrypted_digest == evidence.digest
        && backup.revision != Revision::ZERO
        && matches!(
            backup.state,
            MetadataBackupState::Recorded | MetadataBackupState::Verified
        )
    {
        Ok(backup)
    } else {
        Err(BackupPublicationError::Conflict)
    }
}

pub(super) fn validate_copy(
    copy: BackupCopyRecord,
    object: BackupObjectIdentity,
) -> Result<BackupCopyRecord, BackupPublicationError> {
    if copy.backup_id == object.backup_id
        && copy.destination_id == object.destination_id
        && copy.provider_generation == object.provider_generation
        && copy.byte_length == object.byte_length
        && copy.copy_digest == object.digest
        && copy.revision != Revision::ZERO
        && matches!(
            copy.state,
            BackupCopyState::Stored | BackupCopyState::Verified
        )
    {
        meshspan_contracts::BackupObjectReference::new(copy.object_reference.clone())?;
        Ok(copy)
    } else {
        Err(BackupPublicationError::Conflict)
    }
}

pub(super) fn command_context(
    step: PublicationStep,
    evidence: BackupFileEvidence,
    destination_id: BackupDestinationId,
    actor_principal_id: PrincipalId,
    now: UnixMicros,
) -> Result<CommandContext, BackupPublicationError> {
    Ok(CommandContext {
        operation_id: operation_id(step, evidence, destination_id, now)?,
        actor_principal_id,
        audit_event_id: audit_id(step, evidence, destination_id, now)?,
        occurred_at: now,
        expected_revision: None,
    })
}

pub(super) fn provider_context(
    step: PublicationStep,
    evidence: BackupFileEvidence,
    destination_id: BackupDestinationId,
    now: UnixMicros,
    deadline: UnixMicros,
    expected_revision: Revision,
) -> Result<RequestContext, BackupPublicationError> {
    Ok(RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: operation_id(step, evidence, destination_id, now)?,
        deadline,
        expected_revision: Some(expected_revision),
    })
}

pub(super) fn operation_id(
    step: PublicationStep,
    evidence: BackupFileEvidence,
    destination_id: BackupDestinationId,
    now: UnixMicros,
) -> Result<OperationId, BackupPublicationError> {
    OperationId::from_bytes(uuid_v8(derived_prefix(
        step,
        b"operation",
        evidence,
        destination_id,
        now,
    )))
    .map_err(Into::into)
}

fn audit_id(
    step: PublicationStep,
    evidence: BackupFileEvidence,
    destination_id: BackupDestinationId,
    now: UnixMicros,
) -> Result<AuditEventId, BackupPublicationError> {
    AuditEventId::from_bytes(uuid_v8(derived_prefix(
        step,
        b"audit",
        evidence,
        destination_id,
        now,
    )))
    .map_err(Into::into)
}

fn derived_prefix(
    step: PublicationStep,
    identity_kind: &[u8],
    evidence: BackupFileEvidence,
    destination_id: BackupDestinationId,
    now: UnixMicros,
) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(step.domain());
    digest.update(identity_kind);
    digest.update(evidence.source.backup_id.as_bytes());
    digest.update(destination_id.as_bytes());
    digest.update(now.get().to_be_bytes());
    let digest = digest.finalize();
    let mut prefix = [0; 16];
    prefix.copy_from_slice(&digest[..16]);
    prefix
}

pub(super) fn validate_receipt(
    receipt: CommandReceipt,
    context: CommandContext,
    command: &AuthoritativeCommand,
    entity_kind: EntityKind,
    entity_id: [u8; 16],
) -> Result<(), BackupPublicationError> {
    if receipt.operation_id == context.operation_id
        && receipt.request_digest == command.request_digest(context)
        && receipt.result_digest != [0; 32]
        && receipt.committed_revision != Revision::ZERO
        && receipt.entity.kind == entity_kind
        && receipt.entity.id == entity_id
    {
        Ok(())
    } else {
        Err(BackupPublicationError::InvalidReceipt)
    }
}
