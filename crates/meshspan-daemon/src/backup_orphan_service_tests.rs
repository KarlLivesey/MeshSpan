// SPDX-License-Identifier: GPL-2.0-only

//! Real consensus retirement authority composed with an exact encrypted-folder object.

use super::{
    ConsensusAuthenticationAuthority, PreparedMetadataBackup, RunningAuthority, command_context,
};
use crate::metadata_backup_retention::{
    BackupRetentionAuthority, BackupRetentionInput, MetadataBackupRetentionWorker,
};
use crate::{
    MetadataBackupWorkerLimits, RegisteredBackupTarget, RegisteredTargetBackupProviderResolver,
};
use meshspan_backup::{DirectoryBackupProvider, SharedBackupProvider};
use meshspan_contracts::{
    BackupObjectIdentity, BackupObjectReceipt, BackupProvider, BackupStoreRequest,
    BackupVerifyRequest, ContractError, ContractVersion, RequestContext,
};
use meshspan_domain::{
    BackupDestinationId, DurationMicros, OperationId, Revision, TargetId, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, BackupDestinationBinding, BackupFailureRelationship,
    ConfigureBackupDestination, RecordName,
};

#[path = "backup_orphan_completion_tests.rs"]
mod completion;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn store_before_admission(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    prepared: &PreparedMetadataBackup,
) -> TestResult<(DirectoryBackupProvider, BackupObjectReceipt)> {
    let destination_id = BackupDestinationId::from_bytes([170; 16])?;
    let committed = authority.commit_authoritative(
        command_context(fixture.administrator_id, 171, 172, 101, None)?,
        &AuthoritativeCommand::ConfigureBackupDestination(ConfigureBackupDestination {
            destination_id,
            expected_destination_revision: Revision::ZERO,
            name: RecordName::new("Interrupted provider")?,
            binding: BackupDestinationBinding::RegisteredTarget {
                target_id: TargetId::from_bytes(uuid_v8([32; 16]))?,
                target_generation: 1,
            },
            failure_relationship: BackupFailureRelationship::Unknown,
            failure_evidence_digest: [173; 32],
            enabled: true,
        }),
    )?;
    let directory = fixture.directory.path().join("unadmitted-provider");
    std::fs::create_dir(&directory)?;
    let mut provider = DirectoryBackupProvider::open(
        &directory,
        destination_id,
        1,
        16 * 1024 * 1024,
        UnixMicros::new(101),
    )?;
    let evidence = prepared.staging.evidence;
    let object = BackupObjectIdentity {
        backup_id: evidence.source.backup_id,
        destination_id,
        provider_generation: 1,
        byte_length: evidence.byte_length,
        digest: evidence.digest,
    };
    let claim = authority
        .reader()
        .metadata_backup_run_claim(object.backup_id)?
        .ok_or("live upload claim missing")?
        .claim;
    authority.commit_authoritative(
        command_context(fixture.administrator_id, 178, 179, 101, None)?,
        &AuthoritativeCommand::BindBackupPublicationIntent(
            meshspan_metadata::BindBackupPublicationIntent {
                object,
                store_operation_id: OperationId::from_bytes([174; 16])?,
                claim,
                expected_destination_revision: committed.committed_revision,
            },
        ),
    )?;
    let receipt = provider.store_exact(
        BackupStoreRequest {
            context: RequestContext {
                contract_version: ContractVersion::V1_0,
                operation_id: OperationId::from_bytes([174; 16])?,
                deadline: UnixMicros::new(200),
                expected_revision: Some(committed.committed_revision),
            },
            object: BackupObjectIdentity {
                backup_id: evidence.source.backup_id,
                destination_id,
                provider_generation: 1,
                byte_length: evidence.byte_length,
                digest: evidence.digest,
            },
        },
        &mut std::fs::File::open(&prepared.encrypted_path)?,
        UnixMicros::new(101),
    )?;
    assert!(
        authority
            .reader()
            .metadata_backup(receipt.object.backup_id)?
            .is_none()
    );
    Ok((provider, receipt))
}

pub(super) fn retire_and_remove(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    provider: DirectoryBackupProvider,
    receipt: &BackupObjectReceipt,
) -> TestResult {
    assert!(
        authority
            .reader()
            .abandoned_backup_retirement(receipt.object.backup_id, receipt.object.destination_id)?
            .is_none()
    );
    completion::recover_lost_completion(fixture, authority, provider, receipt)?;
    assert!(
        authority
            .reader()
            .metadata_backup(receipt.object.backup_id)?
            .is_none()
    );
    Ok(())
}
