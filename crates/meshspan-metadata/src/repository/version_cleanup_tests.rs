// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{ContentManifestId, FileVersionId, OperationId, Revision, UnixMicros};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::reachability::retained_root_summary;
use super::volume_head_tests::{context, fixture, open_and_prepare, publication_command};
use super::{ApplyDisposition, EntityKind, LogPosition, RepositoryError};
use crate::{AuthoritativeCommand, PartitionDatabase, ProposeVersionCleanup};

#[test]
fn exact_unreachable_proof_creates_one_replayable_cleanup_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("cleanup.sqlite3");
    let fixture = fixture()?;
    let mut repository = open_and_prepare(&file_path, &fixture)?;
    repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(30, fixture.administrator, 31, 102, Some(2))?,
        &publication_command(&fixture, None, 32, 33, 34, 35, 36)?,
    )?;
    let root_summary = retained_root_summary(
        repository.database.connection(),
        fixture.volume,
        Revision::new(3),
    )?;
    let command = cleanup_command(fixture.volume, root_summary, 40)?;
    let command_context = context(41, fixture.administrator, 42, 103, Some(3))?;
    let receipt =
        repository.apply_committed(LogPosition { index: 4, term: 1 }, command_context, &command)?;
    assert_eq!(receipt.entity.kind, EntityKind::VersionCleanup);
    let after_proposal = retained_root_summary(
        repository.database.connection(),
        fixture.volume,
        Revision::new(4),
    )?;
    assert_eq!(after_proposal.count, root_summary.count);
    assert_eq!(after_proposal.set_digest, root_summary.set_digest);
    assert_ne!(after_proposal.revision_digest, root_summary.revision_digest);
    let intent = repository
        .version_cleanup_intent(command_context.operation_id)?
        .ok_or("missing cleanup intent")?;
    assert_eq!(intent.cleanup_operation_id, command_context.operation_id);
    assert_eq!(intent.volume_id, fixture.volume);
    assert_eq!(intent.version_id.as_bytes(), [40; 16]);
    assert_eq!(intent.manifest_id.as_bytes(), [41; 16]);
    assert_ne!(intent.reachability_subject_digest, [0; 32]);
    assert_eq!(intent.reachability_revision, Revision::new(3));
    assert_eq!(intent.required_attestation_count, 1);
    assert_eq!(intent.revision, Revision::new(4));
    assert_eq!(
        repository
            .version_cleanup_attestation_progress(command_context.operation_id)?
            .ok_or("missing cleanup participants")?,
        super::VersionCleanupAttestationProgress {
            cleanup_operation_id: command_context.operation_id,
            required: 1,
            attested: 0,
        }
    );

    let replay =
        repository.apply_committed(LogPosition { index: 5, term: 1 }, command_context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    drop(repository);

    let database = PartitionDatabase::open(&file_path, fixture.partition, UnixMicros::new(500))?;
    let reopened = super::AuthoritativeRepository::new(database);
    assert_eq!(
        reopened
            .version_cleanup_intent(command_context.operation_id)?
            .ok_or("cleanup intent did not survive restart")?,
        intent
    );
    Ok(())
}

#[test]
fn stale_roots_policy_and_forged_terminal_proofs_change_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fixture = fixture()?;
    let mut repository = open_and_prepare(&directory.path().join("reject.sqlite3"), &fixture)?;
    repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(50, fixture.administrator, 51, 102, Some(2))?,
        &publication_command(&fixture, None, 52, 53, 54, 55, 56)?,
    )?;
    let root_summary = retained_root_summary(
        repository.database.connection(),
        fixture.volume,
        Revision::new(3),
    )?;
    let valid = cleanup_command(fixture.volume, root_summary, 60)?;
    let AuthoritativeCommand::ProposeVersionCleanup(valid_value) = valid else {
        return Err("wrong command fixture".into());
    };
    let command_context = context(61, fixture.administrator, 62, 103, Some(3))?;

    let mut forged = valid_value;
    forged.proof_result_digest[0] ^= 1;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 4, term: 1 },
            command_context,
            &AuthoritativeCommand::ProposeVersionCleanup(forged),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    let mut substituted = valid_value;
    substituted.retained_root_digest[0] ^= 1;
    substituted.proof_result_digest = terminal_digest(&substituted);
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 4, term: 1 },
            command_context,
            &AuthoritativeCommand::ProposeVersionCleanup(substituted),
        ),
        Err(RepositoryError::StaleRevision)
    ));
    let mut substituted_set = valid_value;
    substituted_set.retained_root_set_digest[0] ^= 1;
    substituted_set.proof_result_digest = terminal_digest(&substituted_set);
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 4, term: 1 },
            command_context,
            &AuthoritativeCommand::ProposeVersionCleanup(substituted_set),
        ),
        Err(RepositoryError::StaleRevision)
    ));
    let mut wrong_policy = valid_value;
    wrong_policy.retention_policy_sequence = 2;
    wrong_policy.proof_result_digest = terminal_digest(&wrong_policy);
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 4, term: 1 },
            command_context,
            &AuthoritativeCommand::ProposeVersionCleanup(wrong_policy),
        ),
        Err(RepositoryError::StaleRetentionPolicy)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(3));
    assert!(
        repository
            .version_cleanup_intent(command_context.operation_id)?
            .is_none()
    );
    Ok(())
}

#[test]
fn every_apply_fault_rolls_back_the_complete_cleanup_proposal()
-> Result<(), Box<dyn std::error::Error>> {
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        let directory = tempdir()?;
        let fixture = fixture()?;
        let mut repository = open_and_prepare(&directory.path().join("fault.sqlite3"), &fixture)?;
        repository.apply_committed(
            LogPosition { index: 3, term: 1 },
            context(70, fixture.administrator, 71, 102, Some(2))?,
            &publication_command(&fixture, None, 72, 73, 74, 75, 76)?,
        )?;
        let root_summary = retained_root_summary(
            repository.database.connection(),
            fixture.volume,
            Revision::new(3),
        )?;
        let command = cleanup_command(fixture.volume, root_summary, 80)?;
        let command_context = context(81, fixture.administrator, 82, 103, Some(3))?;
        assert!(matches!(
            apply_committed_with_fault(
                &mut repository.database,
                LogPosition { index: 4, term: 1 },
                command_context,
                &command,
                fault,
            ),
            Err(RepositoryError::InjectedFault)
        ));
        assert_eq!(repository.current_revision()?, Revision::new(3));
        assert!(
            repository
                .version_cleanup_intent(command_context.operation_id)?
                .is_none()
        );
        repository.apply_committed(LogPosition { index: 4, term: 1 }, command_context, &command)?;
        assert!(
            repository
                .version_cleanup_intent(command_context.operation_id)?
                .is_some()
        );
    }
    Ok(())
}

pub(super) fn cleanup_command(
    volume_id: meshspan_domain::VolumeId,
    root_summary: super::reachability::RetainedRootSummary,
    identity: u8,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    let mut value = ProposeVersionCleanup {
        volume_id,
        version_id: FileVersionId::from_bytes([identity; 16])?,
        manifest_id: ContentManifestId::from_bytes([identity.saturating_add(1); 16])?,
        manifest_root_digest: [identity.saturating_add(6); 32],
        source_scan_operation_id: OperationId::from_bytes([identity.saturating_add(2); 16])?,
        scan_request_digest: [identity.saturating_add(3); 32],
        reachability_subject_digest: [identity.saturating_add(5); 32],
        retention_policy_sequence: 1,
        reachability_revision: Revision::new(3),
        retained_root_count: root_summary.count,
        retained_root_digest: root_summary.revision_digest,
        retained_root_set_digest: root_summary.set_digest,
        local_roots_digest: [identity.saturating_add(4); 32],
        proof_result_digest: [0; 32],
    };
    value.proof_result_digest = terminal_digest(&value);
    Ok(AuthoritativeCommand::ProposeVersionCleanup(value))
}

pub(super) fn terminal_digest(command: &ProposeVersionCleanup) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.version-reachability-result.v1\0");
    digest.update(&command.source_scan_operation_id.as_bytes());
    digest.update(&command.scan_request_digest);
    digest.update(&command.local_roots_digest);
    digest.update(&[4]);
    digest.finalize().into()
}
