// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::AuthoritativeCommand::RetireAbandonedBackupCopy as Retire;
use crate::{
    AbandonUnrecordedMetadataBackupRun, CommandReceipt, RepositoryError, RetireAbandonedBackupCopy,
};
use meshspan_contracts::{BackupObjectIdentity, BackupObjectReceipt, BackupObjectReference};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[path = "backup_intent_tests.rs"]
mod intent;

#[test]
fn orphan_retirement_requires_committed_abandonment_and_survives_reopen() -> TestResult {
    let (mut fixture, mut value, claim) = prepared()?;
    let object = value.receipt.object;
    // Both a still-live claim and an expired-but-not-abandoned claim are insufficient.
    for now in [90, 100] {
        assert!(matches!(
            commit(&mut fixture, &Retire(value.clone()), now),
            Err(RepositoryError::InvalidCommand)
        ));
        assert!(
            fixture
                .repository
                .abandoned_backup_retirement(object.backup_id, object.destination_id)?
                .is_none()
        );
    }
    abandon(&mut fixture, object.backup_id, claim)?;
    value.expected_run_revision = Revision::new(7);
    let command = AuthoritativeCommand::RetireAbandonedBackupCopy(value.clone());
    let ctx = context(140, fixture.administrator, 141, 101, 7)?;
    let receipt =
        fixture
            .repository
            .apply_committed(LogPosition { index: 8, term: 1 }, ctx, &command)?;
    assert_eq!(receipt.committed_revision, Revision::new(8));
    assert!(
        fixture
            .repository
            .metadata_backup(object.backup_id)?
            .is_none()
    );
    assert!(
        fixture
            .repository
            .backup_copy(object.backup_id, object.destination_id)?
            .is_none()
    );
    let retained = fixture
        .repository
        .abandoned_backup_retirement(object.backup_id, object.destination_id)?
        .ok_or("retirement missing")?;
    assert_eq!(retained.command, value);
    assert_eq!(retained.retirement_revision, Revision::new(8));
    assert_eq!(retained.retired_at, UnixMicros::new(101));
    assert_eq!(
        fixture
            .repository
            .pending_backup_reclamations(None, PageLimit::new(10)?)?
            .items
            .len(),
        1
    );
    let mut reopened = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &fixture.directory.path().join("backup-catalogue.sqlite3"),
        UnixMicros::new(102),
    )?);
    let replay = reopened.apply_committed(LogPosition { index: 9, term: 1 }, ctx, &command)?;
    assert_eq!(replay.committed_revision, receipt.committed_revision);
    assert_eq!(replay.request_digest, receipt.request_digest);
    assert_eq!(
        reopened.abandoned_backup_retirement(object.backup_id, object.destination_id)?,
        Some(retained)
    );
    Ok(())
}

#[test]
fn orphan_retirement_rejects_substitution_and_does_not_reissue_authority() -> TestResult {
    let (mut fixture, mut value, claim) = prepared()?;
    abandon(&mut fixture, value.receipt.object.backup_id, claim)?;
    value.expected_run_revision = Revision::new(7);
    let mut wrong_generation = value.clone();
    wrong_generation.receipt.object.provider_generation = 2;
    assert!(matches!(
        commit(&mut fixture, &Retire(wrong_generation), 101),
        Err(RepositoryError::StaleRevision)
    ));
    commit(&mut fixture, &Retire(value.clone()), 101)?;
    let stale = RetireAbandonedBackupCopy {
        expected_run_revision: Revision::new(6),
        ..value.clone()
    };
    assert!(matches!(
        commit(&mut fixture, &Retire(stale), 102),
        Err(RepositoryError::StaleRevision)
    ));
    for changed in [
        RetireAbandonedBackupCopy {
            receipt: BackupObjectReceipt {
                object: BackupObjectIdentity {
                    digest: [80; 32],
                    ..value.receipt.object
                },
                ..value.receipt.clone()
            },
            ..value.clone()
        },
        RetireAbandonedBackupCopy {
            receipt: BackupObjectReceipt {
                object_reference: BackupObjectReference::new("different-object".into())?,
                ..value.receipt.clone()
            },
            ..value.clone()
        },
    ] {
        assert!(matches!(
            commit(&mut fixture, &Retire(changed), 102),
            Err(RepositoryError::InvalidCommand)
        ));
    }
    commit(&mut fixture, &Retire(value.clone()), 103)?;
    let retained = fixture
        .repository
        .abandoned_backup_retirement(
            value.receipt.object.backup_id,
            value.receipt.object.destination_id,
        )?
        .ok_or("retirement")?;
    assert_eq!(retained.retirement_revision, Revision::new(8));
    assert_eq!(retained.retired_at, UnixMicros::new(101));
    Ok(())
}

#[test]
fn admitted_generation_is_never_an_orphan() -> TestResult {
    let (mut fixture, mut value, claim) = prepared()?;
    let object = value.receipt.object;
    record_and_verify_backup(
        &mut fixture,
        object.destination_id,
        object.backup_id,
        object.digest,
        claim,
    )?;
    value.expected_run_revision = fixture
        .repository
        .metadata_backup_run(object.backup_id)?
        .ok_or("run")?
        .revision;
    assert!(matches!(
        commit(&mut fixture, &Retire(value), 100),
        Err(RepositoryError::InvalidCommand)
    ));
    assert!(
        fixture
            .repository
            .abandoned_backup_retirement(object.backup_id, object.destination_id)?
            .is_none()
    );
    Ok(())
}

#[test]
fn orphan_cleanup_requires_exact_receipt_and_survives_reopen() -> TestResult {
    use crate::RecordBackupReclamation;
    use meshspan_contracts::BackupDeleteReceipt;

    let (mut fixture, mut value, claim) = prepared()?;
    abandon(&mut fixture, value.receipt.object.backup_id, claim)?;
    value.expected_run_revision = Revision::new(7);
    commit(&mut fixture, &Retire(value.clone()), 101)?;
    let receipt = BackupDeleteReceipt {
        operation_id: OperationId::from_bytes([190; 16])?,
        object: value.receipt.object,
        retirement_revision: Revision::new(8),
    };
    for changed in [
        BackupDeleteReceipt {
            retirement_revision: Revision::new(7),
            ..receipt
        },
        BackupDeleteReceipt {
            object: BackupObjectIdentity {
                provider_generation: 2,
                ..receipt.object
            },
            ..receipt
        },
        BackupDeleteReceipt {
            object: BackupObjectIdentity {
                byte_length: 101,
                ..receipt.object
            },
            ..receipt
        },
        BackupDeleteReceipt {
            object: BackupObjectIdentity {
                digest: [88; 32],
                ..receipt.object
            },
            ..receipt
        },
    ] {
        let command = AuthoritativeCommand::RecordBackupReclamation(RecordBackupReclamation {
            receipt: changed,
        });
        assert!(matches!(
            commit(&mut fixture, &command, 102),
            Err(RepositoryError::InvalidCommand)
        ));
        assert_eq!(fixture.repository.current_revision()?, Revision::new(8));
        assert_eq!(
            fixture
                .repository
                .pending_backup_reclamations(None, PageLimit::new(1)?)?
                .items
                .len(),
            1
        );
    }
    let command =
        AuthoritativeCommand::RecordBackupReclamation(RecordBackupReclamation { receipt });
    commit(&mut fixture, &command, 103)?;
    fixture.repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &fixture.directory.path().join("backup-catalogue.sqlite3"),
        UnixMicros::new(104),
    )?);
    assert!(
        fixture
            .repository
            .pending_backup_reclamations(None, PageLimit::new(1)?)?
            .items
            .is_empty()
    );
    commit(&mut fixture, &command, 104)?;
    let changed = AuthoritativeCommand::RecordBackupReclamation(RecordBackupReclamation {
        receipt: BackupDeleteReceipt {
            operation_id: OperationId::from_bytes([191; 16])?,
            ..receipt
        },
    });
    assert!(matches!(
        commit(&mut fixture, &changed, 105),
        Err(RepositoryError::InvalidCommand)
    ));
    assert!(
        fixture
            .repository
            .metadata_backup(receipt.object.backup_id)?
            .is_none()
    );
    assert!(
        fixture
            .repository
            .backup_copy(receipt.object.backup_id, receipt.object.destination_id)?
            .is_none()
    );
    Ok(())
}

fn prepared() -> TestResult<(Fixture, RetireAbandonedBackupCopy, MetadataBackupRunClaim)> {
    let mut fixture = fixture()?;
    let destination = BackupDestinationId::from_bytes([30; 16])?;
    let backup = BackupId::from_bytes([31; 16])?;
    configure_destination(&mut fixture, destination)?;
    let claim = queue_and_claim(&mut fixture, backup)?;
    let value = RetireAbandonedBackupCopy {
        expected_run_revision: Revision::new(6),
        receipt: BackupObjectReceipt {
            operation_id: OperationId::from_bytes([132; 16])?,
            object: BackupObjectIdentity {
                backup_id: backup,
                destination_id: destination,
                provider_generation: 1,
                byte_length: 100,
                digest: [35; 32],
            },
            object_reference: BackupObjectReference::new("provider-object".into())?,
        },
    };
    Ok((fixture, value, claim))
}

fn abandon(fixture: &mut Fixture, backup: BackupId, claim: MetadataBackupRunClaim) -> TestResult {
    commit(
        fixture,
        &AuthoritativeCommand::AbandonUnrecordedMetadataBackupRun(
            AbandonUnrecordedMetadataBackupRun {
                backup_id: backup,
                expected_claim: claim,
            },
        ),
        100,
    )?;
    Ok(())
}

fn commit(
    fixture: &mut Fixture,
    command: &AuthoritativeCommand,
    now: i64,
) -> Result<CommandReceipt, RepositoryError> {
    let revision = fixture.repository.current_revision()?.get();
    let identity = u8::try_from(revision + 150).map_err(|_| RepositoryError::CapacityExceeded)?;
    fixture.repository.apply_committed(
        LogPosition {
            index: revision + 1,
            term: 1,
        },
        CommandContext {
            operation_id: OperationId::from_bytes([identity; 16])
                .map_err(|_| RepositoryError::InvalidCommand)?,
            actor_principal_id: fixture.administrator,
            audit_event_id: AuditEventId::from_bytes([identity; 16])
                .map_err(|_| RepositoryError::InvalidCommand)?,
            occurred_at: UnixMicros::new(now),
            expected_revision: Some(Revision::new(revision)),
        },
        command,
    )
}
