// SPDX-License-Identifier: GPL-2.0-only

//! Production dispatcher and real consensus abandon a lost, unadmitted occurrence.

use super::{RunningAuthority, SequentialRandom, command_context};
use crate::{
    ConsensusAuthenticationAuthority, MetadataBackupDispatchOutcome, MetadataBackupDispatcher,
    MetadataBackupPreparationService, PreparedMetadataBackup,
};
use meshspan_domain::{DurationMicros, PartitionId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, ConfigureMetadataBackupSchedule, LocalDatabase,
    MetadataBackupRun, MetadataBackupRunState, PartitionDatabase,
};

#[path = "backup_orphan_service_tests.rs"]
mod orphan;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_dispatcher_commits_abandonment_and_fresh_identity_through_consensus()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RunningAuthority::start().await?;
    super::backup_destination_service_tests::register_target(&fixture).await?;
    let partition_id = PartitionId::from_bytes([2; 16])?;
    let reader = AuthoritativeRepository::new(PartitionDatabase::open(
        &fixture.directory.path().join("partition.sqlite3"),
        partition_id,
        UnixMicros::new(100),
    )?);
    let authority = ConsensusAuthenticationAuthority::new(
        reader,
        fixture.handle.clone(),
        tokio::runtime::Handle::current(),
    );
    let outcome = tokio::task::block_in_place(|| -> Result<(), Box<dyn std::error::Error>> {
        authority.commit_authoritative(
            command_context(fixture.administrator_id, 80, 81, 100, None)?,
            &AuthoritativeCommand::ConfigureMetadataBackupSchedule(
                ConfigureMetadataBackupSchedule {
                    partition_id,
                    expected_schedule_sequence: 0,
                    interval: DurationMicros::new(86_400_000_000),
                    retained_generations: 3,
                    minimum_verified_copies: 1,
                    minimum_independent_copies: 0,
                    enabled: true,
                    next_due_at: UnixMicros::new(101),
                },
            ),
        )?;
        // Exercise high-bit entropy too: fences must fit the SQL integer domain.
        let mut random = SequentialRandom(128);
        let first = MetadataBackupDispatcher::new(
            &authority,
            &mut random,
            fixture.node_id,
            1,
            fixture.administrator_id,
        )
        .dispatch(UnixMicros::new(101), DurationMicros::new(100))
        .map_err(|error| format!("initial dispatch: {error:?}"))?;
        let MetadataBackupDispatchOutcome::Claimed {
            run: original,
            claim: original_claim,
        } = first
        else {
            return Err("initial claim".into());
        };
        let (mut local, prepared) = prepare_owned_staging(&fixture, &authority, original)?;
        let (provider, orphan_receipt) =
            orphan::store_before_admission(&fixture, &authority, &prepared)?;
        // A new dispatcher owns no old staging or in-memory cursor. Time is explicit,
        // so this exercises production lease decisions without a five-minute sleep.
        let abandoned = MetadataBackupDispatcher::new(
            &authority,
            &mut random,
            fixture.node_id,
            1,
            fixture.administrator_id,
        )
        .dispatch(UnixMicros::new(201), DurationMicros::new(100))
        .map_err(|error| format!("abandonment dispatch: {error:?}"))?;
        assert_eq!(abandoned, MetadataBackupDispatchOutcome::Idle);
        assert_unadmitted_abandonment(&authority, original.backup_id)?;
        orphan::retire_and_remove(&fixture, &authority, provider, &orphan_receipt)?;
        assert_abandoned_staging_reclaimed(&fixture, &authority, &mut local, &prepared)?;
        let fresh = MetadataBackupDispatcher::new(
            &authority,
            &mut random,
            fixture.node_id,
            1,
            fixture.administrator_id,
        )
        .dispatch(UnixMicros::new(201), DurationMicros::new(100))
        .map_err(|error| format!("replacement dispatch: {error:?}"))?;
        let MetadataBackupDispatchOutcome::Claimed { run, claim } = fresh else {
            return Err("fresh claim".into());
        };
        assert_ne!(run.backup_id, original.backup_id);
        assert_eq!(run.run_sequence, original.run_sequence + 1);
        assert_eq!(claim.claim.claim_generation, 1);
        assert_ne!(claim.claim.fence, original_claim.claim.fence);
        Ok(())
    });
    fixture.shutdown().await?;
    outcome
}

fn assert_unadmitted_abandonment(
    authority: &ConsensusAuthenticationAuthority,
    backup: meshspan_domain::BackupId,
) -> Result<(), Box<dyn std::error::Error>> {
    let reader = authority.reader();
    let run = reader.metadata_backup_run(backup)?.ok_or("abandoned run")?;
    assert_eq!(run.state, MetadataBackupRunState::Incomplete);
    assert!(run.completed_at.is_some());
    assert!(run.result_digest.is_some());
    assert!(reader.metadata_backup(backup)?.is_none());
    assert!(reader.metadata_backup_run_claim(backup)?.is_none());
    Ok(())
}

fn prepare_owned_staging(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    run: MetadataBackupRun,
) -> Result<(LocalDatabase, PreparedMetadataBackup), Box<dyn std::error::Error>> {
    let mut local = LocalDatabase::open(
        &fixture.directory.path().join("local.sqlite3"),
        fixture.node_id,
        UnixMicros::new(101),
    )?;
    let mut random = SequentialRandom(12);
    let prepared = MetadataBackupPreparationService::open(
        authority,
        &mut local,
        &mut random,
        fixture.directory.path(),
    )?
    .prepare(run, UnixMicros::new(101))?;
    let mut retention = crate::metadata_backup_retention::MetadataBackupRetentionWorker::default();
    assert_eq!(
        retention.reclaim_abandoned_staging(authority, &mut local, fixture.directory.path())?,
        0
    );
    assert!(prepared.encrypted_path.is_file());
    assert_eq!(
        local.metadata_backup_staging(run.backup_id)?,
        Some(prepared.staging.clone())
    );
    Ok((local, prepared))
}

fn assert_abandoned_staging_reclaimed(
    fixture: &RunningAuthority,
    authority: &ConsensusAuthenticationAuthority,
    local: &mut LocalDatabase,
    prepared: &PreparedMetadataBackup,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = authority.reader().current_revision()?;
    let mut retention = crate::metadata_backup_retention::MetadataBackupRetentionWorker::default();
    assert_eq!(
        retention.reclaim_abandoned_staging(authority, local, fixture.directory.path())?,
        1
    );
    assert!(!prepared.encrypted_path.exists());
    assert_eq!(
        local.metadata_backup_staging(prepared.staging.evidence.source.backup_id)?,
        None
    );
    let mut reopened = LocalDatabase::open_existing(
        &fixture.directory.path().join("local.sqlite3"),
        UnixMicros::new(202),
    )?;
    assert_eq!(
        retention.reclaim_abandoned_staging(authority, &mut reopened, fixture.directory.path())?,
        0
    );
    assert_eq!(authority.reader().current_revision()?, before);
    Ok(())
}
