// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{DurationMicros, UnixMicros};
use tempfile::tempdir;

use super::volume_head_tests::{context, fixture, open_and_prepare};
use super::{ApplyDisposition, LogPosition, RepositoryError};
use crate::{AuthoritativeCommand, ConfigureVersionRetention, RetentionReclaimMode};

const THIRTY_DAYS_MICROS: u64 = 2_592_000_000_000;

#[test]
fn default_retention_is_safe_and_immutable_replacement_replays_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("retention.sqlite3");
    let fixture = fixture()?;
    let mut repository = open_and_prepare(&file_path, &fixture)?;
    let default = repository
        .version_retention_policy(fixture.volume)?
        .ok_or("missing default retention policy")?;
    assert!(default.history_enabled);
    assert_eq!(default.sequence, 1);
    assert_eq!(default.minimum_age.get(), THIRTY_DAYS_MICROS);
    assert_eq!(default.reclaim_mode, RetentionReclaimMode::UnderPressure);
    assert!(default.soft_minimum_breakable);

    let command = policy_command(fixture.volume, 1);
    let command_context = context(30, fixture.administrator, 31, 102, Some(2))?;
    let applied =
        repository.apply_committed(LogPosition { index: 3, term: 1 }, command_context, &command)?;
    assert_eq!(applied.disposition, ApplyDisposition::Applied);
    let replay =
        repository.apply_committed(LogPosition { index: 4, term: 1 }, command_context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    drop(repository);

    let database =
        crate::PartitionDatabase::open(&file_path, fixture.partition, UnixMicros::new(500))?;
    let reopened = super::AuthoritativeRepository::new(database);
    let policy = reopened
        .version_retention_policy(fixture.volume)?
        .ok_or("missing configured retention policy")?;
    assert_eq!(policy.sequence, 2);
    assert!(!policy.history_enabled);
    assert_eq!(policy.minimum_versions, Some(3));
    assert_eq!(policy.maximum_age, Some(DurationMicros::new(20_000)));
    assert_eq!(policy.conflict_minimum_age, DurationMicros::new(30_000));
    Ok(())
}

#[test]
fn stale_and_structurally_invalid_retention_changes_do_not_advance()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fixture = fixture()?;
    let mut repository = open_and_prepare(&directory.path().join("reject.sqlite3"), &fixture)?;
    repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(40, fixture.administrator, 41, 102, Some(2))?,
        &policy_command(fixture.volume, 1),
    )?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 4, term: 1 },
            context(42, fixture.administrator, 43, 103, Some(3))?,
            &policy_command(fixture.volume, 1),
        ),
        Err(RepositoryError::StaleRetentionPolicy)
    ));
    let invalid = AuthoritativeCommand::ConfigureVersionRetention(ConfigureVersionRetention {
        volume_id: fixture.volume,
        expected_policy_sequence: 2,
        history_enabled: true,
        minimum_age: DurationMicros::new(20_000),
        maximum_age: Some(DurationMicros::new(10_000)),
        minimum_versions: Some(0),
        reclaim_mode: RetentionReclaimMode::AfterMaximumAge,
        soft_minimum_breakable: false,
        conflict_minimum_age: DurationMicros::new(5_000),
    });
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 4, term: 1 },
            context(44, fixture.administrator, 45, 103, Some(3))?,
            &invalid,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(
        repository
            .version_retention_policy(fixture.volume)?
            .ok_or("missing unchanged policy")?
            .sequence,
        2
    );
    Ok(())
}

fn policy_command(
    volume_id: meshspan_domain::VolumeId,
    expected_policy_sequence: u64,
) -> AuthoritativeCommand {
    AuthoritativeCommand::ConfigureVersionRetention(ConfigureVersionRetention {
        volume_id,
        expected_policy_sequence,
        history_enabled: false,
        minimum_age: DurationMicros::new(10_000),
        maximum_age: Some(DurationMicros::new(20_000)),
        minimum_versions: Some(3),
        reclaim_mode: RetentionReclaimMode::AfterMaximumAge,
        soft_minimum_breakable: false,
        conflict_minimum_age: DurationMicros::new(30_000),
    })
}
