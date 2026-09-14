// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_contracts::RuntimeMetricSource;

#[test]
fn retained_job_measurements_are_separate_from_local_attempts() -> Result<(), ContractError> {
    let observations = RuntimeObservations::default();
    observations.record_maintenance_jobs(
        Instant::now(),
        [MaintenanceJobCounts {
            queued: 2,
            claimed: 3,
            completed: 5,
            protection_debt: 1,
            locality_debt: 4,
            pending_demand_bytes: 4_096,
        }; 5],
        MaintenanceProgressCounts::default(),
    );
    let snapshot = observations.collect_metrics()?;
    for kind in MaintenanceMetricKind::ALL {
        for expected in [
            MaintenanceMetric::QueuedJobs(2),
            MaintenanceMetric::ClaimedJobs(3),
            MaintenanceMetric::CompletedJobs(5),
            MaintenanceMetric::ProtectionDebtJobs(1),
            MaintenanceMetric::LocalityDebtJobs(4),
            MaintenanceMetric::PendingDemandBytes(4_096),
            MaintenanceMetric::Attempts(0),
        ] {
            assert!(
                snapshot
                    .samples()
                    .contains(&RuntimeMetric::Maintenance(kind, expected))
            );
        }
    }
    observations.record_maintenance_observation_failure();
    let after_failure = observations.collect_metrics()?;
    assert!(
        after_failure
            .samples()
            .contains(&RuntimeMetric::DroppedObservations(1))
    );
    assert!(
        after_failure
            .samples()
            .contains(&RuntimeMetric::Maintenance(
                MaintenanceMetricKind::Repair,
                MaintenanceMetric::CompletedJobs(5)
            ))
    );
    Ok(())
}

#[test]
fn filesystem_space_is_counted_once_and_missing_evidence_is_not_zero() -> Result<(), ContractError>
{
    use meshspan_contracts::FilesystemSpaceObservation;
    let observations = RuntimeObservations::default();
    let value = |identity, total_bytes, available_bytes| StorageUsageObservation {
        filesystem: Some(FilesystemSpaceObservation {
            identity,
            total_bytes,
            available_bytes,
        }),
        ..StorageUsageObservation::default()
    };
    let mut pass = StorageUsagePass::default();
    pass.observe(Ok(value(1, 1_000, 600)));
    pass.observe(Ok(value(1, 1_000, 500)));
    pass.observe(Ok(value(2, 2_000, 900)));
    observations.record_storage_usage(pass.clone());
    let snapshot = observations.collect_metrics()?;
    for expected in [
        StorageUsageMetric::SampledTargets(3),
        StorageUsageMetric::SampledFilesystems(2),
        StorageUsageMetric::UnavailableFilesystemTargets(0),
        StorageUsageMetric::FilesystemTotalBytes(3_000),
        StorageUsageMetric::FilesystemAvailableBytes(1_400),
    ] {
        assert!(
            snapshot
                .samples()
                .contains(&RuntimeMetric::StorageUsage(expected))
        );
    }
    for failure in [
        StorageUsageObservation::default(),
        value(3, 1, 2),
        value(3, u64::MAX, 0),
    ] {
        let mut partial = pass.clone();
        partial.observe(Ok(failure));
        observations.record_storage_usage(partial);
        let snapshot = observations.collect_metrics()?;
        assert!(snapshot.samples().contains(&RuntimeMetric::StorageUsage(
            StorageUsageMetric::UnavailableFilesystemTargets(1)
        )));
        assert!(!snapshot.samples().iter().any(|sample| matches!(
            sample,
            RuntimeMetric::StorageUsage(
                StorageUsageMetric::FilesystemTotalBytes(_)
                    | StorageUsageMetric::FilesystemAvailableBytes(_)
            )
        )));
    }
    Ok(())
}

#[test]
fn pack_extent_is_separate_from_quota_and_omitted_when_incomplete() -> Result<(), ContractError> {
    use meshspan_contracts::PackSpaceObservation;
    let store = RuntimeObservations::default();
    let value = StorageUsageObservation {
        pack: Some(PackSpaceObservation {
            database_bytes: 40_960,
            reusable_bytes: 8_192,
        }),
        committed_bytes: 17,
        ..StorageUsageObservation::default()
    };
    let mut pass = StorageUsagePass::default();
    pass.observe(Ok(value));
    pass.observe(Ok(value));
    store.record_storage_usage(pass.clone());
    let samples = store.collect_metrics()?;
    for value in [
        StorageUsageMetric::SampledPackTargets(2),
        StorageUsageMetric::UnavailablePackTargets(0),
        StorageUsageMetric::PackDatabaseBytes(81_920),
        StorageUsageMetric::PackReusableBytes(16_384),
        StorageUsageMetric::CommittedBytes(34),
    ] {
        assert!(
            samples
                .samples()
                .contains(&RuntimeMetric::StorageUsage(value))
        );
    }
    for pack in [
        None,
        Some(PackSpaceObservation {
            database_bytes: 10,
            reusable_bytes: 11,
        }),
        Some(PackSpaceObservation {
            database_bytes: u64::MAX,
            reusable_bytes: 0,
        }),
    ] {
        let mut partial = pass.clone();
        partial.observe(Ok(StorageUsageObservation { pack, ..value }));
        store.record_storage_usage(partial);
        let samples = store.collect_metrics()?;
        assert!(samples.samples().contains(&RuntimeMetric::StorageUsage(
            StorageUsageMetric::UnavailablePackTargets(1)
        )));
        assert!(samples.samples().contains(&RuntimeMetric::StorageUsage(
            StorageUsageMetric::CommittedBytes(51)
        )));
        assert!(!samples.samples().iter().any(|value| matches!(
            value,
            RuntimeMetric::StorageUsage(
                StorageUsageMetric::PackDatabaseBytes(_) | StorageUsageMetric::PackReusableBytes(_)
            )
        )));
    }
    Ok(())
}

#[test]
fn usage_totals_are_exact_and_partial_or_overflowed_passes_omit_byte_gauges()
-> Result<(), ContractError> {
    let observations = RuntimeObservations::default();
    let value = StorageUsageObservation {
        filesystem: None,
        pack: None,
        committed_bytes: 17,
        reserved_bytes: 3,
        configured_limit_bytes: 100,
        repair_reserve_bytes: 10,
    };
    let mut pass = StorageUsagePass::default();
    pass.observe(Ok(value));
    pass.observe(Ok(value));
    observations.record_storage_usage(pass.clone());
    let complete = observations.collect_metrics()?;
    for sample in [
        StorageUsageMetric::SampledTargets(2),
        StorageUsageMetric::UnavailableTargets(0),
        StorageUsageMetric::CommittedBytes(34),
        StorageUsageMetric::ReservedBytes(6),
        StorageUsageMetric::ConfiguredLimitBytes(200),
        StorageUsageMetric::RepairReserveBytes(20),
    ] {
        assert!(
            complete
                .samples()
                .contains(&RuntimeMetric::StorageUsage(sample))
        );
    }
    for failure in [
        Err(ContractError::Unavailable),
        Ok(StorageUsageObservation {
            committed_bytes: u64::MAX,
            ..value
        }),
    ] {
        let mut partial = pass.clone();
        partial.observe(failure);
        observations.record_storage_usage(partial);
        let partial = observations.collect_metrics()?;
        assert!(partial.samples().contains(&RuntimeMetric::StorageUsage(
            StorageUsageMetric::UnavailableTargets(1)
        )));
        assert!(!partial.samples().iter().any(|sample| matches!(
            sample,
            RuntimeMetric::StorageUsage(
                StorageUsageMetric::CommittedBytes(_)
                    | StorageUsageMetric::ReservedBytes(_)
                    | StorageUsageMetric::ConfiguredLimitBytes(_)
                    | StorageUsageMetric::RepairReserveBytes(_)
            )
        )));
    }
    observations.record_storage_usage(pass);
    assert!(
        observations
            .collect_metrics()?
            .samples()
            .contains(&RuntimeMetric::StorageUsage(
                StorageUsageMetric::CommittedBytes(34)
            ))
    );
    Ok(())
}

#[test]
fn selected_work_records_normal_failure_and_early_return_once_per_kind() -> Result<(), ContractError>
{
    let observations = RuntimeObservations::default();
    for (index, kind) in MaintenanceMetricKind::ALL.into_iter().enumerate() {
        for _ in 0..=index {
            assert_eq!(observations.begin_maintenance(kind).finish(Ok(())), Ok(()));
        }
        assert_eq!(
            observations.begin_maintenance(kind).finish(Err(())),
            Err(())
        );
        drop(observations.begin_maintenance(kind));
    }
    let snapshot = observations.collect_metrics()?;
    for (index, kind) in MaintenanceMetricKind::ALL.into_iter().enumerate() {
        let attempts = u64::try_from(index).map_err(|_| ContractError::InternalContract)? + 3;
        assert!(snapshot.samples().contains(&RuntimeMetric::Maintenance(
            kind,
            MaintenanceMetric::Attempts(attempts)
        )));
        assert!(snapshot.samples().contains(&RuntimeMetric::Maintenance(
            kind,
            MaintenanceMetric::Failures(2)
        )));
        assert!(snapshot.samples().iter().any(|value| matches!(value,
            RuntimeMetric::Maintenance(actual, MaintenanceMetric::Duration(histogram))
            if *actual == kind && histogram.count == attempts)));
    }
    let encoded = String::from_utf8(crate::encode_openmetrics(&snapshot)?)
        .map_err(|_| ContractError::InternalContract)?;
    for (index, kind) in ["repair", "drain", "rebalance", "reconcile", "scrub"]
        .into_iter()
        .enumerate()
    {
        let attempts = index + 3;
        assert!(encoded.contains(&format!(
            "meshspan_v1_maintenance_{kind}_attempts_total {attempts}\n"
        )));
        assert!(encoded.contains(&format!(
            "meshspan_v1_maintenance_{kind}_failures_total 2\n"
        )));
        assert!(encoded.contains(&format!(
            "meshspan_v1_maintenance_{kind}_duration_seconds_count {attempts}\n"
        )));
    }
    Ok(())
}

#[test]
fn maintenance_overflow_is_atomic() -> Result<(), ContractError> {
    let mut counters = MaintenanceCounters::default();
    counters.record(true, Duration::from_millis(1))?;
    counters.failures = u64::MAX;
    let before = counters.duration.clone();
    assert_eq!(
        counters.record(true, Duration::from_millis(6)),
        Err(ContractError::ResourceExhausted)
    );
    assert_eq!(counters.duration, before);
    assert_eq!(counters.failures, u64::MAX);
    Ok(())
}

#[test]
fn storage_measurements_do_not_wait_for_a_busy_observation_store()
-> Result<(), Box<dyn std::error::Error>> {
    let observations = RuntimeObservations::default();
    let work = observations.begin_maintenance(MaintenanceMetricKind::Scrub);
    let state = observations
        .0
        .state
        .lock()
        .map_err(|_| "poisoned observation store")?;
    observations.record_storage_usage(StorageUsagePass::default());
    assert_eq!(work.finish(Ok(())), Ok(()));
    assert!(state.storage.usage.is_none());
    assert_eq!(
        observations
            .0
            .dropped
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    Ok(())
}
