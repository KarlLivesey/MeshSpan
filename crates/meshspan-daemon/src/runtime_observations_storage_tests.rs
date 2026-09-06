// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_contracts::RuntimeMetricSource;

#[test]
fn usage_totals_are_exact_and_partial_or_overflowed_passes_omit_byte_gauges()
-> Result<(), ContractError> {
    let observations = RuntimeObservations::default();
    let value = StorageUsageObservation {
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
