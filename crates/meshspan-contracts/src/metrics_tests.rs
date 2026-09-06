// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn histogram_preserves_exact_inclusive_boundaries_and_nanosecond_sums() -> Result<(), ContractError>
{
    let mut histogram = LatencyHistogram::default();
    for duration in [
        Duration::ZERO,
        Duration::from_millis(1),
        Duration::from_nanos(1_000_001),
        Duration::from_secs(31),
    ] {
        histogram.observe(duration)?;
    }
    assert_eq!(histogram.buckets, [2, 3, 3, 3, 3, 3, 3, 3]);
    assert_eq!(histogram.count, 4);
    assert_eq!(histogram.sum, Duration::from_nanos(31_002_000_001));
    Ok(())
}

#[test]
fn histogram_rejects_invalid_input_and_overflow_without_partial_update() {
    for mut histogram in [
        LatencyHistogram {
            buckets: [1, 0, 0, 0, 0, 0, 0, 0],
            count: 1,
            sum: Duration::ZERO,
        },
        LatencyHistogram {
            buckets: [1; 8],
            count: 0,
            sum: Duration::ZERO,
        },
        LatencyHistogram {
            sum: Duration::from_nanos(1),
            ..LatencyHistogram::default()
        },
        LatencyHistogram {
            buckets: [u64::MAX; 8],
            count: u64::MAX,
            sum: Duration::ZERO,
        },
        LatencyHistogram {
            buckets: [0; 8],
            count: 1,
            sum: Duration::MAX,
        },
    ] {
        let before = histogram.clone();
        assert_eq!(
            histogram.observe(Duration::from_millis(1)),
            Err(ContractError::InvalidInput)
        );
        assert_eq!(histogram, before);
    }
}

#[test]
fn snapshots_reject_duplicates_and_do_not_fill_absent_measurements() -> Result<(), ContractError> {
    let snapshot = RuntimeMetricSnapshot::new(vec![RuntimeMetric::Uptime(Duration::from_secs(2))])?;
    assert_eq!(
        snapshot.samples(),
        &[RuntimeMetric::Uptime(Duration::from_secs(2))]
    );
    assert_eq!(
        RuntimeMetricSnapshot::new(vec![
            RuntimeMetric::OpenTargets(1),
            RuntimeMetric::OpenTargets(2)
        ]),
        Err(ContractError::InvalidInput)
    );
    assert_eq!(
        RuntimeMetricSnapshot::new(vec![
            RuntimeMetric::OpenTargets(1);
            MAX_RUNTIME_METRIC_FAMILIES + 1
        ]),
        Err(ContractError::InvalidInput)
    );
    assert!(RuntimeMetricSnapshot::new(vec![])?.samples().is_empty());
    Ok(())
}

#[test]
fn gateway_histograms_are_revalidated_at_the_snapshot_boundary() {
    let invalid = LatencyHistogram {
        buckets: [1; 8],
        ..LatencyHistogram::default()
    };
    for metric in [
        RuntimeMetric::HttpsDispatchDuration(invalid.clone()),
        RuntimeMetric::SmbDispatchDuration(invalid),
    ] {
        assert_eq!(
            RuntimeMetricSnapshot::new(vec![metric]),
            Err(ContractError::InvalidInput)
        );
    }
}

#[test]
fn operational_families_keep_kind_and_measurement_identity() -> Result<(), ContractError> {
    let repair = RuntimeMetric::Maintenance(
        MaintenanceMetricKind::Repair,
        MaintenanceMetric::Attempts(1),
    );
    let scrub =
        RuntimeMetric::Maintenance(MaintenanceMetricKind::Scrub, MaintenanceMetric::Attempts(2));
    let failures = RuntimeMetric::Maintenance(
        MaintenanceMetricKind::Repair,
        MaintenanceMetric::Failures(0),
    );
    let bytes = RuntimeMetric::StorageUsage(StorageUsageMetric::CommittedBytes(3));
    let reserved = RuntimeMetric::StorageUsage(StorageUsageMetric::ReservedBytes(4));
    let samples = vec![repair.clone(), scrub, failures, bytes.clone(), reserved];
    assert_eq!(
        RuntimeMetricSnapshot::new(samples.clone())?.samples(),
        samples
    );
    for duplicate in [repair, bytes] {
        let mut repeated = samples.clone();
        repeated.push(duplicate);
        assert_eq!(
            RuntimeMetricSnapshot::new(repeated),
            Err(ContractError::InvalidInput)
        );
    }
    assert_eq!(
        RuntimeMetricSnapshot::new(vec![RuntimeMetric::Maintenance(
            MaintenanceMetricKind::Drain,
            MaintenanceMetric::Duration(LatencyHistogram {
                buckets: [1; 8],
                ..LatencyHistogram::default()
            })
        )]),
        Err(ContractError::InvalidInput)
    );
    Ok(())
}
