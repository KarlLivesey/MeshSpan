// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_api_contract::DiagnosticRuntimeEventCode as Code;
use meshspan_contracts::{
    ContractError, MAX_RUNTIME_METRIC_FAMILIES, RuntimeMetric, RuntimeMetricSource,
};

fn target(seed: u8) -> Result<TargetId, meshspan_domain::IdentifierError> {
    let mut bytes = [seed; 16];
    bytes[6] = 0x40;
    bytes[8] = 0x80;
    TargetId::from_bytes(bytes)
}

fn cycle(failed_steps: usize) -> StorageCycleSummary {
    StorageCycleSummary {
        configured_folders: 2,
        open_targets: 1,
        pending_return_scans: 1,
        failed_steps,
    }
}

#[test]
fn runtime_observations_deduplicate_transitions_without_using_wall_clock_order()
-> Result<(), Box<dyn std::error::Error>> {
    let store = RuntimeObservations::default();
    let target = target(1)?;
    for (passed, wall) in [(false, 100), (false, 90), (true, 80)] {
        store.record_probe(
            (target, 7),
            passed,
            Duration::from_millis(3),
            Some(UnixMicros::new(wall)),
        );
    }
    for failures in [1, 1, 0] {
        store.record_cycle(
            cycle(failures),
            Duration::from_millis(8),
            Some(UnixMicros::new(70)),
        );
    }
    let mut snapshot = store.snapshot().ok_or("snapshot missing")?;
    snapshot.captured += Duration::from_secs(2);
    snapshot.uptime += Duration::from_secs(2);
    let response = snapshot.project();
    assert_eq!(response.target_probe_passes.0, "1");
    assert_eq!(response.target_probe_failures.0, "2");
    assert_eq!(response.reconciliation_cycles.0, "3");
    assert_eq!(response.reconciliation_failures.0, "2");
    assert_eq!(response.target_checks.len(), 1);
    assert_eq!(response.target_checks[0].observation.sequence.0, "3");
    assert_eq!(
        response.target_checks[0]
            .observation
            .observed_at_epoch_micros,
        80
    );
    assert!(
        response.target_checks[0]
            .observation
            .age_millis
            .0
            .parse::<u64>()?
            >= 2000
    );
    assert_eq!(
        response
            .recent_events
            .iter()
            .map(|event| event.code)
            .collect::<Vec<_>>(),
        vec![
            Code::StorageReconciliationRecovered,
            Code::StorageReconciliationFailed,
            Code::TargetProbeRecovered,
            Code::TargetProbeFailed,
        ]
    );
    assert_eq!(
        response
            .recent_events
            .iter()
            .map(|event| event.observation.sequence.0.as_str())
            .collect::<Vec<_>>(),
        vec!["6", "4", "3", "1"]
    );
    Ok(())
}

#[test]
fn runtime_observation_windows_bound_churn_and_expose_evictions()
-> Result<(), Box<dyn std::error::Error>> {
    let store = RuntimeObservations::default();
    for seed in 1..=105 {
        store.record_probe(
            (target(seed)?, 1),
            false,
            Duration::ZERO,
            Some(UnixMicros::new(100)),
        );
    }
    let response = store.snapshot().ok_or("snapshot missing")?.project();
    assert_eq!(response.target_checks.len(), 100);
    assert_eq!(response.recent_events.len(), 100);
    assert_eq!(response.target_check_evictions.0, "5");
    assert_eq!(response.event_evictions.0, "5");
    assert_eq!(response.target_probe_failures.0, "105");
    assert_eq!(response.recent_events[0].observation.sequence.0, "105");
    assert_eq!(response.recent_events[99].observation.sequence.0, "6");
    let metrics = store.collect_metrics()?;
    assert!(
        metrics
            .samples()
            .contains(&RuntimeMetric::TargetProbeFailures(105))
    );
    let histogram = metrics
        .samples()
        .iter()
        .find_map(|sample| match sample {
            RuntimeMetric::TargetProbeDuration(histogram) => Some(histogram),
            _ => None,
        })
        .ok_or("probe histogram missing")?;
    assert_eq!(histogram.count, 105);
    assert_eq!(histogram.buckets, [105; 8]);
    Ok(())
}

#[test]
fn runtime_observation_contention_and_invalid_clocks_do_not_block_domain_work()
-> Result<(), Box<dyn std::error::Error>> {
    let store = RuntimeObservations::default();
    let locked = store.0.state.lock().map_err(|_| "observation lock")?;
    assert_eq!(store.collect_metrics(), Err(ContractError::Unavailable));
    let worker_store = store.clone();
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        worker_store.record_cycle(cycle(0), Duration::ZERO, Some(UnixMicros::new(100)));
        send.send(worker_store.snapshot().is_none())
    });
    let observed = receive.recv_timeout(Duration::from_secs(2));
    drop(locked);
    worker.join().map_err(|_| "observation worker panic")??;
    assert!(observed?);
    for at in [
        None,
        Some(UnixMicros::new(-1)),
        Some(UnixMicros::new(9_007_199_254_740_992)),
    ] {
        store.record_cycle(cycle(0), Duration::ZERO, at);
    }
    store.record_probe(
        (target(1)?, 0),
        true,
        Duration::ZERO,
        Some(UnixMicros::new(100)),
    );
    let response = store.snapshot().ok_or("snapshot missing")?.project();
    assert_eq!(response.dropped_updates.0, "5");
    assert_eq!(response.observation_sequence.0, "0");
    assert!(response.storage_reconciliation.is_none());
    assert!(response.target_checks.is_empty());
    assert!(response.recent_events.is_empty());
    Ok(())
}

#[test]
fn runtime_metrics_omit_unobserved_gauges_and_include_all_recorded_families()
-> Result<(), Box<dyn std::error::Error>> {
    let store = RuntimeObservations::default();
    // Last-cycle and usage gauges are absent until sampled; lifetime counters start at zero.
    assert_eq!(store.collect_metrics()?.samples().len(), 33);
    store.record_storage_usage(super::StorageUsagePass::default());
    store.record_cycle(
        cycle(2),
        Duration::from_millis(8),
        Some(UnixMicros::new(100)),
    );
    let metrics = store.collect_metrics()?;
    assert_eq!(metrics.samples().len(), MAX_RUNTIME_METRIC_FAMILIES);
    for sample in [
        RuntimeMetric::ReconciliationCycles(1),
        RuntimeMetric::ReconciliationFailures(1),
        RuntimeMetric::ConfiguredFolders(2),
        RuntimeMetric::OpenTargets(1),
        RuntimeMetric::PendingReturnScans(1),
        RuntimeMetric::LastReconciliationFailedSteps(2),
    ] {
        assert!(metrics.samples().contains(&sample));
    }
    let text = String::from_utf8(crate::encode_openmetrics(&metrics)?)?;
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("# TYPE "))
            .count(),
        MAX_RUNTIME_METRIC_FAMILIES
    );
    assert!(text.len() < crate::MAX_OPENMETRICS_BYTES);
    assert!(text.ends_with("# EOF\n"));
    // All labels are finite histogram boundaries; target and event identities never escape.
    assert!(
        text.lines()
            .filter(|line| line.contains('{'))
            .all(|line| line.contains("_bucket{le=\""))
    );
    Ok(())
}
