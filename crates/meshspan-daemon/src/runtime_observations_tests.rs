// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::metric_history::{MetricHistoryQuery, MetricHistorySource};
use meshspan_api_contract::DiagnosticRuntimeEventCode as Code;
use meshspan_contracts::{
    ConsensusMetric, ContractError, MAX_RUNTIME_METRIC_FAMILIES, RuntimeMetric, RuntimeMetricSource,
};

fn target(seed: u8) -> Result<TargetId, meshspan_domain::IdentifierError> {
    let mut bytes = [seed; 16];
    bytes[6] = 0x40;
    bytes[8] = 0x80;
    TargetId::from_bytes(bytes)
}

fn consensus_observation()
-> Result<meshspan_cluster::MetadataAuthorityObservation, meshspan_domain::IdentifierError> {
    Ok(meshspan_cluster::MetadataAuthorityObservation {
        partition_id: meshspan_domain::PartitionId::from_bytes([1; 16])?,
        node_id: meshspan_domain::NodeId::from_bytes([2; 16])?,
        role: meshspan_consensus::Role::Candidate,
        known_leader: None,
        term: 7,
        commit_index: 10,
        applied_index: 9,
        membership_epoch: 1,
        plan_digest: [3; 32],
        persistence_blocked: true,
        pending_operations: 2,
        queued_operations: 3,
        remote_members: 3,
        replication: None,
    })
}

#[test]
fn consensus_metrics_preserve_exact_observations_without_authority_claims()
-> Result<(), Box<dyn std::error::Error>> {
    let store = RuntimeObservations::default();
    let empty = store.collect_metrics()?;
    assert!(
        !empty
            .samples()
            .iter()
            .any(|sample| matches!(sample, RuntimeMetric::Consensus(ConsensusMetric::Role(_))))
    );
    store.record_consensus(consensus_observation()?, UnixMicros::new(100));
    store.record_consensus_unavailable(UnixMicros::new(90));
    let mut invalid = consensus_observation()?;
    invalid.applied_index = 11;
    store.record_consensus(invalid, UnixMicros::new(80));
    let metrics = store.collect_metrics()?;
    for expected in [
        ConsensusMetric::Role(meshspan_contracts::ConsensusObservedRole::Candidate),
        ConsensusMetric::Term(7),
        ConsensusMetric::CommittedIndex(10),
        ConsensusMetric::AppliedIndex(9),
        ConsensusMetric::PendingOperations(2),
        ConsensusMetric::QueuedOperations(3),
        ConsensusMetric::PersistenceBlocked(true),
        ConsensusMetric::LeaderKnown(false),
        ConsensusMetric::ObservationFailures(1),
        ConsensusMetric::RemoteMembers(3),
        ConsensusMetric::ApplyGap(1),
    ] {
        assert!(
            metrics
                .samples()
                .contains(&RuntimeMetric::Consensus(expected))
        );
    }
    assert!(
        metrics
            .samples()
            .contains(&RuntimeMetric::DroppedObservations(1))
    );
    let snapshot = store.snapshot().ok_or("missing snapshot")?;
    let mut aged = Vec::new();
    snapshot
        .state
        .consensus
        .as_ref()
        .ok_or("missing consensus")?
        .append_metrics(snapshot.captured + Duration::from_secs(2), &mut aged);
    assert!(aged.iter().any(|sample| matches!(sample,
        RuntimeMetric::Consensus(ConsensusMetric::ObservationAge(age)) if *age >= Duration::from_secs(2))));
    let text = String::from_utf8(crate::encode_openmetrics(&metrics)?)?;
    for line in [
        "meshspan_v1_consensus_role 2",
        "meshspan_v1_consensus_term 7",
        "meshspan_v1_consensus_committed_index 10",
        "meshspan_v1_consensus_applied_index 9",
        "meshspan_v1_consensus_pending_operations 2",
        "meshspan_v1_consensus_queued_operations 3",
        "meshspan_v1_consensus_persistence_blocked 1",
        "meshspan_v1_consensus_leader_known 0",
        "meshspan_v1_consensus_observation_failures_total 1",
    ] {
        assert!(text.lines().any(|actual| actual == line), "{line}");
    }
    assert!(!text.contains("quorum_available"));
    assert!(!text.contains("node_id"));
    assert!(!text.contains("consensus_replication_lagging_members"));
    Ok(())
}

#[test]
fn consensus_replication_metrics_clear_on_step_down_and_reject_inconsistent_counts()
-> Result<(), Box<dyn std::error::Error>> {
    let store = RuntimeObservations::default();
    let mut leader = consensus_observation()?;
    leader.role = meshspan_consensus::Role::Leader;
    leader.replication = Some(meshspan_cluster::MetadataReplicationObservation {
        unknown_members: 1,
        lagging_members: 1,
        maximum_committed_gap: 4,
    });
    store.record_consensus(leader, UnixMicros::new(100));
    let text = String::from_utf8(crate::encode_openmetrics(&store.collect_metrics()?)?)?;
    for line in [
        "meshspan_v1_consensus_remote_members 3",
        "meshspan_v1_consensus_apply_gap 1",
        "meshspan_v1_consensus_replication_unknown_members 1",
        "meshspan_v1_consensus_replication_lagging_members 1",
        "meshspan_v1_consensus_replication_maximum_committed_gap 4",
    ] {
        assert!(text.lines().any(|actual| actual == line), "{line}");
    }
    for invalid in [
        meshspan_cluster::MetadataReplicationObservation {
            unknown_members: 4,
            lagging_members: 0,
            maximum_committed_gap: 0,
        },
        meshspan_cluster::MetadataReplicationObservation {
            unknown_members: 2,
            lagging_members: 2,
            maximum_committed_gap: 4,
        },
        meshspan_cluster::MetadataReplicationObservation {
            unknown_members: 0,
            lagging_members: 1,
            maximum_committed_gap: 11,
        },
    ] {
        leader.replication = Some(invalid);
        store.record_consensus(leader, UnixMicros::new(101));
    }
    assert!(
        store
            .collect_metrics()?
            .samples()
            .contains(&RuntimeMetric::DroppedObservations(3))
    );
    store.record_consensus(consensus_observation()?, UnixMicros::new(102));
    let text = String::from_utf8(crate::encode_openmetrics(&store.collect_metrics()?)?)?;
    assert!(!text.contains("consensus_replication_"));
    assert!(text.contains("meshspan_v1_consensus_remote_members 3\n"));
    Ok(())
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
    // Includes both HTTPS rejection counters and the separate SMB credential-rejection counter.
    assert_eq!(store.collect_metrics()?.samples().len(), 99);
    store.record_inventory(
        Instant::now(),
        InventorySample::Certificate(Some(CertificateInventory {
            remaining: Duration::from_secs(60),
            not_yet_valid: false,
            expired: false,
            required: 3,
            installed: 2,
        })),
    );
    store.record_inventory(Instant::now(), InventorySample::Backups([1, 2, 3, 4, 5]));
    store.record_inventory(
        Instant::now(),
        InventorySample::Updates(UpdateInventory {
            states: [1, 2, 3, 4],
            active: Some(meshspan_metadata::UpdateProgressCounts::default()),
        }),
    );
    for kind in meshspan_contracts::LifecycleKind::ALL {
        store.record_lifecycle(
            kind,
            meshspan_contracts::LifecycleOutcome::Idle,
            Duration::from_millis(1),
        );
    }
    store.record_protection(Instant::now(), ProtectionCounts::default());
    store.record_maintenance_jobs(
        Instant::now(),
        [super::MaintenanceJobCounts::default(); 5],
        super::MaintenanceProgressCounts::default(),
    );
    let mut leader = consensus_observation()?;
    leader.role = meshspan_consensus::Role::Leader;
    leader.replication = Some(meshspan_cluster::MetadataReplicationObservation {
        unknown_members: 1,
        lagging_members: 1,
        maximum_committed_gap: 4,
    });
    store.record_consensus(leader, UnixMicros::new(100));
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
        RuntimeMetric::Lifecycle(
            meshspan_contracts::LifecycleKind::FederationSessions,
            meshspan_contracts::LifecycleMetric::Idle(1),
        ),
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
    assert!(text.contains("meshspan_v1_federation_sessions_idle_passes_total 1\n"));
    store.sample_history(UnixMicros::new(100));
    let history = store.history(MetricHistoryQuery::parse(None)?)?;
    assert_eq!(
        history.points[0]
            .metrics
            .as_ref()
            .ok_or("missing history metrics")?
            .len(),
        MAX_RUNTIME_METRIC_FAMILIES
    );
    meshspan_api_contract::encode_metric_history_response(&history)?;
    // All labels are finite histogram boundaries; target and event identities never escape.
    assert!(
        text.lines()
            .filter(|line| line.contains('{'))
            .all(|line| line.contains("_bucket{le=\""))
    );
    Ok(())
}

#[test]
fn metric_history_recovers_within_the_same_minute_after_observation_contention()
-> Result<(), Box<dyn std::error::Error>> {
    let store = RuntimeObservations::default();
    let locked = store
        .0
        .state
        .lock()
        .map_err(|_| "observation state poisoned")?;
    store.sample_history(UnixMicros::new(1));
    drop(locked);
    let missing = store.history(MetricHistoryQuery::parse(None)?)?;
    assert_eq!(missing.points.len(), 1);
    assert!(missing.points[0].metrics.is_none());
    store.sample_history(UnixMicros::new(2));
    let recovered = store.history(MetricHistoryQuery::parse(None)?)?;
    assert_eq!(recovered.points.len(), 1);
    assert_eq!(
        recovered.points[0].bucket_start_seconds,
        missing.points[0].bucket_start_seconds
    );
    assert_eq!(recovered.points[0].observed_at_epoch_micros, Some(2));
    assert!(recovered.points[0].metrics.as_ref().is_some_and(|metrics| {
        metrics
            .iter()
            .any(|metric| metric.name == "meshspan_v1_https_dispatches")
    }));
    store.sample_history(UnixMicros::new(3));
    assert_eq!(
        store.history(MetricHistoryQuery::parse(None)?)?.points,
        recovered.points
    );
    Ok(())
}
