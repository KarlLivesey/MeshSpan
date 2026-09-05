// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_contracts::RuntimeMetric;

#[test]
fn openmetrics_encodes_exact_counters_seconds_and_complete_histograms()
-> Result<(), Box<dyn std::error::Error>> {
    let mut latency = LatencyHistogram::default();
    latency.observe(Duration::from_millis(1))?;
    latency.observe(Duration::from_nanos(1_000_001))?;
    latency.observe(Duration::from_secs(31))?;
    let snapshot = RuntimeMetricSnapshot::new(vec![
        RuntimeMetric::Uptime(Duration::from_nanos(2_000_000_003)),
        RuntimeMetric::TargetProbeDuration(latency),
        RuntimeMetric::DroppedObservations(9_007_199_254_740_993),
    ])?;
    let expected = concat!(
        "# TYPE meshspan_v1_observation_drops counter\n",
        "# HELP meshspan_v1_observation_drops Observation updates not recorded by this process.\n",
        "meshspan_v1_observation_drops_total 9007199254740993\n",
        "# TYPE meshspan_v1_target_probe_duration_seconds histogram\n",
        "# UNIT meshspan_v1_target_probe_duration_seconds seconds\n",
        "# HELP meshspan_v1_target_probe_duration_seconds Duration of observed provider checks aggregated across all targets.\n",
        "meshspan_v1_target_probe_duration_seconds_bucket{le=\"0.001000000\"} 1\n",
        "meshspan_v1_target_probe_duration_seconds_bucket{le=\"0.005000000\"} 2\n",
        "meshspan_v1_target_probe_duration_seconds_bucket{le=\"0.025000000\"} 2\n",
        "meshspan_v1_target_probe_duration_seconds_bucket{le=\"0.100000000\"} 2\n",
        "meshspan_v1_target_probe_duration_seconds_bucket{le=\"0.500000000\"} 2\n",
        "meshspan_v1_target_probe_duration_seconds_bucket{le=\"1.000000000\"} 2\n",
        "meshspan_v1_target_probe_duration_seconds_bucket{le=\"5.000000000\"} 2\n",
        "meshspan_v1_target_probe_duration_seconds_bucket{le=\"30.000000000\"} 2\n",
        "meshspan_v1_target_probe_duration_seconds_bucket{le=\"+Inf\"} 3\n",
        "meshspan_v1_target_probe_duration_seconds_count 3\n",
        "meshspan_v1_target_probe_duration_seconds_sum 31.002000001\n",
        "# TYPE meshspan_v1_uptime_seconds gauge\n",
        "# UNIT meshspan_v1_uptime_seconds seconds\n",
        "# HELP meshspan_v1_uptime_seconds Monotonic process lifetime.\n",
        "meshspan_v1_uptime_seconds 2.000000003\n",
        "# EOF\n",
    );
    assert_eq!(encode_openmetrics(&snapshot)?, expected.as_bytes());
    assert_eq!(
        encode_openmetrics(&RuntimeMetricSnapshot::new(vec![])?)?,
        b"# EOF\n"
    );
    Ok(())
}

#[test]
fn openmetrics_family_order_is_independent_of_source_order() -> Result<(), ContractError> {
    let samples = vec![
        RuntimeMetric::OpenTargets(u64::MAX),
        RuntimeMetric::TargetProbePasses(2),
    ];
    let forward = encode_openmetrics(&RuntimeMetricSnapshot::new(samples.clone())?)?;
    let reverse = encode_openmetrics(&RuntimeMetricSnapshot::new(
        samples.into_iter().rev().collect(),
    )?)?;
    assert_eq!(forward, reverse);
    assert!(forward.len() < MAX_OPENMETRICS_BYTES);
    Ok(())
}
