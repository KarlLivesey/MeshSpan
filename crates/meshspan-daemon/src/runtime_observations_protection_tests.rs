// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_contracts::{
    PlacementAssessment, ProtectionMetric, RuntimeMetric, RuntimeMetricSource,
};

#[test]
fn protection_metrics_preserve_coverage_unknowns_age_and_exact_debt_counts()
-> Result<(), Box<dyn std::error::Error>> {
    let store = RuntimeObservations::default();
    assert!(
        !store
            .collect_metrics()?
            .samples()
            .iter()
            .any(|metric| matches!(
                metric,
                RuntimeMetric::Protection(ProtectionMetric::AssessedStripes(_))
            ))
    );
    let mut counts = ProtectionCounts::default();
    for (missing, assessment) in [
        (
            0,
            Some(PlacementAssessment {
                sufficient_receipts: true,
                protection_satisfied: true,
                locality_satisfied: true,
            }),
        ),
        (
            1,
            Some(PlacementAssessment {
                sufficient_receipts: true,
                protection_satisfied: false,
                locality_satisfied: true,
            }),
        ),
        (
            2,
            Some(PlacementAssessment {
                sufficient_receipts: false,
                protection_satisfied: false,
                locality_satisfied: false,
            }),
        ),
        (3, None),
    ] {
        counts
            .observe(missing, assessment)
            .map_err(|()| "count failed")?;
    }
    store.record_protection(Instant::now(), counts);
    store.record_protection_unavailable();
    let snapshot = store.collect_metrics()?;
    for expected in [
        ProtectionMetric::AssessedStripes(3),
        ProtectionMetric::UnassessableStripes(1),
        ProtectionMetric::MissingShardReceipts(6),
        ProtectionMetric::InsufficientReceiptsStripes(1),
        ProtectionMetric::ProtectionDebtStripes(2),
        ProtectionMetric::LocalityDebtStripes(1),
        ProtectionMetric::ObservationFailures(1),
    ] {
        assert!(
            snapshot
                .samples()
                .contains(&RuntimeMetric::Protection(expected))
        );
    }
    let text = String::from_utf8(crate::encode_openmetrics(&snapshot)?)?;
    assert!(
        text.lines()
            .any(|line| line == "meshspan_v1_protection_catalogue_protection_debt_stripes 2")
    );
    assert!(
        text.lines()
            .any(|line| line == "meshspan_v1_protection_catalogue_locality_debt_stripes 1")
    );
    let history = crate::openmetrics::historical_metrics(&snapshot)?;
    assert!(history.iter().any(|metric| metric.name
        == "meshspan_v1_protection_catalogue_missing_shard_receipts"
        && metric.measurement
            == meshspan_api_contract::HistoricalMetricValue::Gauge {
                value: meshspan_api_contract::DiagnosticCounter("6".to_owned()),
            }));
    let captured = store.snapshot().ok_or("snapshot missing")?;
    let mut aged = Vec::new();
    captured
        .state
        .protection
        .as_ref()
        .ok_or("pass missing")?
        .append_metrics(captured.captured + Duration::from_secs(10), &mut aged);
    assert!(aged.iter().any(|metric| matches!(metric,
        RuntimeMetric::Protection(ProtectionMetric::ObservationAge(age)) if *age >= Duration::from_secs(10))));
    Ok(())
}
