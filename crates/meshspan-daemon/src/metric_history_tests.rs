// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_api_contract::{HistoricalMetricValue, encode_metric_history_response};
use meshspan_contracts::{LatencyHistogram, RuntimeMetric, RuntimeMetricSnapshot};

fn point(elapsed: u64) -> MetricHistoryPoint {
    MetricHistoryPoint {
        bucket_start_seconds: count(0),
        sampled_uptime_seconds: count(elapsed),
        observed_at_epoch_micros: Some(1),
        metrics: None,
    }
}

#[test]
fn metric_history_is_time_bounded_downsampled_and_paged_without_sleep()
-> Result<(), Box<dyn std::error::Error>> {
    let mut history = MetricHistory::default();
    let elapsed = 14 * 24 * 3600;
    for now in (0..=elapsed).step_by(60) {
        history.record(point(now), now);
    }
    assert_eq!(history.minutes.points.len(), 360);
    assert_eq!(history.hours.points.len(), 168);
    let first = history.page(&MetricHistoryQuery::parse(None)?, elapsed)?;
    assert_eq!(first.points.len(), 30);
    assert_eq!(first.points[0].bucket_start_seconds, count(elapsed));
    assert!(first.older_samples_expired);
    assert!(first.points.iter().all(|point| point.metrics.is_none()));
    encode_metric_history_response(&first)?;
    let next = first.next_page_url.as_ref().ok_or("missing continuation")?;
    let query = next.split_once('?').ok_or("missing query")?.1;
    let second = history.page(&MetricHistoryQuery::parse(Some(query))?, elapsed)?;
    assert_eq!(
        second.points[0].bucket_start_seconds,
        count(elapsed - 30 * 60)
    );
    assert!(matches!(
        MetricHistory::default().page(&MetricHistoryQuery::parse(Some(query))?, elapsed),
        Err(MetricsError::Conflict)
    ));
    let hour = history.page(
        &MetricHistoryQuery::parse(Some("resolution=hour"))?,
        elapsed,
    )?;
    assert_eq!(hour.points[1].sampled_uptime_seconds, count(elapsed - 60));
    encode_metric_history_response(&hour)?;
    Ok(())
}

#[test]
fn metric_history_does_not_invent_samples_across_gaps_or_backward_wall_time()
-> Result<(), Box<dyn std::error::Error>> {
    let mut history = MetricHistory::default();
    let mut first = point(1);
    first.observed_at_epoch_micros = Some(100);
    first.metrics = Some(Vec::new());
    history.record(first, 1);
    history.record(point(301), 301);
    let page = history.page(&MetricHistoryQuery::parse(None)?, 301)?;
    assert_eq!(page.points.len(), 2);
    assert_eq!(page.points[0].bucket_start_seconds, count(300));
    assert_eq!(page.points[0].observed_at_epoch_micros, Some(1));
    assert_eq!(page.points[1].observed_at_epoch_micros, Some(100));
    assert_eq!(page.points[1].metrics, Some(Vec::new()));
    assert_eq!(page.next_page_url, None);
    encode_metric_history_response(&page)?;
    Ok(())
}

#[test]
fn metric_history_query_rejects_ambiguous_unbounded_and_unbound_continuations() {
    for query in [
        "resolution=minute&resolution=hour",
        "resolution=day",
        "unknown=1",
        "before=60",
        "history_id=1",
        "history_id=0&before=0",
        "history_id=01&before=0",
        "history_id=00000000000000000000000000000000&before=-1",
        "history_id=00000000000000000000000000000000&before=18446744073709551616",
        "history_id=00000000000000000000000000000000&before=0&before=60",
    ] {
        assert!(
            MetricHistoryQuery::parse(Some(query)).is_err(),
            "accepted {query}"
        );
    }
    assert!(MetricHistoryQuery::parse(Some(&"x".repeat(181))).is_err());
}

#[test]
fn metric_history_projection_preserves_exact_counter_and_histogram_values()
-> Result<(), Box<dyn std::error::Error>> {
    let mut histogram = LatencyHistogram::default();
    histogram.observe(std::time::Duration::from_micros(1000))?;
    let source = RuntimeMetricSnapshot::new(vec![
        RuntimeMetric::HttpsDispatches(u64::MAX),
        RuntimeMetric::HttpsDispatchDuration(histogram),
    ])?;
    let values = crate::openmetrics::historical_metrics(&source)?;
    assert!(values.iter().any(|value| value.measurement
        == HistoricalMetricValue::Counter {
            value: count(u64::MAX)
        }));
    let mut history = MetricHistory::default();
    let mut sampled = point(5);
    sampled.metrics = Some(values);
    history.record(sampled, 5);
    let page = history.page(&MetricHistoryQuery::parse(None)?, 5)?;
    encode_metric_history_response(&page)?;
    Ok(())
}

#[test]
fn metric_history_output_rejects_overflow_misordered_buckets_and_substituted_links()
-> Result<(), Box<dyn std::error::Error>> {
    let mut history = MetricHistory::default();
    for now in (0..=1800).step_by(60) {
        history.record(point(now), now);
    }
    let page = history.page(&MetricHistoryQuery::parse(None)?, 1800)?;
    let mut invalid = page.clone();
    invalid.history_id = "invalid".to_owned();
    assert!(encode_metric_history_response(&invalid).is_err());
    invalid = page.clone();
    invalid.uptime_seconds.0 = "18446744073709551616".to_owned();
    assert!(encode_metric_history_response(&invalid).is_err());
    invalid = page.clone();
    invalid.points.swap(0, 1);
    assert!(encode_metric_history_response(&invalid).is_err());
    invalid = page;
    invalid.next_page_url =
        Some("/api/latest/admin/metrics/history?resolution=hour&history_id=1&before=60".to_owned());
    assert!(encode_metric_history_response(&invalid).is_err());
    Ok(())
}
