// SPDX-License-Identifier: GPL-2.0-only

//! JSON history shares the exact typed catalogue with the text exporter.

use super::{Measurement, describe, seconds};
use meshspan_api_contract::{
    DiagnosticCounter, HistoricalMetric, HistoricalMetricValue, MetricSeconds,
};
use meshspan_contracts::{ContractError, RuntimeMetricSnapshot};

pub(crate) fn historical_metrics(
    snapshot: &RuntimeMetricSnapshot,
) -> Result<Vec<HistoricalMetric>, ContractError> {
    snapshot.validate()?;
    let count = |value: u64| DiagnosticCounter(value.to_string());
    let mut result = Vec::with_capacity(snapshot.samples().len());
    for sample in snapshot.samples() {
        let family = describe(sample);
        let measurement = match family.measurement {
            Measurement::Counter(value) => HistoricalMetricValue::Counter {
                value: count(value),
            },
            Measurement::Gauge(value) => HistoricalMetricValue::Gauge {
                value: count(value),
            },
            Measurement::Bytes(value) => HistoricalMetricValue::Bytes {
                value: count(value),
            },
            Measurement::Seconds(value) => HistoricalMetricValue::Seconds {
                value: MetricSeconds(seconds(value)),
            },
            Measurement::Latency(value) => HistoricalMetricValue::Histogram {
                count: count(value.count),
                sum_seconds: MetricSeconds(seconds(value.sum)),
                bucket_counts: value.buckets.into_iter().map(count).collect(),
            },
        };
        result.push(HistoricalMetric {
            name: format!("meshspan_v1_{}", family.name),
            measurement,
        });
    }
    result.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    Ok(result)
}
