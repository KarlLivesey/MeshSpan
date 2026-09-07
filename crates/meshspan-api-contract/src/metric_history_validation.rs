// SPDX-License-Identifier: GPL-2.0-only

//! Independent history-output validation, including exact counters and pagination context.

use crate::metadata_diagnostics::counter;
use crate::{
    BoundaryError, HistoricalMetricValue, MetricHistoryPoint, MetricHistoryResolution,
    MetricHistoryResponse,
};

/// Validates every outgoing sample, ordering and continuation before serialisation.
///
/// # Errors
/// Rejects invalid structure, unsigned overflow, contradictory histograms or page context.
pub fn encode_metric_history_response(
    value: &MetricHistoryResponse,
) -> Result<Vec<u8>, BoundaryError> {
    use crate::validation::{compile, validate, validator_from};
    static VALIDATOR: std::sync::OnceLock<Result<crate::validation::CompiledValidator, String>> =
        std::sync::OnceLock::new();
    let json = serde_json::to_value(value).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(
            VALIDATOR.get_or_init(|| {
                compile(&crate::schema::response_schema::<MetricHistoryResponse>())
            }),
        )?,
        &json,
    )?;
    let history_id = &value.history_id;
    let uptime = counter(&value.uptime_seconds)?;
    let (interval, retention, resolution) = match value.resolution {
        MetricHistoryResolution::Minute => (60, 21_600, "minute"),
        MetricHistoryResolution::Hour => (3600, 604_800, "hour"),
    };
    if counter(&value.retention_seconds)? != retention {
        return Err(BoundaryError::EncodeMismatch);
    }
    let mut previous = None;
    for point in &value.points {
        let bucket = validate_point(point, interval, uptime)?;
        if previous.is_some_and(|previous| bucket >= previous) {
            return Err(BoundaryError::EncodeMismatch);
        }
        previous = Some(bucket);
    }
    if let Some(next) = &value.next_page_url {
        let before = previous.ok_or(BoundaryError::EncodeMismatch)?;
        if next
            != &format!(
                "/api/latest/admin/metrics/history?resolution={resolution}&history_id={history_id}&before={before}"
            )
        {
            return Err(BoundaryError::EncodeMismatch);
        }
    }
    let bytes = serde_json::to_vec(&json).map_err(|_| BoundaryError::EncodeMismatch)?;
    if bytes.len() > crate::MAX_METRIC_HISTORY_BYTES {
        return Err(BoundaryError::EncodeMismatch);
    }
    Ok(bytes)
}

fn validate_point(
    point: &MetricHistoryPoint,
    interval: u64,
    uptime: u64,
) -> Result<u64, BoundaryError> {
    let bucket = counter(&point.bucket_start_seconds)?;
    let sampled = counter(&point.sampled_uptime_seconds)?;
    if bucket % interval != 0
        || sampled < bucket
        || sampled - bucket >= interval
        || sampled > uptime
    {
        return Err(BoundaryError::EncodeMismatch);
    }
    if let Some(metrics) = &point.metrics {
        let mut names = std::collections::BTreeSet::new();
        for metric in metrics {
            if !names.insert(&metric.name) {
                return Err(BoundaryError::EncodeMismatch);
            }
            validate_measurement(&metric.measurement)?;
        }
    }
    Ok(bucket)
}

fn validate_measurement(value: &HistoricalMetricValue) -> Result<(), BoundaryError> {
    match value {
        HistoricalMetricValue::Counter { value }
        | HistoricalMetricValue::Gauge { value }
        | HistoricalMetricValue::Bytes { value } => {
            counter(value)?;
        }
        HistoricalMetricValue::Seconds { value } => {
            seconds(&value.0)?;
        }
        HistoricalMetricValue::Histogram {
            count,
            sum_seconds,
            bucket_counts,
        } => {
            let count = counter(count)?;
            let sum = seconds(&sum_seconds.0)?;
            let mut previous = 0;
            for bucket in bucket_counts {
                let value = counter(bucket)?;
                if value < previous || value > count {
                    return Err(BoundaryError::EncodeMismatch);
                }
                previous = value;
            }
            if count == 0 && sum != (0, 0) {
                return Err(BoundaryError::EncodeMismatch);
            }
        }
    }
    Ok(())
}

fn seconds(value: &str) -> Result<(u64, u32), BoundaryError> {
    let (seconds, nanos) = value.split_once('.').ok_or(BoundaryError::EncodeMismatch)?;
    Ok((
        seconds.parse().map_err(|_| BoundaryError::EncodeMismatch)?,
        nanos.parse().map_err(|_| BoundaryError::EncodeMismatch)?,
    ))
}
