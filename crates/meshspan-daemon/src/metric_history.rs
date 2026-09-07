// SPDX-License-Identifier: GPL-2.0-only

//! Fixed local windows, sampled outside the request path. No consensus or provider IO.

use std::collections::VecDeque;

use meshspan_api_contract::{
    DiagnosticCounter, MetricHistoryPoint, MetricHistoryResolution, MetricHistoryResponse,
};
use meshspan_contracts::RuntimeMetricSource;
use meshspan_domain::UnixMicros;

use crate::metrics_exporter_service::MetricsError;
use crate::runtime_observations::RuntimeObservations;

const PAGE_ITEMS: usize = 30;

pub(crate) trait MetricHistorySource: RuntimeMetricSource {
    fn history(&self, query: MetricHistoryQuery) -> Result<MetricHistoryResponse, MetricsError>;
}

/// Strict bounded page selection; continuations bind the current process history identity.
pub(crate) struct MetricHistoryQuery {
    resolution: MetricHistoryResolution,
    history_id: Option<String>,
    before: Option<u64>,
}

impl MetricHistoryQuery {
    pub(crate) fn parse(query: Option<&str>) -> Result<Self, MetricsError> {
        let raw = query.unwrap_or_default();
        if raw.len() > 180 {
            return Err(MetricsError::InvalidInput);
        }
        let mut resolution = None;
        let mut history_id = None;
        let mut before = None;
        for (name, value) in form_urlencoded::parse(raw.as_bytes()) {
            match name.as_ref() {
                "resolution" if resolution.is_none() => {
                    resolution = Some(match value.as_ref() {
                        "minute" => MetricHistoryResolution::Minute,
                        "hour" => MetricHistoryResolution::Hour,
                        _ => return Err(MetricsError::InvalidInput),
                    });
                }
                "history_id"
                    if history_id.is_none()
                        && value.len() == 32
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
                {
                    history_id = Some(value.into_owned());
                }
                "before" if before.is_none() => before = Some(number(&value)?),
                _ => return Err(MetricsError::InvalidInput),
            }
        }
        if history_id.is_some() != before.is_some() {
            return Err(MetricsError::InvalidInput);
        }
        Ok(Self {
            resolution: resolution.unwrap_or(MetricHistoryResolution::Minute),
            history_id,
            before,
        })
    }
}

fn number(value: &str) -> Result<u64, MetricsError> {
    let parsed: u64 = value.parse().map_err(|_| MetricsError::InvalidInput)?;
    (value == parsed.to_string())
        .then_some(parsed)
        .ok_or(MetricsError::InvalidInput)
}

pub(crate) struct MetricHistory {
    id: Option<String>,
    last_minute: Option<u64>,
    minutes: HistoryWindow,
    hours: HistoryWindow,
}

impl Default for MetricHistory {
    fn default() -> Self {
        let mut bytes = [0; 16];
        // Optional history becomes unavailable if entropy fails; the appliance keeps serving.
        let id = getrandom::fill(&mut bytes).ok().map(|()| {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            bytes
                .into_iter()
                .flat_map(|byte| {
                    [
                        char::from(HEX[usize::from(byte >> 4)]),
                        char::from(HEX[usize::from(byte & 15)]),
                    ]
                })
                .collect()
        });
        Self {
            id,
            last_minute: None,
            minutes: HistoryWindow::default(),
            hours: HistoryWindow::default(),
        }
    }
}

#[derive(Default)]
struct HistoryWindow {
    points: VecDeque<MetricHistoryPoint>,
    expired: bool,
}

impl HistoryWindow {
    fn record(
        &mut self,
        mut point: MetricHistoryPoint,
        elapsed: u64,
        interval: u64,
        capacity: u64,
    ) {
        let bucket = elapsed / interval * interval;
        point.bucket_start_seconds = count(bucket);
        if self
            .points
            .back()
            .is_some_and(|point| point.bucket_start_seconds.0 == bucket.to_string())
        {
            self.points.pop_back();
        }
        self.points.push_back(point);
        let cutoff = bucket.saturating_sub((capacity - 1) * interval);
        while self.points.front().is_some_and(|point| {
            point
                .bucket_start_seconds
                .0
                .parse::<u64>()
                .is_ok_and(|value| value < cutoff)
        }) {
            self.points.pop_front();
            self.expired = true;
        }
    }
}

impl MetricHistory {
    fn record(&mut self, point: MetricHistoryPoint, elapsed: u64) {
        self.minutes.record(point.clone(), elapsed, 60, 360);
        self.hours.record(point, elapsed, 3600, 168);
        self.last_minute = Some(elapsed / 60);
    }

    fn page(
        &self,
        query: &MetricHistoryQuery,
        elapsed: u64,
    ) -> Result<MetricHistoryResponse, MetricsError> {
        let history_id = self.id.as_ref().ok_or(MetricsError::Unavailable)?;
        if query
            .history_id
            .as_ref()
            .is_some_and(|expected| expected != history_id)
        {
            return Err(MetricsError::Conflict);
        }
        let (window, retention, interval, resolution) = match query.resolution {
            MetricHistoryResolution::Minute => (&self.minutes, 21_600, 60, "minute"),
            MetricHistoryResolution::Hour => (&self.hours, 604_800, 3600, "hour"),
        };
        if query
            .before
            .is_some_and(|before| before % interval != 0 || before > elapsed)
        {
            return Err(MetricsError::InvalidInput);
        }
        let mut selected = window.points.iter().rev().filter(|point| {
            query.before.is_none_or(|before| {
                point
                    .bucket_start_seconds
                    .0
                    .parse::<u64>()
                    .is_ok_and(|bucket| bucket < before)
            })
        });
        let points: Vec<_> = selected.by_ref().take(PAGE_ITEMS).cloned().collect();
        let next_page_url = if selected.next().is_some() {
            let before = &points
                .last()
                .ok_or(MetricsError::Failed)?
                .bucket_start_seconds
                .0;
            Some(format!(
                "/api/latest/admin/metrics/history?resolution={resolution}&history_id={history_id}&before={before}"
            ))
        } else {
            None
        };
        Ok(MetricHistoryResponse {
            history_id: history_id.clone(),
            resolution: query.resolution,
            retention_seconds: count(retention),
            uptime_seconds: count(elapsed),
            older_samples_expired: window.expired,
            points,
            next_page_url,
        })
    }
}

impl RuntimeObservations {
    pub(crate) fn sample_history(&self, now: UnixMicros) {
        let Ok(mut history) = self.0.history.try_lock() else {
            return;
        };
        let elapsed = self.0.started.elapsed().as_secs();
        if history
            .last_minute
            .is_some_and(|minute| elapsed / 60 <= minute)
        {
            return;
        }
        // Both locks are non-waiting; no observation collector takes them in reverse order.
        let metrics = self
            .collect_metrics()
            .ok()
            .and_then(|value| crate::openmetrics::historical_metrics(&value).ok());
        history.record(
            MetricHistoryPoint {
                bucket_start_seconds: count(0),
                sampled_uptime_seconds: count(elapsed),
                observed_at_epoch_micros: (0..=9_007_199_254_740_991)
                    .contains(&now.get())
                    .then_some(now.get()),
                metrics,
            },
            elapsed,
        );
    }
}

impl MetricHistorySource for RuntimeObservations {
    fn history(&self, query: MetricHistoryQuery) -> Result<MetricHistoryResponse, MetricsError> {
        self.0
            .history
            .try_lock()
            .map_err(|_| MetricsError::Unavailable)?
            .page(&query, self.0.started.elapsed().as_secs())
    }
}

fn count(value: u64) -> DiagnosticCounter {
    DiagnosticCounter(value.to_string())
}

#[cfg(test)]
#[path = "metric_history_tests.rs"]
mod tests;
