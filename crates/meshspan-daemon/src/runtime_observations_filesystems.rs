// SPDX-License-Identifier: GPL-2.0-only

//! Per-pass mounted-filesystem attribution, independent of target payload accounting.

use meshspan_contracts::{FilesystemSpaceObservation, RuntimeMetric, StorageUsageMetric};
use std::collections::BTreeMap;

#[derive(Clone, Default)]
pub(super) struct FilesystemMeasurements {
    sampled: BTreeMap<u64, FilesystemSpaceObservation>,
    unavailable: u64,
}

impl FilesystemMeasurements {
    pub(super) fn observe(&mut self, value: Option<FilesystemSpaceObservation>) {
        let Some(value) = value
            .filter(|value| value.total_bytes > 0 && value.available_bytes <= value.total_bytes)
        else {
            self.unavailable = self.unavailable.saturating_add(1);
            return;
        };
        if let Some(previous) = self.sampled.get_mut(&value.identity) {
            // Multiple folders see the same space at different instants. Keep the smaller
            // observations, never sum them or imply that sampling reserved these bytes.
            previous.total_bytes = previous.total_bytes.min(value.total_bytes);
            previous.available_bytes = previous.available_bytes.min(value.available_bytes);
        } else if self.sampled.len() < 1_024 {
            self.sampled.insert(value.identity, value);
        } else {
            self.unavailable = self.unavailable.saturating_add(1);
        }
    }

    pub(super) fn append_metrics(&self, output: &mut Vec<RuntimeMetric>) {
        let totals = self
            .sampled
            .values()
            .try_fold((0_u64, 0_u64), |(total, available), value| {
                Some((
                    total.checked_add(value.total_bytes)?,
                    available.checked_add(value.available_bytes)?,
                ))
            });
        let unavailable = self.unavailable.saturating_add(u64::from(totals.is_none()));
        let mut values = vec![
            StorageUsageMetric::SampledFilesystems(self.sampled.len() as u64),
            StorageUsageMetric::UnavailableFilesystemTargets(unavailable),
        ];
        if unavailable == 0
            && let Some((total, available)) = totals
        {
            values.extend([
                StorageUsageMetric::FilesystemTotalBytes(total),
                StorageUsageMetric::FilesystemAvailableBytes(available),
            ]);
        }
        output.extend(values.into_iter().map(RuntimeMetric::StorageUsage));
    }
}
