// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{PackSpaceObservation, RuntimeMetric, StorageUsageMetric};

#[derive(Clone, Default)]
pub(super) struct PackMeasurements {
    sampled: u64,
    unavailable: u64,
    database_bytes: u64,
    reusable_bytes: u64,
}

impl PackMeasurements {
    pub(super) fn observe(&mut self, value: Option<PackSpaceObservation>) {
        let totals = value
            .filter(|value| {
                value.database_bytes > 0 && value.reusable_bytes <= value.database_bytes
            })
            .and_then(|value| {
                Some((
                    self.database_bytes.checked_add(value.database_bytes)?,
                    self.reusable_bytes.checked_add(value.reusable_bytes)?,
                ))
            });
        if let Some((database, reusable)) = totals {
            self.sampled = self.sampled.saturating_add(1);
            self.database_bytes = database;
            self.reusable_bytes = reusable;
        } else {
            self.unavailable = self.unavailable.saturating_add(1);
        }
    }

    pub(super) fn append_metrics(&self, output: &mut Vec<RuntimeMetric>) {
        let mut values = vec![
            StorageUsageMetric::SampledPackTargets(self.sampled),
            StorageUsageMetric::UnavailablePackTargets(self.unavailable),
        ];
        if self.unavailable == 0 {
            values.extend([
                StorageUsageMetric::PackDatabaseBytes(self.database_bytes),
                StorageUsageMetric::PackReusableBytes(self.reusable_bytes),
            ]);
        }
        output.extend(values.into_iter().map(RuntimeMetric::StorageUsage));
    }
}
