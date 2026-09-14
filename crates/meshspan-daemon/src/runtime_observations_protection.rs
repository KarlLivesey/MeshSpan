// SPDX-License-Identifier: GPL-2.0-only

//! Completed pass coverage and uncertainty are retained together, independently of request IO.

use super::RuntimeObservations;
use meshspan_contracts::{PlacementAssessment, ProtectionMetric, RuntimeMetric};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Default)]
pub(crate) struct ProtectionCounts {
    assessed: u64,
    unassessable: u64,
    missing_receipts: u64,
    insufficient_receipts: u64,
    protection_debt: u64,
    locality_debt: u64,
}

impl ProtectionCounts {
    pub(crate) fn observe(
        &mut self,
        missing: u64,
        assessment: Option<PlacementAssessment>,
    ) -> Result<(), ()> {
        let mut next = *self;
        next.missing_receipts = next.missing_receipts.checked_add(missing).ok_or(())?;
        if let Some(assessment) = assessment {
            next.assessed = next.assessed.checked_add(1).ok_or(())?;
            next.insufficient_receipts = next
                .insufficient_receipts
                .checked_add(u64::from(!assessment.sufficient_receipts))
                .ok_or(())?;
            next.protection_debt = next
                .protection_debt
                .checked_add(u64::from(!assessment.protection_satisfied))
                .ok_or(())?;
            next.locality_debt = next
                .locality_debt
                .checked_add(u64::from(!assessment.locality_satisfied))
                .ok_or(())?;
        } else {
            next.unassessable = next.unassessable.checked_add(1).ok_or(())?;
        }
        *self = next;
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct ObservedProtection {
    started: Instant,
    duration: Duration,
    counts: ProtectionCounts,
}

impl ObservedProtection {
    pub(super) fn append_metrics(&self, now: Instant, output: &mut Vec<RuntimeMetric>) {
        let counts = self.counts;
        output.extend(
            [
                ProtectionMetric::ObservationAge(now.saturating_duration_since(self.started)),
                ProtectionMetric::PassDuration(self.duration),
                ProtectionMetric::AssessedStripes(counts.assessed),
                ProtectionMetric::UnassessableStripes(counts.unassessable),
                ProtectionMetric::MissingShardReceipts(counts.missing_receipts),
                ProtectionMetric::InsufficientReceiptsStripes(counts.insufficient_receipts),
                ProtectionMetric::ProtectionDebtStripes(counts.protection_debt),
                ProtectionMetric::LocalityDebtStripes(counts.locality_debt),
            ]
            .into_iter()
            .map(RuntimeMetric::Protection),
        );
    }
}

impl RuntimeObservations {
    pub(crate) fn record_protection(&self, started: Instant, counts: ProtectionCounts) {
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        state.protection = Some(ObservedProtection {
            started,
            duration: started.elapsed(),
            counts,
        });
    }

    pub(crate) fn record_protection_unavailable(&self) {
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        if let Some(count) = state.protection_failures.checked_add(1) {
            state.protection_failures = count;
        } else {
            self.drop_update();
        }
    }
}
