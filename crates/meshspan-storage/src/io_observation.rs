// SPDX-License-Identifier: GPL-2.0-only

//! RAII observation of synchronous calls, after releasing the provider lock.

use meshspan_contracts::{
    ContractError, ScrubObservation, ScrubOutcome, StorageIoCounts, StorageIoKind,
    StorageIoObservation, StorageIoObserver,
};
use std::sync::Arc;
use std::time::Instant;

pub(super) struct IoAttempt {
    observer: Option<Arc<dyn StorageIoObserver>>,
    kind: StorageIoKind,
    started: Instant,
    failed: bool,
    counts: Option<StorageIoCounts>,
}

impl IoAttempt {
    pub(super) fn new(observer: Option<Arc<dyn StorageIoObserver>>, kind: StorageIoKind) -> Self {
        Self {
            observer,
            kind,
            started: Instant::now(),
            failed: true,
            counts: Some(StorageIoCounts::default()),
        }
    }

    pub(super) fn finish<T>(
        mut self,
        result: &Result<T, ContractError>,
        counts: Option<StorageIoCounts>,
    ) {
        self.failed = result.is_err();
        self.counts = if matches!(result, Err(ContractError::Corrupt)) {
            Some(StorageIoCounts {
                payload_bytes: 0,
                corruption_reports: 1,
            })
        } else {
            counts
        };
    }
}

impl Drop for IoAttempt {
    fn drop(&mut self) {
        if let Some(observer) = &self.observer {
            observer.observe_storage_io(StorageIoObservation {
                kind: self.kind,
                duration: self.started.elapsed(),
                failed: self.failed,
                counts: self.counts,
            });
        }
    }
}

pub(super) fn scrub_counts(observations: &[ScrubObservation]) -> Option<StorageIoCounts> {
    observations
        .iter()
        .try_fold(StorageIoCounts::default(), |total, observation| {
            Some(StorageIoCounts {
                payload_bytes: total
                    .payload_bytes
                    .checked_add(observation.observed_length.unwrap_or(0))?,
                corruption_reports: total
                    .corruption_reports
                    .checked_add(u64::from(observation.outcome == ScrubOutcome::Corrupt))?,
            })
        })
}
