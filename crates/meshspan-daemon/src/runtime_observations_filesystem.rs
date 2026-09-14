// SPDX-License-Identifier: GPL-2.0-only

use super::RuntimeObservations;
use meshspan_contracts::{
    ContractError, FileOperationKind, FileOperationMetric, LatencyHistogram, RuntimeMetric,
};
use meshspan_domain::DurabilityScope;
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
struct OperationMeasurements {
    duration: LatencyHistogram,
    errors: u64,
}

#[derive(Clone, Default)]
pub(super) struct FilesystemMeasurements {
    operations: [OperationMeasurements; 6],
    read_bytes: u64,
    staged_bytes: u64,
    publications: [u64; 3],
}

impl FilesystemMeasurements {
    fn record(
        &mut self,
        kind: FileOperationKind,
        failed: bool,
        bytes: u64,
        duration: Duration,
    ) -> Result<(), ContractError> {
        let (index, counter) = match kind {
            FileOperationKind::Open => (0, None),
            FileOperationKind::Read => (1, Some(&mut self.read_bytes)),
            FileOperationKind::StageWrite => (2, Some(&mut self.staged_bytes)),
            FileOperationKind::Flush => (3, None),
            FileOperationKind::Close => (4, None),
            FileOperationKind::UploadCommit => (5, None),
        };
        let total = counter
            .as_deref()
            .copied()
            .unwrap_or(0)
            .checked_add(bytes)
            .ok_or(ContractError::ResourceExhausted)?;
        let operation = self
            .operations
            .get_mut(index)
            .ok_or(ContractError::InternalContract)?;
        let errors = operation
            .errors
            .checked_add(u64::from(failed))
            .ok_or(ContractError::ResourceExhausted)?;
        operation.duration.observe(duration)?;
        operation.errors = errors;
        if let Some(counter) = counter {
            *counter = total;
        }
        Ok(())
    }

    pub(super) fn append_metrics(&self, output: &mut Vec<RuntimeMetric>) {
        for (kind, value) in FileOperationKind::ALL.into_iter().zip(&self.operations) {
            output.extend(
                [
                    FileOperationMetric::Calls(value.duration.count),
                    FileOperationMetric::ReturnedErrors(value.errors),
                    FileOperationMetric::Duration(value.duration.clone()),
                ]
                .map(|value| RuntimeMetric::FilesystemOperation(kind, value)),
            );
        }
        output.extend([
            RuntimeMetric::FilesystemReadBytes(self.read_bytes),
            RuntimeMetric::FilesystemStagedWriteBytes(self.staged_bytes),
        ]);
        for (scope, count) in [
            DurabilityScope::NodeLocal,
            DurabilityScope::CellReplicated,
            DurabilityScope::GloballyConverged,
        ]
        .into_iter()
        .zip(self.publications)
        {
            output.push(RuntimeMetric::FilePublications(scope, count));
        }
    }
}

impl RuntimeObservations {
    pub(crate) fn measure_filesystem<T, E>(
        &self,
        kind: FileOperationKind,
        operation: impl FnOnce() -> Result<T, E>,
        bytes: impl FnOnce(&T) -> u64,
    ) -> Result<T, E> {
        let started = Instant::now();
        let result = operation();
        let duration = started.elapsed();
        let count = result.as_ref().map_or(0, bytes);
        if let Ok(mut state) = self.0.state.try_lock() {
            if state
                .filesystem
                .record(kind, result.is_err(), count, duration)
                .is_err()
            {
                self.drop_update();
            }
        } else {
            self.drop_update();
        }
        result
    }

    pub(crate) fn observe_file_publication(&self, scope: DurabilityScope) {
        let Ok(mut state) = self.0.state.try_lock() else {
            self.drop_update();
            return;
        };
        let [local, cell, converged] = &mut state.filesystem.publications;
        let counter = match scope {
            DurabilityScope::NodeLocal => local,
            DurabilityScope::CellReplicated => cell,
            DurabilityScope::GloballyConverged => converged,
        };
        if let Some(value) = counter.checked_add(1) {
            *counter = value;
        } else {
            self.drop_update();
        }
    }
}

#[cfg(test)]
#[path = "runtime_observations_filesystem_tests.rs"]
mod tests;
