// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_contracts::RuntimeMetricSource;

#[test]
fn file_results_keep_bytes_staging_and_publication_scopes_distinct()
-> Result<(), Box<dyn std::error::Error>> {
    let store = RuntimeObservations::default();
    let returned = store.measure_filesystem(
        FileOperationKind::Read,
        || Ok::<_, &str>(b"read".to_vec()),
        |bytes| bytes.len() as u64,
    )?;
    assert_eq!(returned, b"read");
    assert_eq!(
        store.measure_filesystem(
            FileOperationKind::Read,
            || Err::<Vec<u8>, _>("unavailable before coding"),
            |bytes| bytes.len() as u64
        ),
        Err("unavailable before coding")
    );
    for _ in 0..2 {
        store.measure_filesystem(FileOperationKind::StageWrite, || Ok::<_, &str>(()), |()| 3)?;
    }
    assert_eq!(
        store.measure_filesystem(
            FileOperationKind::UploadCommit,
            || Err::<(), _>("unknown publication outcome"),
            |()| 0
        ),
        Err("unknown publication outcome")
    );
    let samples = store.collect_metrics()?;
    for expected in [
        RuntimeMetric::FilesystemReadBytes(4),
        RuntimeMetric::FilesystemStagedWriteBytes(6),
        RuntimeMetric::FilesystemOperation(FileOperationKind::Read, FileOperationMetric::Calls(2)),
        RuntimeMetric::FilesystemOperation(
            FileOperationKind::Read,
            FileOperationMetric::ReturnedErrors(1),
        ),
        RuntimeMetric::FilesystemOperation(
            FileOperationKind::StageWrite,
            FileOperationMetric::Calls(2),
        ),
        RuntimeMetric::FilesystemOperation(
            FileOperationKind::UploadCommit,
            FileOperationMetric::ReturnedErrors(1),
        ),
        RuntimeMetric::FilePublications(DurabilityScope::NodeLocal, 0),
    ] {
        assert!(samples.samples().contains(&expected));
    }
    for scope in [
        DurabilityScope::NodeLocal,
        DurabilityScope::NodeLocal,
        DurabilityScope::CellReplicated,
        DurabilityScope::GloballyConverged,
    ] {
        store.observe_file_publication(scope);
    }
    let samples = store.collect_metrics()?;
    for (scope, count) in [
        (DurabilityScope::NodeLocal, 2),
        (DurabilityScope::CellReplicated, 1),
        (DurabilityScope::GloballyConverged, 1),
    ] {
        assert!(
            samples
                .samples()
                .contains(&RuntimeMetric::FilePublications(scope, count))
        );
    }
    Ok(())
}

#[test]
fn busy_telemetry_never_prevents_the_file_operation() -> Result<(), Box<dyn std::error::Error>> {
    let store = RuntimeObservations::default();
    let state = store.0.state.lock().map_err(|_| "poisoned test lock")?;
    assert_eq!(
        store.measure_filesystem(FileOperationKind::Read, || Ok::<_, &str>(17), |_| 17),
        Ok(17)
    );
    assert_eq!(state.filesystem.read_bytes, 0);
    assert_eq!(
        store.0.dropped.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    Ok(())
}
