// SPDX-License-Identifier: GPL-2.0-only

use super::Measurement;
use meshspan_contracts::{FileOperationKind, FileOperationMetric};
use meshspan_domain::DurabilityScope;

pub(super) fn operation(
    kind: FileOperationKind,
    value: &FileOperationMetric,
) -> (&'static str, &'static str) {
    use FileOperationKind::{Close, Flush, Open, Read, StageWrite, UploadCommit};
    use FileOperationMetric::{Calls, Duration, ReturnedErrors};
    let name = match (kind, value) {
        (Open, Calls(_)) => "filesystem_open_calls",
        (Open, ReturnedErrors(_)) => "filesystem_open_returned_errors",
        (Open, Duration(_)) => "filesystem_open_duration_seconds",
        (Read, Calls(_)) => "filesystem_read_calls",
        (Read, ReturnedErrors(_)) => "filesystem_read_returned_errors",
        (Read, Duration(_)) => "filesystem_read_duration_seconds",
        (StageWrite, Calls(_)) => "filesystem_stage_write_calls",
        (StageWrite, ReturnedErrors(_)) => "filesystem_stage_write_returned_errors",
        (StageWrite, Duration(_)) => "filesystem_stage_write_duration_seconds",
        (Flush, Calls(_)) => "filesystem_flush_calls",
        (Flush, ReturnedErrors(_)) => "filesystem_flush_returned_errors",
        (Flush, Duration(_)) => "filesystem_flush_duration_seconds",
        (Close, Calls(_)) => "filesystem_close_calls",
        (Close, ReturnedErrors(_)) => "filesystem_close_returned_errors",
        (Close, Duration(_)) => "filesystem_close_duration_seconds",
        (UploadCommit, Calls(_)) => "filesystem_upload_commit_calls",
        (UploadCommit, ReturnedErrors(_)) => "filesystem_upload_commit_returned_errors",
        (UploadCommit, Duration(_)) => "filesystem_upload_commit_duration_seconds",
    };
    let help = match value {
        Calls(_) => "Shared filesystem calls which returned, including errors and exact retries.",
        ReturnedErrors(_) => {
            "Shared filesystem calls returning errors; durable effects may already exist. Not proof of rejection or rollback."
        }
        Duration(_) => {
            "Shared filesystem adapter duration including lock residence and required publication work; excludes client delivery."
        }
    };
    (name, help)
}

pub(super) fn publication(scope: DurabilityScope) -> (&'static str, &'static str) {
    let name = match scope {
        DurabilityScope::NodeLocal => "file_publications_node_local",
        DurabilityScope::CellReplicated => "file_publications_cell_replicated",
        DurabilityScope::GloballyConverged => "file_publications_globally_converged",
    };
    (
        name,
        "Verified file-publication barrier acknowledgements at the recorded scope, including replay; not unique versions or client delivery.",
    )
}

pub(super) fn measurement(value: &FileOperationMetric) -> Measurement<'_> {
    match value {
        FileOperationMetric::Calls(value) | FileOperationMetric::ReturnedErrors(value) => {
            Measurement::Counter(*value)
        }
        FileOperationMetric::Duration(value) => Measurement::Latency(value),
    }
}
