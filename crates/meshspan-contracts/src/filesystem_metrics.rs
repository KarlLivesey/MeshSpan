// SPDX-License-Identifier: GPL-2.0-only

use crate::LatencyHistogram;

/// Fixed connector-neutral file-operation families, without user or path labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileOperationKind {
    /// Open an existing file handle.
    Open,
    /// Return verified logical bytes through a handle.
    Read,
    /// Durably stage a handle or upload range, without publishing the file.
    StageWrite,
    /// Flush a handle through its publication barrier.
    Flush,
    /// Close a handle, including any required flush or delete.
    Close,
    /// Complete an upload through its publication barrier.
    UploadCommit,
}

impl FileOperationKind {
    /// Every fixed operation in the process observation catalogue.
    pub const ALL: [Self; 6] = [
        Self::Open,
        Self::Read,
        Self::StageWrite,
        Self::Flush,
        Self::Close,
        Self::UploadCommit,
    ];
}

/// Returned adapter-call evidence, not client delivery or a count of unique mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileOperationMetric {
    /// Calls that returned, including errors and exact retries.
    Calls(u64),
    /// Calls returning errors; durable effects may already exist and require resolution.
    ReturnedErrors(u64),
    /// Time inside the shared adapter, including waiting for its filesystem lock and publication.
    Duration(LatencyHistogram),
}
