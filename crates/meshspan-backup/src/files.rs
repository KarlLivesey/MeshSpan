// SPDX-License-Identifier: GPL-2.0-only

//! Fixed local source/destination slots; container input never chooses a filesystem path.

use std::path::Path;

/// Caller-selected closed source files or new restore destinations for one archive.
/// The metadata member always exists. Optional history is an inseparable journal pair.
#[derive(Clone, Copy, Debug)]
pub struct BackupFiles<'a> {
    /// Exact control-state SQLite snapshot.
    pub metadata: &'a Path,
    /// Both filesystem journals, when producing or extracting a history-bearing archive.
    pub history: Option<BackupHistoryFiles<'a>>,
}

/// Explicit local paths for the two fixed filesystem-history members.
#[derive(Clone, Copy, Debug)]
pub struct BackupHistoryFiles<'a> {
    /// Namespace journal source or new destination.
    pub namespace: &'a Path,
    /// Content-layout journal source or new destination.
    pub content: &'a Path,
}
