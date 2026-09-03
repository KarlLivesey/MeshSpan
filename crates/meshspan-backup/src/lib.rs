// SPDX-License-Identifier: GPL-2.0-only

//! Streaming authenticated encryption for exact-position metadata backups.
//!
//! The format keeps bulk backup bytes opaque at rest while wrapping one fresh
//! content key independently for each exact recovery recipient. Restore never
//! overwrites an existing destination and authenticates every bounded chunk
//! before writing it.

mod error;
mod format;
mod reader;
mod writer;

pub use error::BackupError;
pub use format::{BackupFileEvidence, BackupSourceManifest};
pub use reader::restore_backup;
pub use writer::encrypt_backup;

#[cfg(test)]
mod tests;
