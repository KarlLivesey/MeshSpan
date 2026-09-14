// SPDX-License-Identifier: GPL-2.0-only

//! Streaming authenticated encryption for exact-position metadata backups.
//!
//! The format keeps bulk backup bytes opaque at rest while wrapping one fresh
//! content key independently for each exact recovery recipient. Restore never
//! overwrites an existing destination and authenticates every bounded chunk
//! before writing it.

mod directory_provider;
#[cfg(test)]
mod directory_provider_tests;
mod error;
mod export;
#[cfg(test)]
mod export_tests;
mod files;
mod format;
mod intersected_capacity;
mod namespaced_provider;
mod reader;
mod shared_provider;
mod writer;

pub use directory_provider::{DirectoryBackupProvider, DirectoryBackupProviderError};
pub use error::BackupError;
pub use export::{BackupExportEvidence, VerifiedBackupExport};
pub use files::{BackupFiles, BackupHistoryFiles};
pub use format::{
    BackupFileEvidence, BackupHistoryEvidence, BackupJournalEvidence, BackupSourceManifest,
};
pub use intersected_capacity::IntersectedBackupCapacity;
pub use namespaced_provider::NamespacedBackupProvider;
pub use reader::{read_backup_evidence, restore_backup, restore_backup_files};
pub use shared_provider::SharedBackupProvider;
pub use writer::{encrypt_backup, encrypt_backup_files};

#[cfg(test)]
mod tests;
