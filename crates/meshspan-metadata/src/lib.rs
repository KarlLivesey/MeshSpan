// SPDX-License-Identifier: GPL-2.0-only

//! Strict SQLite-compatible persistence for authoritative partitions and node-local state.

mod database;
mod migration;

pub use database::{IntegrityReport, LocalDatabase, PartitionDatabase};
pub use migration::MetadataStoreError;
