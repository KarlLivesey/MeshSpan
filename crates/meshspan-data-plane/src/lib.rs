// SPDX-License-Identifier: GPL-2.0-only

//! Authentication, capability decoding and bounded private shard and backup streams.

mod backup_bridge;
mod backup_client;
mod backup_error;
mod backup_router;
mod backup_server;
mod backup_wire;
mod capability;
mod client;
mod data_router;
mod error;
mod router;
mod server;
mod wire;

pub use backup_client::{delete_backup, read_backup, store_backup, verify_backup};
pub use backup_error::BackupPlaneError;
pub use backup_router::RemoteBackupRouter;
pub use backup_server::{RemoteBackupAuthorisation, RemoteBackupAuthority, RemoteBackupService};
pub use capability::{
    CapabilityCodecError, decode_federated_shard_permit, decode_read_permit, decode_removal_permit,
    decode_write_permit, encode_federated_shard_permit, encode_read_permit, encode_removal_permit,
    encode_write_permit,
};
pub use client::{
    get_federated_shard, get_shard, put_federated_shard, put_shard, reclaim_federated_shard,
    reclaim_shard, retire_federated_shard, scrub_federated_shard, tombstone_shard,
};
pub use data_router::{RemoteDataRouter, RemoteDataRouterError};
pub use error::DataPlaneError;
pub use router::RemoteShardRouter;
pub use server::{
    FederatedReclamationEvidence, FederatedRetirementEvidence, FederatedScrubEvidence,
    FederatedScrubPreparation, FederatedShardAuthority, FederatedShardOutcome,
    FederatedWriteEvidence, RemoteShardService,
};
