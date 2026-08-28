// SPDX-License-Identifier: GPL-2.0-only

//! Strict SQLite-compatible persistence for authoritative partitions and node-local state.

mod command;
mod database;
mod migration;
mod name;

pub use command::{
    ActivateGrant, AddGroupMember, AuthoritativeCommand, BootstrapMesh, CommandContext,
    CreateActivationPolicy, CreateComponent, CreateGroup, CreateObject, CreateUser, CreateVolume,
    GrantInheritance, GrantPermission, NamespaceObjectKind, PermissionScope,
};
pub use database::{IntegrityReport, LocalDatabase, PartitionDatabase};
pub use migration::MetadataStoreError;
pub use name::{RecordName, RecordNameError};
