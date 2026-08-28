// SPDX-License-Identifier: GPL-2.0-only

//! Strict SQLite-compatible persistence for authoritative partitions and node-local state.

mod command;
mod database;
mod migration;
mod name;
mod repository;

pub use command::{
    ActivateGrant, ActivateGroup, AddGroupMember, AssignComponent, AuthoritativeCommand,
    BootstrapMesh, CommandContext, ConfigureComponent, CreateActivationPolicy, CreateComponent,
    CreateGroup, CreateObject, CreateUser, CreateVolume, GrantInheritance, GrantPermission,
    NamespaceObjectKind, PermissionScope,
};
pub use database::{IntegrityReport, LocalDatabase, PartitionDatabase};
pub use migration::MetadataStoreError;
pub use name::{RecordName, RecordNameError};
pub use repository::{
    ApplyDisposition, AuthoritativeMetadataKernel, AuthoritativeRepository, CommandReceipt,
    EntityKind, EntityReference, GroupMemberCursor, InvariantFinding, InvariantKind,
    InvariantReport, LogPosition, NamespaceCursor, NamespaceRecord, Page, PageLimit,
    PartitionBackupManifest, PrincipalKind, PrincipalRecord, RepositoryConformanceCheck,
    RepositoryConformanceReport, RepositoryConformanceVector, RepositoryError,
    restore_partition_backup, run_repository_conformance,
};
