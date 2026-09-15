// SPDX-License-Identifier: GPL-2.0-only

//! Versioned capability boundaries and reusable deterministic conformance harnesses.

mod access;
mod authority;
mod backup;
mod backup_capacity;
mod common;
mod component;
mod conformance;
mod data;
mod federation_storage;
mod filesystem;
mod maintenance_metrics;
mod maintenance_progress_metrics;
pub use maintenance_progress_metrics::MaintenanceProgressMetric;
mod coding_metrics;
mod filesystem_metrics;
pub use filesystem_metrics::{FileOperationKind, FileOperationMetric};
mod gateway_transfer;
mod inventory_metrics;
mod lifecycle_metrics;
mod metrics;
pub use coding_metrics::{CodingMetric, CodingOperation};
pub use gateway_transfer::{GatewayTransferMetric, GatewayTransferObserver};
pub use inventory_metrics::InventoryMetric;
pub use lifecycle_metrics::{LifecycleKind, LifecycleMetric, LifecycleOutcome};
mod placement_assessment;
mod protection_metrics;
pub use placement_assessment::{PlacementAssessment, PlacementAssessmentRequest};
pub use protection_metrics::ProtectionMetric;
mod observability;
mod security;
mod shard_put;
mod shard_receipt;
pub use shard_put::{RepairPutAdmission, ShardPutIdentity, ShardPutIntent, ShardPutResolution};
mod shard_put_intent;
pub use shard_put_intent::{
    SHARD_PUT_INTENT_V1_BYTES, decode_shard_put_intent_v1, encode_shard_put_intent_v1,
};
mod storage;
pub use shard_receipt::{SHARD_RECEIPT_V1_BYTES, decode_shard_receipt_v1, encode_shard_receipt_v1};
mod storage_io;
mod storage_usage;
pub use storage_io::{
    StorageIoCounts, StorageIoKind, StorageIoMetric, StorageIoObservation, StorageIoObserver,
};
mod suites;

pub use maintenance_metrics::{MaintenanceMetric, MaintenanceMetricKind};
pub use storage_usage::{
    FilesystemSpaceObservation, PackSpaceObservation, StorageUsageMetric, StorageUsageObservation,
    StorageUsageSource,
};

pub use access::{
    AccessConnector, AccessIntent, AccessOperation, AccessResult, AccessSession,
    AdministrationClient, AdministrationIntent, AdministrationResult,
};

pub use authority::{
    ConsensusCommit, ConsensusEngine, ConsensusProposal, LogPosition, MetadataCommand,
    MetadataCommandKind, MetadataPage, MetadataQuery, MetadataRepository, MetadataResult,
    OperationState, RepositorySnapshot,
};
pub use backup::{
    BackupDeleteReceipt, BackupDeleteRequest, BackupLookupRequest, BackupObjectIdentity,
    BackupObjectReceipt, BackupObjectReference, BackupProvider, BackupReadReceipt,
    BackupReadRequest, BackupStoreRequest, BackupVerifyRequest,
    MAXIMUM_BACKUP_OBJECT_REFERENCE_BYTES, validate_backup_delete_request,
    validate_backup_lookup_request, validate_backup_read_request, validate_backup_store_request,
    validate_backup_verify_request,
};
pub use backup_capacity::{BackupCapacityBudget, MAXIMUM_BACKUP_CAPACITY_PAGE};

pub use common::{
    BoundedBytes, BoundedBytesError, BoundedItems, BoundedItemsError, ContractError, ContractKind,
    ContractLimits, ContractVersion, ImplementationDescriptor, RequestContext, VersionedPayload,
};
pub use component::{
    ComponentConfiguration, ComponentLifecycle, ComponentObservation, ComponentTransition,
};
pub use conformance::{
    CaseFailureKind, ConformanceCase, ConformanceFailure, HarnessError, run_conformance_cases,
    verify_descriptor,
};
pub use data::{
    CodingLayout, CodingLayoutError, CodingScheme, PlacementCandidate, PlacementCellRequirement,
    PlacementCellRole, PlacementPlan, PlacementPolicy, PlacementRequest, RebalancePlacementPlan,
    RebalancePlacementRequest, ReconstructionRequest, RepairPlacementPlan, RepairPlacementRequest,
    ShardAcknowledgement,
};
pub use federation_storage::{
    FederatedBackupPermit, FederatedBackupRequest, FederatedBackupScope, FederatedShardPermit,
    FederatedStorageInventoryRecord, FederatedStoragePermitMacKey,
    MAXIMUM_FEDERATED_BACKUP_PERMIT_LIFETIME_MICROS, federated_backup_permit_mac,
    federated_backup_request_digest, federated_provider_backup_identity,
    federated_provider_shard_identity, federated_shard_permit_mac,
    federated_shard_read_result_digest, federated_shard_reclamation_result_digest,
    federated_shard_retirement_result_digest, federated_shard_scrub_result_digest,
    federated_shard_write_result_digest, validate_federated_backup_permit,
    validate_federated_storage_inventory_record, verify_federated_backup_permit_mac,
    verify_federated_shard_permit_mac,
};
pub use filesystem::{
    namespace_reconciliation_result_digest, namespace_snapshot_restore_result_digest,
};
pub use metrics::{
    ConsensusMetric, ConsensusObservedRole, GatewayDispatchObservation, GatewayDispatchObserver,
    GatewayDispatchOutcome, GatewayProtocol, LatencyHistogram, MAX_RUNTIME_METRIC_FAMILIES,
    METRIC_LATENCY_BOUNDARIES_MICROS, RuntimeMetric, RuntimeMetricSnapshot, RuntimeMetricSource,
};
pub use observability::{EventSeverity, ObservabilityReceipt, ObservabilitySink, RedactedEvent};
pub use security::{
    AuthenticationAttempt, AuthenticationHandler, AuthenticationOutcome, CertificateChallenge,
    CertificateChallengeCleanup, CertificateChallengeKind, CertificateChallengeReceipt,
    CertificateChallengeRequest,
};
pub use storage::{
    InventoryEntry, InventoryPage, PutShardRequest, ReclamationReceipt, RemovalAuthorityFence,
    RemovalPermit, ReservationClass, ReserveStorageRequest, ScrubObservation, ScrubOutcome,
    ScrubPage, ShardIdentity, ShardReadPermit, ShardReceipt, ShardWritePermit, StoragePermitMacKey,
    StorageProvider, StorageReservation, TombstoneReceipt, read_permit_mac,
    reclamation_receipt_digest, removal_permit_mac, tombstone_receipt_digest,
    validate_exact_scrub_observation, verify_read_permit_mac, verify_removal_permit_mac,
    verify_write_permit_mac, write_permit_mac,
};
pub use suites::{
    run_access_connector_suite, run_administration_client_suite, run_authentication_handler_suite,
    run_backup_provider_suite, run_certificate_challenge_suite, run_coding_scheme_suite,
    run_consensus_engine_suite, run_metadata_repository_suite, run_observability_sink_suite,
    run_placement_policy_suite, run_storage_provider_suite,
};
