// SPDX-License-Identifier: GPL-2.0-only

//! Versioned capability boundaries and reusable deterministic conformance harnesses.

mod access;
mod authority;
mod common;
mod component;
mod conformance;
mod data;
mod federation_storage;
mod filesystem;
mod observability;
mod security;
mod storage;
mod suites;

pub use access::{
    AccessConnector, AccessIntent, AccessOperation, AccessResult, AccessSession,
    AdministrationClient, AdministrationIntent, AdministrationResult,
};

pub use authority::{
    ConsensusCommit, ConsensusEngine, ConsensusProposal, LogPosition, MetadataCommand,
    MetadataCommandKind, MetadataPage, MetadataQuery, MetadataRepository, MetadataResult,
    OperationState, RepositorySnapshot,
};

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
    CodingLayout, CodingLayoutError, CodingScheme, PlacementPlan, PlacementPolicy,
    PlacementRequest, ReconstructionRequest,
};
pub use federation_storage::{
    FederatedShardPermit, FederatedStoragePermitMacKey, federated_provider_shard_identity,
    federated_shard_permit_mac, federated_shard_read_result_digest,
    federated_shard_reclamation_result_digest, federated_shard_retirement_result_digest,
    federated_shard_scrub_result_digest, federated_shard_write_result_digest,
    verify_federated_shard_permit_mac,
};
pub use filesystem::{
    namespace_reconciliation_result_digest, namespace_snapshot_restore_result_digest,
};
pub use observability::{EventSeverity, ObservabilityReceipt, ObservabilitySink, RedactedEvent};
pub use security::{
    AuthenticationAttempt, AuthenticationHandler, AuthenticationOutcome, CertificateChallenge,
    CertificateChallengeKind, CertificateChallengeReceipt, CertificateChallengeRequest,
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
    run_certificate_challenge_suite, run_coding_scheme_suite, run_consensus_engine_suite,
    run_metadata_repository_suite, run_observability_sink_suite, run_placement_policy_suite,
    run_storage_provider_suite,
};
