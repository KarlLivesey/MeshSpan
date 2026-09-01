// SPDX-License-Identifier: GPL-2.0-only

//! Runtime composition boundary for deterministic consensus, metadata persistence and QUIC.

mod access_administration;
mod cleanup;
mod cleanup_network;
mod cleanup_worker;
mod consensus_network;
mod convergence;
mod driver;
mod federation_authority;
mod federation_authority_exchange;
mod federation_authority_page_source;
mod federation_authority_receiver;
mod federation_authority_sync;
mod federation_body_exchange;
mod federation_branch_authority;
mod federation_branch_exchange;
mod federation_branch_page_source;
mod federation_content_healing;
mod federation_content_layout_exchange;
mod federation_content_layout_source;
mod federation_content_layout_wire;
mod federation_content_shard_exchange;
mod federation_content_shard_source;
mod federation_filesystem_content;
mod federation_filesystem_history;
mod federation_grant_authority;
mod federation_history_admission;
mod federation_history_object_exchange;
mod federation_history_object_source;
mod federation_history_receiver;
mod federation_history_sync;
mod federation_mutation_acceptance;
mod federation_mutation_admission;
mod federation_mutation_relay;
mod federation_resource_wire;
mod federation_session;
mod federation_shard_authority;
mod federation_storage_capability;
mod federation_storage_exchange;
mod federation_storage_inventory_exchange;
mod federation_storage_inventory_wire;
mod filesystem_authority;
mod filesystem_convergence;
mod membership;
mod metadata_authority;
mod node_runtime;
mod retention;
mod status;
mod wire;

#[cfg(test)]
mod access_administration_tests;
#[cfg(test)]
mod convergence_tests;
#[cfg(test)]
mod federation_mutation_relay_tests;
#[cfg(test)]
mod filesystem_convergence_tests;
#[cfg(test)]
mod handoff_tests;
#[cfg(test)]
mod protected_volume_test_support;

pub use access_administration::{
    AccessAdministrationAuthority, AccessAdministrationError, AuthorisedAccessPage,
    MetadataAccessAdministration,
};
pub use cleanup::{
    CleanupAttestationError, CleanupCancellationAuthorityError, CleanupCompletionError,
    CleanupPermitError, CleanupReclamationError, CleanupRetirementAuthorityError,
    version_cleanup_attestation, version_cleanup_cancellation_authority, version_cleanup_proposal,
    version_cleanup_reclamation, version_cleanup_removal_permit,
    version_cleanup_retirement_authority, version_cleanup_tombstone_completion,
};
pub use cleanup_network::{
    CleanupConnectionSource, CleanupNetworkContext, CleanupNetworkError,
    MAXIMUM_CLEANUP_REQUEST_TIMEOUT, dispatch_cleanup_work_over_quic,
    execute_cleanup_work_over_quic,
};
pub use cleanup_worker::{
    CleanupProviderDispatch, CleanupWorkAction, CleanupWorkCatalogue, CleanupWorkEntry,
    CleanupWorkPage, CleanupWorkerError, CleanupWorkerOutcome, MAXIMUM_CLEANUP_WORK_PAGE_ITEMS,
    execute_cleanup_work,
};

#[cfg(test)]
mod cleanup_worker_tests;
pub use consensus_network::{
    ConsensusNetwork, ConsensusNetworkConfig, ConsensusNetworkError, ConsensusPeerConfig,
    OutboundConsensusSnapshot, PeerControlRequest, PeerDataStream, ReceivedConsensusSnapshot,
};
pub use convergence::{reconciliation_head_command, snapshot_restore_head_command};
pub use driver::{
    AppliedAuthoritativeCommand, ClusterDriverError, DriverEffect, PartitionConsensusDriver,
    ScopedProposal,
};
pub use federation_authority::{
    FederationAuthorityError, FederationConnectionAuthority, federation_connection_authority,
};
pub use federation_authority_exchange::{
    FederationAuthorityFetchRequest, FederationAuthorityPageServeRequest,
    ServedFederationAuthorityPage,
};
pub use federation_authority_page_source::{
    FederationAuthorityPageQuery, FederationAuthorityPageRecords, FederationAuthorityPageSource,
    FederationAuthorityPageSourceError,
};
pub use federation_authority_receiver::{
    FederationAuthorityImportError, FederationAuthorityImportLimits, FederationAuthorityUpdate,
    FederationRemoteAuthoritySnapshotReceiver,
};
pub use federation_authority_sync::{
    FederationAuthoritySyncError, FederationAuthoritySyncOutcome, FederationAuthoritySyncRequest,
};
pub use federation_branch_authority::{
    FederationBranchAuthoritySource, MetadataFederationBranchAuthority,
};
pub use federation_branch_exchange::{
    FederationBranchFetchRequest, FederationBranchPageServeRequest, FederationBranchPageServices,
    ServedFederationBranchPage,
};
pub use federation_branch_page_source::{
    FederationBranchPageFuture, FederationBranchPageQuery, FederationBranchPageRecords,
    FederationBranchPageSource, FederationBranchPageSourceError,
};
pub use federation_content_healing::{
    FederationContentHealingError, FederationContentHealingRequest, HealedFederationContentShard,
    heal_federated_content_shard,
};
pub use federation_content_layout_exchange::{
    FederationContentLayoutFetchRequest, FederationContentLayoutFetchServices,
    FederationContentLayoutServeRequest, FederationContentLayoutServices,
    ReceivedFederationContentLayoutPage, ServedFederationContentLayoutPage,
};
pub use federation_content_layout_source::{
    FederationContentLayoutFuture, FederationContentLayoutQuery, FederationContentLayoutRecords,
    FederationContentLayoutSource, FederationContentLayoutSourceError,
    FederationContentRouteSource, FederationContentShardRoute,
};
pub use federation_content_layout_wire::{
    FederationContentLayoutWireError, decode_federated_content_layout_chunk,
    decode_federated_content_layout_header, version_federated_content_layout_chunk,
    version_federated_content_layout_header,
};
pub use federation_content_shard_exchange::{
    FederationContentShardFetchRequest, FederationContentShardFetchServices,
    FederationContentShardServeRequest, FederationContentShardServices,
    ReceivedFederationContentShard, ServedFederationContentShard,
};
pub use federation_content_shard_source::{
    FederationContentShard, FederationContentShardFuture, FederationContentShardQuery,
    FederationContentShardSource, FederationContentShardSourceError,
};
pub use federation_filesystem_content::{
    FederationContentShardProviderBinding, FilesystemFederationContentShardSource,
    FilesystemFederationContentSource,
};
pub use federation_filesystem_history::FilesystemFederationHistorySource;
pub use federation_grant_authority::{
    EffectiveFederationGrantAuthority, EffectiveFederationGrantAuthorityError,
    effective_federation_grant_authority,
};
pub use federation_history_admission::{
    ConsensusFederationMutationAdmissionCommitter, FederationAuthoritativeCommandOutcome,
    FederationAuthoritativeCommandResolveFuture, FederationAuthoritativeCommandSubmission,
    FederationAuthoritativeCommandSubmitError, FederationAuthoritativeCommandSubmitFuture,
    FederationAuthoritativeCommandSubmitter, FederationHistoryAdmissionBatch,
    FederationHistoryAdmissionError, FederationHistoryAdmissionFuture,
    FederationHistoryAdmissionSource, FederationMutationAdmissionCommit,
    FederationMutationAdmissionCommitError, FederationMutationAdmissionCommitFuture,
    FederationMutationAdmissionCommitter, MetadataFederationHistoryAdmissionSource,
};
pub use federation_history_object_exchange::{
    FederationHistoryObjectFetchRequest, FederationHistoryObjectServeRequest,
    FederationHistoryObjectServices, ServedFederationHistoryObject,
};
pub use federation_history_object_source::{
    FederationHistoryObject, FederationHistoryObjectFuture, FederationHistoryObjectQuery,
    FederationHistoryObjectSource, FederationHistoryObjectSourceError,
};
pub use federation_history_receiver::{
    AdmittingFederationHistoryReceiver, FederationHistoryReceiveError,
    FederationHistoryReceiveFuture, FederationHistoryReceiver,
};
pub use federation_history_sync::{
    FederationHistorySyncError, FederationHistorySyncOutcome, FederationHistorySyncRequest,
};
pub use federation_mutation_acceptance::{
    AdmittedFederationMutation, FederationMutationAcceptanceAuthority,
    FederationMutationAcceptanceError, FederationMutationAcceptanceRequest,
    FederationMutationAcceptor, MetadataFederationMutationAcceptanceAuthority,
    MetadataFederationMutationAcceptanceError,
};
pub use federation_mutation_admission::{
    FederatedHistoryMutationAdmission, FederatedHistoryMutationAdmissionError,
    classify_federated_history_mutation,
};
pub use federation_mutation_relay::{
    FederationMutationRelayError, relay_federated_history_mutation,
};
pub use federation_resource_wire::{
    FederationResourceWireError, version_federation_resource_scope,
};
pub use federation_session::{
    FederationAcceptRequest, FederationAuthoritySource, FederationDialRequest,
    FederationSessionError, FederationSessionRuntime,
};
pub use federation_shard_authority::MetadataFederatedShardAuthority;
pub use federation_storage_capability::{
    FederationStorageCapabilityIssueRequest, FederationStorageCapabilityIssuer,
    FederationStorageCapabilityIssuerError, IssuedFederationStorageCapability,
};
pub use federation_storage_exchange::{
    FederationShardServeRequest, FederationStorageCapabilityProvider,
    FederationStorageCapabilityRequest, FederationStorageCapabilityServeRequest,
    FederationStorageReceiptReceiveRequest, ServedFederatedShard,
    ServedFederationStorageCapability,
};
pub use federation_storage_inventory_exchange::{
    FederationStorageInventoryExchangeError, FederationStorageInventoryFetchRequest,
    FederationStorageInventoryProvider, FederationStorageInventoryServeRequest,
    ReceivedFederationStorageInventoryPage, ServedFederationStorageInventoryPage,
};
pub use federation_storage_inventory_wire::{
    FederationStorageInventoryWireError, decode_federated_storage_inventory_record,
    version_federated_storage_inventory_record,
};
pub use filesystem_authority::{MetadataFilesystemAuthority, MetadataFilesystemAuthorityError};
pub use filesystem_convergence::{
    FilesystemConvergenceError, FilesystemConvergenceService, PreparedHistoryReconciliation,
};
pub use membership::{MembershipRestoreError, restore_member_incarnations};
pub use meshspan_metadata::FederationRemoteAuthoritySnapshot;
pub use metadata_authority::{
    ConsensusMessageTransport, MetadataAuthorityConfig, MetadataAuthorityHandle,
    MetadataAuthorityRequestError, MetadataAuthorityRuntimeError, MetadataAuthorityStartError,
    PeerConsensusMessage, spawn_metadata_authority,
};
pub use node_runtime::{NodeRuntimeError, run_stage_three_node};
pub use retention::version_retention_selection_policy;
pub use status::{
    AvailabilityError, AvailabilityReason, AvailabilityState, NodePresence, PartitionAvailability,
    PartitionStatusInput, PresenceError, PresenceRegistry, PresenceRole, PresenceUpdate,
    evaluate_partition_availability,
};
pub use wire::{ConsensusWireError, decode_consensus_message, encode_consensus_message};
