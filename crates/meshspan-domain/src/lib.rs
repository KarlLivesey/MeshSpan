// SPDX-License-Identifier: GPL-2.0-only

//! Pure `MeshSpan` domain types, decisions and deterministic state transitions.

mod access;
mod federation;
mod federation_access;
mod federation_graph;
mod federation_storage;
mod lifecycle;
mod operation;
mod partitioning;
mod primitives;
mod routing;
mod seams;
mod topology;

pub use access::{
    AccessActivation, AccessActivationError, AccessActivationPolicy, AccessActivationRequest,
    AccessWindow, ActivationSubject, AssuranceLevel, GroupGraph, GroupGraphError, MembershipChange,
    OwnerSet, OwnerSetError, Rights, RightsError,
};
pub use federation::{
    DEFAULT_FEDERATION_OFFLINE_DURATION, FederatedPrincipal, FederationAccess, FederationPolicy,
    FederationPolicyError, FederationPreset, FederationResourceScope, NamespaceFederationPolicy,
    StorageFederationPolicy, StorageParticipation,
};
pub use federation_access::{
    FederatedMutationAdmission, FederatedMutationEvidence, FederationGrant, FederationGrantError,
    QuarantineReason, classify_federated_mutation,
};
pub use federation_graph::{FederationGraph, FederationGraphError, FederationRelationshipKind};
pub use federation_storage::{
    FederationStorageAction, FederationStorageActionError, FederationStorageAllocation,
    FederationStorageAllocationError,
};
pub use lifecycle::{LifecycleEvent, LifecycleState, LifecycleTransitionError};
pub use operation::{
    CommitOutcome, DurabilityScope, OperationDecision, OperationReceipt, classify_operation,
};
pub use partitioning::{
    DelegatedMetadataScope, DelegationAdmission, DelegationError, MetadataKeyRange,
    MetadataOperationFamily, RootDelegatedRoute,
};
pub use primitives::{
    ActivationId, ActivationPolicyId, AuditEventId, BackupId, BranchId, ComponentInstanceId,
    ContentManifestId, DurationMicros, FaultGroupClassId, FaultGroupId, FederationGrantId,
    FederationRelationshipId, FederationStorageAllocationId, FederationSuccessionId, FileVersionId,
    GrantId, GroupId, HandleId, HostId, IdentifierError, JoinGrantId, LockId, MeshId,
    NamespaceCommitId, NodeId, ObjectId, ObjectRevisionId, OperationId, OwnerSetId, PartitionId,
    PrincipalId, QuarantineId, QuorumPlanId, Revision, RevisionError, RoleId, ScopeId, SessionId,
    SnapshotId, SnapshotScheduleId, StageId, TagId, TargetId, UnixMicros, VolumeId,
};
pub use routing::{HandoffEvidence, RouteError, RouteState, ScopeRoute};
pub use seams::{Clock, EntropyError, RandomSource};
pub use topology::{
    FailureScenario, FailureTerm, FaultGroupMember, ProtectionError, ProtectionLayout,
    ProtectionProof, Topology, prove_protection,
};
