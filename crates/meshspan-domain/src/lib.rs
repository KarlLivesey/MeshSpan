// SPDX-License-Identifier: GPL-2.0-only

//! Pure `MeshSpan` domain types, decisions and deterministic state transitions.

mod access;
mod lifecycle;
mod operation;
mod primitives;
mod routing;
mod seams;
mod topology;

pub use access::{
    AccessActivation, AccessActivationError, AccessActivationPolicy, AccessActivationRequest,
    AccessWindow, ActivationSubject, AssuranceLevel, GroupGraph, GroupGraphError, MembershipChange,
    OwnerSet, OwnerSetError, Rights, RightsError,
};
pub use lifecycle::{LifecycleEvent, LifecycleState, LifecycleTransitionError};
pub use operation::{
    CommitOutcome, DurabilityScope, OperationDecision, OperationReceipt, classify_operation,
};
pub use primitives::{
    ActivationId, ActivationPolicyId, AuditEventId, BackupId, BranchId, ComponentInstanceId,
    ContentManifestId, DurationMicros, FaultGroupClassId, FaultGroupId, FileVersionId, GrantId,
    GroupId, HandleId, HostId, IdentifierError, JoinGrantId, MeshId, NamespaceCommitId, NodeId,
    ObjectId, ObjectRevisionId, OperationId, OwnerSetId, PartitionId, PrincipalId, QuorumPlanId,
    Revision, RevisionError, RoleId, ScopeId, SnapshotId, StageId, TagId, TargetId, UnixMicros,
    VolumeId,
};
pub use routing::{HandoffEvidence, RouteError, RouteState, ScopeRoute};
pub use seams::{Clock, EntropyError, RandomSource};
pub use topology::{
    FailureScenario, FailureTerm, FaultGroupMember, ProtectionError, ProtectionLayout,
    ProtectionProof, Topology, prove_protection,
};
