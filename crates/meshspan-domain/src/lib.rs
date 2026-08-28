// SPDX-License-Identifier: GPL-2.0-only

//! Pure `MeshSpan` domain types, decisions and deterministic state transitions.

mod access;
mod lifecycle;
mod operation;
mod primitives;
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
    ActivationId, ActivationPolicyId, AuditEventId, BackupId, ComponentInstanceId, DurationMicros,
    FaultGroupClassId, FaultGroupId, GrantId, GroupId, HostId, IdentifierError, MeshId, NodeId,
    ObjectId, OperationId, OwnerSetId, PartitionId, PrincipalId, QuorumPlanId, Revision,
    RevisionError, RoleId, TagId, TargetId, UnixMicros, VolumeId,
};
pub use seams::{Clock, EntropyError, RandomSource};
pub use topology::{
    FailureScenario, FailureTerm, FaultGroupMember, ProtectionError, ProtectionLayout,
    ProtectionProof, Topology, prove_protection,
};
