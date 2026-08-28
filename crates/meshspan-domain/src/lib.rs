// SPDX-License-Identifier: GPL-2.0-only

//! Pure `MeshSpan` domain types, decisions and deterministic state transitions.

mod lifecycle;
mod operation;
mod primitives;
mod seams;

pub use lifecycle::{LifecycleEvent, LifecycleState, LifecycleTransitionError};
pub use operation::{OperationDecision, OperationReceipt, classify_operation};
pub use primitives::{
    DurationMicros, FaultGroupClassId, FaultGroupId, GrantId, GroupId, HostId, IdentifierError,
    MeshId, NodeId, ObjectId, OperationId, PartitionId, PrincipalId, Revision, RevisionError,
    TargetId, UnixMicros, VolumeId,
};
pub use seams::{Clock, EntropyError, RandomSource};
