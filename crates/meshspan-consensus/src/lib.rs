// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic owned consensus building blocks with mechanically proved quorum plans.

mod core;
mod membership;
mod quorum;

pub use membership::{
    CatchUpEvidence, JointQuorumPlan, MembershipChangeError, PlannedPromotion,
    plan_next_flat_promotion, recommended_voter_count,
};

pub use core::{
    AppendRequest, AppendResponse, ConsensusCore, CoreConfig, CoreEffect, CoreError, CoreInput,
    CoreMessage, DurableCoreState, DurableMutation, LogEntry, LogPosition, MemberIncarnations,
    PersistenceId, ProposalId, ReadBarrierId, Role, VoteRequest, VoteResponse,
};

pub use quorum::{
    CompiledQuorumPlan, FamilyProof, JointTransitionProof, QuorumFamily, QuorumPlanError,
    QuorumPlanSpec, QuorumPredicate, VoterSet, WeightedVoter, compile_plan, flat_plan,
    prove_joint_transition,
};
