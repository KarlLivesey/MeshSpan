// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic owned consensus building blocks with mechanically proved quorum plans.

mod core;
mod quorum;

pub use core::{
    AppendRequest, AppendResponse, ConsensusCore, CoreConfig, CoreEffect, CoreError, CoreInput,
    CoreMessage, DurableMutation, LogEntry, LogPosition, MemberIncarnations, PersistenceId,
    ProposalId, Role, VoteRequest, VoteResponse,
};

pub use quorum::{
    CompiledQuorumPlan, FamilyProof, JointTransitionProof, QuorumFamily, QuorumPlanError,
    QuorumPlanSpec, QuorumPredicate, VoterSet, WeightedVoter, compile_plan, flat_plan,
    prove_joint_transition,
};
