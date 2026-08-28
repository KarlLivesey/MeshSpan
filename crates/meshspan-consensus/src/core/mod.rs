// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic leader-based replicated-log state machine with explicit durable effects.

mod state;
mod types;

#[cfg(test)]
mod tests;

pub use state::ConsensusCore;
pub use types::{
    AppendRequest, AppendResponse, CoreConfig, CoreEffect, CoreError, CoreInput, CoreMessage,
    DurableMutation, LogEntry, LogPosition, MemberIncarnations, PersistenceId, ProposalId, Role,
    VoteRequest, VoteResponse,
};
