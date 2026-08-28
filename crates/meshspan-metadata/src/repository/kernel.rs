// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable typed metadata-kernel boundary and reusable exact conformance proof.

use meshspan_domain::{OperationId, Revision};

use super::{
    ApplyDisposition, CommandReceipt, InvariantReport, LogPosition, PageLimit, RepositoryError,
};
use crate::{AuthoritativeCommand, CommandContext};

/// Engine-neutral typed boundary required of an authoritative metadata implementation.
pub trait AuthoritativeMetadataKernel {
    /// Returns the exact current state revision.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable or malformed persisted state.
    fn current_revision(&self) -> Result<Revision, RepositoryError>;

    /// Atomically applies one already-committed typed command.
    ///
    /// # Errors
    ///
    /// Rejects gaps, stale input, conflicting replay, failed authority or invariant violations.
    fn apply_committed(
        &mut self,
        position: LogPosition,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, RepositoryError>;

    /// Resolves an exact durable operation result.
    ///
    /// # Errors
    ///
    /// Fails closed rather than interpreting malformed stored bytes.
    fn resolve_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CommandReceipt>, RepositoryError>;

    /// Runs a bounded set of cross-row invariant checks.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds, unavailable storage and corrupt values.
    fn check_invariants(&self, limit: PageLimit) -> Result<InvariantReport, RepositoryError>;
}

/// Exact bootstrap/replay/conflict inputs shared by every metadata engine.
pub struct RepositoryConformanceVector<'a> {
    /// First committed position.
    pub initial_position: LogPosition,
    /// Second position used to replay the exact same operation.
    pub replay_position: LogPosition,
    /// Third position used to prove conflicting operation reuse fails closed.
    pub conflict_position: LogPosition,
    /// Complete deterministic command context.
    pub context: CommandContext,
    /// Initial and replayed command.
    pub command: &'a AuthoritativeCommand,
    /// Different semantic command using the same operation identity.
    pub conflicting_command: &'a AuthoritativeCommand,
}

/// One failed reusable metadata-kernel behaviour check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryConformanceCheck {
    /// Fresh implementations disagreed on an exact receipt.
    DeterministicReceipt,
    /// Replay did not return the exact original result/revision.
    ExactReplay,
    /// Conflicting operation reuse did not fail closed.
    ConflictingReplay,
    /// A fresh completed vector violated a domain invariant.
    CleanInvariants,
}

/// Bounded reusable behavioural results for one metadata implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryConformanceReport {
    /// Empty only when every exact check passed.
    pub failures: Vec<RepositoryConformanceCheck>,
}

struct OneRun {
    receipt: CommandReceipt,
    replay_exact: bool,
    conflict_closed: bool,
    invariant_clean: bool,
}

/// Runs the same exact vector against two fresh metadata implementations.
///
/// # Errors
///
/// Returns the implementation's stable repository error for setup, apply, resolution or checking
/// failures. Semantic mismatches are returned as false report fields rather than hidden.
pub fn run_repository_conformance<Factory, Kernel>(
    vector: &RepositoryConformanceVector<'_>,
    mut factory: Factory,
) -> Result<RepositoryConformanceReport, RepositoryError>
where
    Factory: FnMut() -> Result<Kernel, RepositoryError>,
    Kernel: AuthoritativeMetadataKernel,
{
    let first = run_one(vector, factory()?)?;
    let second = run_one(vector, factory()?)?;
    let mut failures = Vec::new();
    if first.receipt != second.receipt {
        failures.push(RepositoryConformanceCheck::DeterministicReceipt);
    }
    if !first.replay_exact || !second.replay_exact {
        failures.push(RepositoryConformanceCheck::ExactReplay);
    }
    if !first.conflict_closed || !second.conflict_closed {
        failures.push(RepositoryConformanceCheck::ConflictingReplay);
    }
    if !first.invariant_clean || !second.invariant_clean {
        failures.push(RepositoryConformanceCheck::CleanInvariants);
    }
    Ok(RepositoryConformanceReport { failures })
}

fn run_one<Kernel>(
    vector: &RepositoryConformanceVector<'_>,
    mut kernel: Kernel,
) -> Result<OneRun, RepositoryError>
where
    Kernel: AuthoritativeMetadataKernel,
{
    let applied =
        kernel.apply_committed(vector.initial_position, vector.context, vector.command)?;
    let resolved = kernel
        .resolve_operation(vector.context.operation_id)?
        .ok_or(RepositoryError::CorruptState)?;
    let replay = kernel.apply_committed(vector.replay_position, vector.context, vector.command)?;
    let replay_exact = applied.disposition == ApplyDisposition::Applied
        && resolved.disposition == ApplyDisposition::Replayed
        && replay.disposition == ApplyDisposition::Replayed
        && applied.result_digest == resolved.result_digest
        && applied.result_digest == replay.result_digest
        && applied.committed_revision == replay.committed_revision
        && kernel.current_revision()? == applied.committed_revision;
    let conflict_closed = matches!(
        kernel.apply_committed(
            vector.conflict_position,
            vector.context,
            vector.conflicting_command
        ),
        Err(RepositoryError::OperationConflict)
    );
    let invariant_clean = kernel
        .check_invariants(PageLimit::new(100)?)?
        .findings
        .is_empty();
    Ok(OneRun {
        receipt: applied,
        replay_exact,
        conflict_closed,
        invariant_clean,
    })
}
