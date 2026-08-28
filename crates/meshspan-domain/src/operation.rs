// SPDX-License-Identifier: GPL-2.0-only

//! Idempotent operation replay decisions.

use crate::{OperationId, Revision};

/// Exact durability scope proved when an ordinary filesystem branch is acknowledged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurabilityScope {
    /// Durable on one named node only.
    NodeLocal,
    /// Durable under the declared predicate within one availability cell.
    CellReplicated,
    /// Included in the authoritative converged namespace head.
    GloballyConverged,
}

/// Stable semantic outcome of a bounded domain operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// No matching mutation committed.
    Rejected,
    /// A filesystem mutation committed at the returned local durability scope.
    BranchCommitted(DurabilityScope),
    /// Every required acknowledgement predicate and converged-head transition committed.
    PolicyCommitted,
    /// A previously local branch is included in the converged head.
    GloballyConverged,
    /// Durable work exists but has not reached a terminal outcome.
    InProgress,
}

/// Durable identity and outcome evidence for an applied operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationReceipt {
    operation_id: OperationId,
    request_digest: [u8; 32],
    result_digest: [u8; 32],
    committed_revision: Revision,
}

impl OperationReceipt {
    /// Constructs a receipt from independently verified durable values.
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        request_digest: [u8; 32],
        result_digest: [u8; 32],
        committed_revision: Revision,
    ) -> Self {
        Self {
            operation_id,
            request_digest,
            result_digest,
            committed_revision,
        }
    }

    /// Returns the operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the exact canonical request digest.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Returns the exact committed result digest.
    #[must_use]
    pub const fn result_digest(&self) -> [u8; 32] {
        self.result_digest
    }

    /// Returns the authority revision that committed the result.
    #[must_use]
    pub const fn committed_revision(&self) -> Revision {
        self.committed_revision
    }
}

/// Decision made before any repeated mutation is executed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationDecision<'a> {
    /// No durable operation with this ID exists, so execution may begin.
    Execute,
    /// The exact request already committed and its stored result must be returned.
    Replay(&'a OperationReceipt),
    /// The ID already belongs to different canonical input and must be rejected.
    Conflict,
}

/// Classifies a request against the receipt already stored under its operation ID.
#[must_use]
pub fn classify_operation<'a>(
    existing: Option<&'a OperationReceipt>,
    request_digest: &[u8; 32],
) -> OperationDecision<'a> {
    match existing {
        None => OperationDecision::Execute,
        Some(receipt) if receipt.request_digest() == *request_digest => {
            OperationDecision::Replay(receipt)
        }
        Some(_) => OperationDecision::Conflict,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "the statically fixed non-nil identifier is part of the test fixture"
    )]

    use crate::{OperationDecision, OperationId, OperationReceipt, Revision, classify_operation};

    fn receipt() -> OperationReceipt {
        OperationReceipt::new(
            OperationId::from_bytes([1; 16]).expect("fixture ID is non-nil"),
            [2; 32],
            [3; 32],
            Revision::new(7),
        )
    }

    #[test]
    fn classifies_new_replay_and_conflict_without_guessing() {
        let receipt = receipt();
        assert_eq!(
            classify_operation(None, &[2; 32]),
            OperationDecision::Execute
        );
        assert_eq!(
            classify_operation(Some(&receipt), &[2; 32]),
            OperationDecision::Replay(&receipt)
        );
        assert_eq!(
            classify_operation(Some(&receipt), &[9; 32]),
            OperationDecision::Conflict
        );
    }
}
