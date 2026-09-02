// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable coding-scheme and placement-policy contracts.

use thiserror::Error;

use meshspan_domain::{
    FailureScenario, ProtectionLayout, ProtectionProof, Revision, TargetId, Topology,
};

use crate::{
    BoundedBytes, BoundedItems, ComponentLifecycle, ContractError, RequestContext, VersionedPayload,
};

const MAX_SLICES: u16 = 24;

/// Recorded systematic coding geometry for one stripe generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodingLayout {
    /// Number of verified slices required to reconstruct.
    data_slices: u16,
    /// Number of additional recoverable slice losses.
    recovery_slices: u16,
    /// Exact bytes in each full slice before final-stripe shortening.
    slice_bytes: u32,
}

impl CodingLayout {
    /// Constructs a supported non-empty geometry.
    ///
    /// # Errors
    ///
    /// Rejects zero data/slice size, overflow or more than 24 total slices.
    pub const fn new(
        data_slices: u16,
        recovery_slices: u16,
        slice_bytes: u32,
    ) -> Result<Self, CodingLayoutError> {
        let Some(total_slices) = data_slices.checked_add(recovery_slices) else {
            return Err(CodingLayoutError::InvalidGeometry);
        };
        if data_slices == 0 || slice_bytes == 0 || total_slices > MAX_SLICES {
            Err(CodingLayoutError::InvalidGeometry)
        } else {
            Ok(Self {
                data_slices,
                recovery_slices,
                slice_bytes,
            })
        }
    }

    /// Returns the number of verified slices required to reconstruct.
    #[must_use]
    pub const fn data_slices(self) -> u16 {
        self.data_slices
    }

    /// Returns the number of additional recoverable slice losses.
    #[must_use]
    pub const fn recovery_slices(self) -> u16 {
        self.recovery_slices
    }

    /// Returns the bytes in each full slice before final-stripe shortening.
    #[must_use]
    pub const fn slice_bytes(self) -> u32 {
        self.slice_bytes
    }

    /// Returns the exact total slice count.
    #[must_use]
    pub const fn total_slices(self) -> u16 {
        self.data_slices + self.recovery_slices
    }
}

/// Rejection of invalid coding geometry.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CodingLayoutError {
    /// Geometry is empty, overflows or exceeds the recorded format limit.
    #[error("coding geometry is invalid")]
    InvalidGeometry,
}

/// Complete bounded reconstruction input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconstructionRequest {
    /// Operation/deadline context.
    pub context: RequestContext,
    /// Exact recorded geometry.
    pub layout: CodingLayout,
    /// Indexed optional slices; absent entries are reconstructed.
    pub available_slices: BoundedItems<Option<BoundedBytes>>,
    /// Expected BLAKE3 digest for every indexed slice before decoding.
    pub slice_digests: BoundedItems<[u8; 32]>,
    /// Exact unpadded logical bytes represented by the stripe.
    pub logical_length: u64,
    /// Expected BLAKE3 digest of the exact unpadded logical bytes.
    pub logical_digest: [u8; 32],
}

/// Deterministic systematic transformation independent of storage placement.
pub trait CodingScheme: ComponentLifecycle {
    /// Encodes one bounded logical stripe into exactly the recorded indexed slices.
    ///
    /// # Errors
    ///
    /// Rejects unsupported layouts, excessive input or outgoing length inconsistency.
    fn encode(
        &self,
        context: RequestContext,
        layout: CodingLayout,
        logical_bytes: &BoundedBytes,
    ) -> Result<BoundedItems<BoundedBytes>, ContractError>;

    /// Reconstructs and verifies logical bytes from any sufficient valid slice subset.
    ///
    /// # Errors
    ///
    /// Rejects wrong counts, lengths, corruption, insufficient slices or excessive output.
    fn reconstruct(&self, request: &ReconstructionRequest) -> Result<BoundedBytes, ContractError>;
}

/// Revision-bound placement decision with exact proof evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacementPlan {
    /// Automatically selected systematic coding geometry.
    pub coding_layout: CodingLayout,
    /// Target selected for every indexed slice.
    pub slice_targets: BoundedItems<TargetId>,
    /// Topology revision used for eligibility and failure proof.
    pub topology_revision: Revision,
    /// Capacity observation revision used for admission.
    pub capacity_revision: Revision,
    /// Exact proofs in the same order as the requested alternative scenarios.
    pub protection_proofs: BoundedItems<ProtectionProof>,
    /// Independently versioned acknowledgement/locality evidence.
    pub policy_evidence: VersionedPayload,
}

/// One fixed-revision target candidate admitted to placement planning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlacementCandidate {
    /// Stable target identity.
    pub target_id: TargetId,
    /// Positive current target generation.
    pub target_generation: u64,
    /// Bytes available to this write after authoritative reserves and limits.
    pub writable_bytes: u64,
    /// Relative performance preference; independence remains a hard constraint.
    pub performance_weight: u16,
}

/// Complete fixed-revision input to one placement decision.
#[derive(Clone, Copy, Debug)]
pub struct PlacementRequest<'a> {
    /// Operation/deadline context.
    pub context: RequestContext,
    /// Exact logical bytes in this bounded stripe before padding.
    pub logical_stripe_bytes: u32,
    /// Alternative failure scenarios that every returned plan must survive independently.
    pub scenarios: &'a [FailureScenario],
    /// Fixed topology snapshot.
    pub topology: &'a Topology,
    /// Revision of the fixed topology snapshot.
    pub topology_revision: Revision,
    /// Revision of the fixed capacity observations.
    pub capacity_revision: Revision,
    /// Bounded target capacity and performance evidence at `capacity_revision`.
    pub candidates: &'a [PlacementCandidate],
}

/// Fault-aware target selection without shard IO or namespace authority.
pub trait PlacementPolicy: ComponentLifecycle {
    /// Selects targets and proves the requested scenario at fixed revisions.
    ///
    /// # Errors
    ///
    /// Returns explicit infeasibility, stale evidence or bounded-capacity failure.
    fn plan_write(&self, request: PlacementRequest<'_>) -> Result<PlacementPlan, ContractError>;

    /// Re-evaluates an existing placement against one exact topology snapshot.
    ///
    /// # Errors
    ///
    /// Rejects unknown targets, excessive scenarios or inconsistent layouts.
    fn evaluate(
        &self,
        scenario: &FailureScenario,
        layout: &ProtectionLayout,
        topology: &Topology,
    ) -> Result<ProtectionProof, ContractError>;
}

#[cfg(test)]
mod tests {
    use super::{CodingLayout, CodingLayoutError};

    #[test]
    fn coding_layout_rejects_empty_overflow_and_excessive_geometry() {
        assert_eq!(
            CodingLayout::new(0, 1, 1),
            Err(CodingLayoutError::InvalidGeometry)
        );
        assert_eq!(
            CodingLayout::new(16, 9, 1),
            Err(CodingLayoutError::InvalidGeometry)
        );
        assert_eq!(
            CodingLayout::new(10, 4, 1_048_576),
            Ok(CodingLayout {
                data_slices: 10,
                recovery_slices: 4,
                slice_bytes: 1_048_576,
            })
        );
    }
}
