// SPDX-License-Identifier: GPL-2.0-only

//! Read-only policy assessment; recorded locations are not evidence of current byte availability.

use meshspan_domain::{FailureScenario, TargetId, Topology};

use crate::{CodingLayout, PlacementCandidate, PlacementCellRequirement};

/// Bounded fixed-topology input for assessing the distinct slices with recorded receipts.
#[derive(Clone, Copy, Debug)]
pub struct PlacementAssessmentRequest<'a> {
    /// Original coding geometry, including slices whose receipts are missing.
    pub coding_layout: CodingLayout,
    /// One target per distinct receipted slice, at most the original total slice count.
    pub recorded_targets: &'a [TargetId],
    /// Current policy's independent failure scenarios.
    pub scenarios: &'a [FailureScenario],
    /// Exact topology used throughout this assessment.
    pub topology: &'a Topology,
    /// Target identity and cell membership at this same topology revision.
    pub candidates: &'a [PlacementCandidate],
    /// Required, eventual and excluded cell policies.
    pub cells: &'a [PlacementCellRequirement],
}

/// Mathematical assessment of recorded locations; never a live read or commit receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlacementAssessment {
    /// Whether at least the decode threshold has recorded receipts.
    pub sufficient_receipts: bool,
    /// Whether recorded slices survive every requested failure scenario.
    pub protection_satisfied: bool,
    /// Whether recorded slices satisfy every configured cell predicate, including exclusions.
    pub locality_satisfied: bool,
}
