// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_contracts::{PlacementAssessment, PlacementAssessmentRequest};

#[test]
fn recorded_assessment_separates_decode_protection_and_locality_debt()
-> Result<(), Box<dyn std::error::Error>> {
    let (topology, mut candidates) = independent_targets(4)?;
    let cell_id = AvailabilityCellId::from_bytes([20; 16])?;
    for candidate in candidates.iter_mut().take(2) {
        candidate.availability_cells = BoundedItems::new(vec![cell_id], 256)?;
    }
    let cells = [PlacementCellRequirement {
        cell_id,
        role: PlacementCellRole::Eventual,
        complete_local: true,
        minimum_durable_targets: None,
        minimum_distinct_nodes: None,
        local_scenarios: BoundedItems::new(Vec::new(), 16)?,
    }];
    let scenarios = [FailureScenario::new(vec![FailureTerm {
        class_id: class(2)?,
        failure_count: 1,
    }])?];
    let targets = candidates
        .iter()
        .map(|candidate| candidate.target_id)
        .collect::<Vec<_>>();
    let placement = FaultAwarePlacement::new();
    let coding_layout = CodingLayout::new(2, 2, 100)?;
    let evaluate = |recorded_targets| {
        placement.assess_recorded(PlacementAssessmentRequest {
            coding_layout,
            recorded_targets,
            scenarios: &scenarios,
            topology: &topology,
            candidates: &candidates,
            cells: &cells,
        })
    };
    for (removed, expected) in [
        (0, (true, true, true)),
        (1, (true, true, false)),
        (2, (true, false, false)),
        (3, (false, false, false)),
        (4, (false, false, false)),
    ] {
        assert_eq!(
            evaluate(&targets[removed..])?,
            PlacementAssessment {
                sufficient_receipts: expected.0,
                protection_satisfied: expected.1,
                locality_satisfied: expected.2,
            }
        );
    }
    let duplicates = [targets[0], targets[0]];
    let unknown = [target(99)?];
    assert!(evaluate(&duplicates).is_err());
    assert!(evaluate(&unknown).is_err());
    let excluded = [PlacementCellRequirement {
        role: PlacementCellRole::Excluded,
        complete_local: false,
        ..cells[0].clone()
    }];
    let assessment = placement.assess_recorded(PlacementAssessmentRequest {
        coding_layout: CodingLayout::new(2, 2, 100)?,
        recorded_targets: &targets,
        scenarios: &scenarios,
        topology: &topology,
        candidates: &candidates,
        cells: &excluded,
    })?;
    assert!(assessment.protection_satisfied);
    assert!(!assessment.locality_satisfied);
    Ok(())
}
