// SPDX-License-Identifier: GPL-2.0-only

//! Reuses placement's fault and cell predicates without searching for destinations.

use meshspan_contracts::{
    ContractError, PlacementAssessment, PlacementAssessmentRequest, PlacementCellRole,
};
use meshspan_domain::ProtectionLayout;
use std::collections::BTreeSet;

pub(super) fn assess(
    request: PlacementAssessmentRequest<'_>,
) -> Result<PlacementAssessment, ContractError> {
    validate(&request)?;
    let sufficient_receipts =
        request.recorded_targets.len() >= usize::from(request.coding_layout.data_slices());
    let mut protection_satisfied = sufficient_receipts;
    if sufficient_receipts {
        let layout = ProtectionLayout::new(
            request.coding_layout.data_slices(),
            request.recorded_targets.to_vec(),
        )
        .map_err(|_| ContractError::InvalidInput)?;
        for scenario in request.scenarios {
            protection_satisfied &=
                super::best_effort_proof(request.topology, scenario, &layout)?.survives;
        }
    }
    let excluded = request
        .cells
        .iter()
        .filter(|cell| cell.role == PlacementCellRole::Excluded)
        .any(|cell| {
            request.candidates.iter().any(|candidate| {
                request.recorded_targets.contains(&candidate.target_id)
                    && candidate
                        .availability_cells
                        .as_slice()
                        .contains(&cell.cell_id)
            })
        });
    let locality_satisfied = !excluded
        && super::cell_constraints_satisfied(
            request.topology,
            request.candidates,
            request.recorded_targets,
            request.cells,
            true,
            request.coding_layout.data_slices(),
        )?;
    Ok(PlacementAssessment {
        sufficient_receipts,
        protection_satisfied,
        locality_satisfied,
    })
}

fn validate(request: &PlacementAssessmentRequest<'_>) -> Result<(), ContractError> {
    if request.recorded_targets.len() > usize::from(request.coding_layout.total_slices())
        || request.scenarios.len() > super::MAXIMUM_SCENARIOS
        || request.candidates.len() > super::MAXIMUM_CANDIDATES
        || request.cells.len() > super::MAXIMUM_CELLS
        || request
            .cells
            .iter()
            .any(|cell| cell.local_scenarios.len() > super::MAXIMUM_SCENARIOS)
    {
        return Err(ContractError::InvalidInput);
    }
    super::validate_cells(request.cells)?;
    let mut candidates = BTreeSet::new();
    if request.candidates.iter().any(|candidate| {
        !candidates.insert(candidate.target_id)
            || candidate.target_generation == 0
            || candidate.availability_cells.len() > super::MAXIMUM_CELLS
            || request.topology.target_host(candidate.target_id) != Some(candidate.host_id)
    }) {
        return Err(ContractError::InvalidInput);
    }
    let mut selected = BTreeSet::new();
    if request
        .recorded_targets
        .iter()
        .any(|target| !selected.insert(*target) || !candidates.contains(target))
    {
        return Err(ContractError::InvalidInput);
    }
    Ok(())
}
