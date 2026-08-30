// SPDX-License-Identifier: GPL-2.0-only

//! Daemon process composition, configuration and local secret presentation.

mod claim_file;
mod claim_service;
#[cfg(test)]
mod claim_service_tests;
mod create_mesh_setup;
#[cfg(test)]
mod create_mesh_setup_tests;
mod setup_api;
#[cfg(test)]
mod setup_api_tests;

pub use claim_file::{ClaimFile, ClaimFileError};
pub use claim_service::{
    ClaimConsumptionOutcome, ClaimEnsureDisposition, ClaimEnsureOutcome, ClaimRotationOutcome,
    FirstBootClaimError, FirstBootClaimService,
};
pub use create_mesh_setup::{
    BootstrapAuthority, BootstrapAuthorityError, BootstrapCommit, CreateMeshSetupError,
    CreateMeshSetupService,
};
pub use setup_api::{
    CreateMeshSetupController, SetupApiError, SetupLifecycleError, SetupStateSnapshot,
    SetupStatusSource, setup_api_router, setup_api_router_with_creation,
};

use meshspan_domain::{EntropyError, RandomSource};

/// Operating-system cryptographic entropy used by daemon-owned secret material.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperatingSystemRandom;

impl RandomSource for OperatingSystemRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(destination).map_err(|_| EntropyError)
    }
}
