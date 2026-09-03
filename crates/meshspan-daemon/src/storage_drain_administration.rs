// SPDX-License-Identifier: GPL-2.0-only

//! Manager-only admission and visibility for safe storage removal.

mod api;
mod contract;
mod model;
#[cfg(test)]
mod model_tests;
mod service;

pub use api::{StorageDrainAdministrationApiError, storage_drain_administration_api_router};
pub use contract::{StorageDrainAdministrationAuthority, StorageDrainAdministrationAuthorityError};
pub use service::{
    StorageDrainAdministrationController, StorageDrainAdministrationError,
    StorageDrainAdministrationService,
};
