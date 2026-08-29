// SPDX-License-Identifier: GPL-2.0-only

//! Recovery-succession repository facade.

pub(super) use super::federation_succession_evidence::active_for_retiring;
pub use super::federation_succession_evidence::{
    FederationSuccessionRecord, FederationSuccessionState,
};
pub(super) use super::federation_succession_transition::{execute, is_command};
