// SPDX-License-Identifier: GPL-2.0-only

//! Versioned capability boundaries and reusable deterministic conformance harnesses.

mod common;
mod component;
mod conformance;

pub use common::{
    BoundedBytes, BoundedBytesError, ContractError, ContractKind, ContractLimits, ContractVersion,
    ImplementationDescriptor, RequestContext,
};
pub use component::{
    ComponentConfiguration, ComponentLifecycle, ComponentObservation, ComponentTransition,
};
pub use conformance::{
    CaseFailureKind, ConformanceCase, ConformanceFailure, HarnessError, run_conformance_cases,
    verify_descriptor,
};
