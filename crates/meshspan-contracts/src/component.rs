// SPDX-License-Identifier: GPL-2.0-only

//! Lifecycle shared by compiled replaceable component implementations.

use meshspan_domain::{LifecycleState, Revision, UnixMicros};

use crate::{BoundedBytes, ContractError, ImplementationDescriptor};

/// Canonical desired configuration committed by metadata authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentConfiguration {
    /// Schema version understood independently of the component contract version.
    pub schema_version: u32,
    /// Monotonic desired configuration revision.
    pub desired_revision: Revision,
    /// Canonical bounded configuration bytes.
    pub canonical_bytes: BoundedBytes,
}

/// Result of an idempotent lifecycle request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentTransition {
    /// Local preparation proved the desired revision can activate.
    Ready,
    /// The desired revision is already active.
    Active,
    /// Work remains before the transition can complete.
    Pending,
    /// Installed code cannot implement the requested contract or configuration.
    Unsupported,
    /// The deadline elapsed before a safe drain completed.
    TimedOut,
}

/// Bounded non-authoritative report of local observed component state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentObservation {
    /// Desired revision to which this observation responds.
    pub desired_revision: Revision,
    /// Locally observed lifecycle.
    pub lifecycle: LifecycleState,
    /// Authoritative instant supplied to the observation operation.
    pub observed_at: UnixMicros,
}

/// Common lifecycle required of every replaceable compiled implementation.
pub trait ComponentLifecycle {
    /// Describes the compiled implementation without consulting mutable state.
    fn describe(&self) -> ImplementationDescriptor;

    /// Validates canonical configuration without changing local state.
    ///
    /// # Errors
    ///
    /// Returns a stable contract error for unsupported or invalid configuration.
    fn validate_configuration(
        &self,
        configuration: &ComponentConfiguration,
    ) -> Result<(), ContractError>;

    /// Prepares an exact desired revision idempotently.
    ///
    /// # Errors
    ///
    /// Returns a stable error without partially activating invalid configuration.
    fn prepare(
        &mut self,
        configuration: &ComponentConfiguration,
    ) -> Result<ComponentTransition, ContractError>;

    /// Activates a previously prepared exact revision idempotently.
    ///
    /// # Errors
    ///
    /// Returns a stable error if preparation, revision or local binding is invalid.
    fn activate(
        &mut self,
        desired_revision: Revision,
    ) -> Result<ComponentTransition, ContractError>;

    /// Stops new assignments and drains until an authoritative deadline.
    ///
    /// # Errors
    ///
    /// Returns a stable failure without pretending an incomplete drain succeeded.
    fn drain(&mut self, deadline: UnixMicros) -> Result<ComponentTransition, ContractError>;

    /// Permanently retires an already safe component revision.
    ///
    /// # Errors
    ///
    /// Returns a stable error if active responsibility remains.
    fn retire(&mut self, desired_revision: Revision) -> Result<ComponentTransition, ContractError>;

    /// Returns the current bounded local observation.
    fn observe(&self, observed_at: UnixMicros) -> ComponentObservation;
}
