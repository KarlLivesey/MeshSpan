// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{
    ComponentConfiguration, ComponentObservation, ComponentTransition, ContractError,
};
use meshspan_domain::{LifecycleState, Revision, UnixMicros};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Lifecycle {
    state: LifecycleState,
    prepared: Option<Revision>,
    active_revision: Revision,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            state: LifecycleState::Active,
            prepared: None,
            active_revision: Revision::ZERO,
        }
    }
}

impl Lifecycle {
    pub(crate) fn require_active(self) -> Result<(), ContractError> {
        if self.state == LifecycleState::Active {
            Ok(())
        } else {
            Err(ContractError::Unavailable)
        }
    }

    pub(crate) fn validate(configuration: &ComponentConfiguration) -> Result<(), ContractError> {
        if configuration.schema_version == 1
            && configuration.desired_revision != Revision::ZERO
            && configuration.canonical_bytes.is_empty()
        {
            Ok(())
        } else {
            Err(ContractError::InvalidInput)
        }
    }

    pub(crate) fn prepare(
        &mut self,
        configuration: &ComponentConfiguration,
    ) -> Result<ComponentTransition, ContractError> {
        Self::validate(configuration)?;
        if configuration.desired_revision == self.active_revision {
            return Ok(ComponentTransition::Active);
        }
        self.prepared = Some(configuration.desired_revision);
        Ok(ComponentTransition::Ready)
    }

    pub(crate) fn activate(
        &mut self,
        revision: Revision,
    ) -> Result<ComponentTransition, ContractError> {
        if self.prepared != Some(revision) {
            return Err(ContractError::Stale);
        }
        self.active_revision = revision;
        self.prepared = None;
        self.state = LifecycleState::Active;
        Ok(ComponentTransition::Active)
    }

    pub(crate) fn drain(&mut self) -> ComponentTransition {
        self.state = LifecycleState::Draining;
        ComponentTransition::Ready
    }

    pub(crate) fn retire(
        &mut self,
        revision: Revision,
    ) -> Result<ComponentTransition, ContractError> {
        if revision != self.active_revision || self.state != LifecycleState::Draining {
            return Err(ContractError::Stale);
        }
        self.state = LifecycleState::Retired;
        Ok(ComponentTransition::Active)
    }

    pub(crate) fn observe(self, now: UnixMicros) -> ComponentObservation {
        ComponentObservation {
            desired_revision: self.active_revision,
            lifecycle: self.state,
            observed_at: now,
        }
    }
}
