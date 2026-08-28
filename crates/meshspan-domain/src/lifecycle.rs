// SPDX-License-Identifier: GPL-2.0-only

//! Shared guarded lifecycle used by replaceable resources.

use thiserror::Error;

/// Durable lifecycle of an admitted resource or component instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    /// The resource is recorded but not serving work.
    Registered,
    /// The resource is eligible to serve work.
    Active,
    /// New assignments are stopped while existing responsibility is removed.
    Draining,
    /// The resource is permanently fenced from new work.
    Retired,
}

/// Requested lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleEvent {
    /// Admit a registered resource to active service.
    Activate,
    /// Stop new assignments and begin a guarded drain.
    BeginDrain,
    /// Cancel a drain before irreversible retirement.
    CancelDrain,
    /// Permanently retire a fully drained resource.
    Retire,
}

impl LifecycleState {
    /// Applies one event without skipping a required safety phase.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleTransitionError`] when the event is invalid for the current state.
    pub const fn transition(self, event: LifecycleEvent) -> Result<Self, LifecycleTransitionError> {
        match (self, event) {
            (Self::Registered, LifecycleEvent::Activate)
            | (Self::Draining, LifecycleEvent::CancelDrain) => Ok(Self::Active),
            (Self::Active, LifecycleEvent::BeginDrain) => Ok(Self::Draining),
            (Self::Registered | Self::Draining, LifecycleEvent::Retire) => Ok(Self::Retired),
            _ => Err(LifecycleTransitionError { event, state: self }),
        }
    }
}

/// Rejection of an unsafe or meaningless lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("event {event:?} is invalid while lifecycle is {state:?}")]
pub struct LifecycleTransitionError {
    event: LifecycleEvent,
    state: LifecycleState,
}

#[cfg(test)]
mod tests {
    use super::{LifecycleEvent, LifecycleState};

    #[test]
    fn transition_table_accepts_only_guarded_paths() {
        let cases = [
            (LifecycleState::Registered, LifecycleEvent::Activate, true),
            (LifecycleState::Registered, LifecycleEvent::Retire, true),
            (LifecycleState::Active, LifecycleEvent::BeginDrain, true),
            (LifecycleState::Draining, LifecycleEvent::CancelDrain, true),
            (LifecycleState::Draining, LifecycleEvent::Retire, true),
            (
                LifecycleState::Registered,
                LifecycleEvent::BeginDrain,
                false,
            ),
            (LifecycleState::Active, LifecycleEvent::Activate, false),
            (LifecycleState::Active, LifecycleEvent::Retire, false),
            (LifecycleState::Retired, LifecycleEvent::Activate, false),
        ];

        for (state, event, accepted) in cases {
            assert_eq!(
                state.transition(event).is_ok(),
                accepted,
                "{state:?} {event:?}"
            );
        }
    }
}
