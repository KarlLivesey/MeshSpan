// SPDX-License-Identifier: GPL-2.0-only

//! Durable CA-directed polling deadlines, independent of worker lease ownership.

use meshspan_domain::UnixMicros;

use super::{AcmeMachineError, AcmeMachineEvent, AcmeOrderMachine, Phase};
use crate::AcmeRetryAfter;

impl AcmeOrderMachine {
    /// Returns the retained earliest execution instant, unchanged by worker handoff.
    #[must_use]
    pub fn poll_not_before(&self) -> Option<UnixMicros> {
        self.poll_not_before.map(UnixMicros::new)
    }

    /// Advances a validated response and retains its guidance only if polling remains necessary.
    ///
    /// Relative hints use response receipt time. Zero/past hints impose no extra delay;
    /// successful validation or issuance proceeds to cleanup/download immediately.
    /// Callers must commit the resulting checkpoint before another external action.
    ///
    /// # Errors
    ///
    /// Rejects negative receipt time and the same invalid transitions as `advance`.
    pub fn advance_with_retry(
        &mut self,
        event: AcmeMachineEvent,
        received_at: UnixMicros,
        retry_after: Option<AcmeRetryAfter>,
    ) -> Result<(), AcmeMachineError> {
        if received_at.get() < 0 {
            return Err(AcmeMachineError::InvalidInput);
        }
        self.advance(event)?;
        if matches!(self.phase, Phase::PollAuthorization | Phase::PollOrder) {
            self.poll_not_before = retry_after
                .and_then(|hint| hint.not_before(received_at))
                .map(UnixMicros::get);
        } else if self.retirement_reason().is_some() {
            self.poll_not_before = self.poll_not_before.max(
                retry_after
                    .and_then(|hint| hint.not_before(received_at))
                    .map(UnixMicros::get),
            );
        }
        Ok(())
    }

    pub(super) fn validate_poll_schedule(&self) -> Result<(), AcmeMachineError> {
        if self.poll_not_before.is_some_and(|instant| {
            instant <= 0
                || !matches!(
                    self.phase,
                    Phase::PollAuthorization
                        | Phase::PollOrder
                        | Phase::PublishChallenge
                        | Phase::RetireChallenge(_)
                        | Phase::Retired(_)
                )
        }) {
            // A replacement fence can require republication before polling; it must not
            // erase the retained CA deadline merely by changing the next action.
            return Err(AcmeMachineError::CorruptState);
        }
        Ok(())
    }
}
