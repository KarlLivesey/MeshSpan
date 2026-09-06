// SPDX-License-Identifier: GPL-2.0-only

//! Exact cleanup precedes durable retirement; publication expiry is not a CA validity claim.

use meshspan_domain::UnixMicros;
use serde::{Deserialize, Serialize};

use super::{AcmeMachineError, AcmeOrderMachine, Phase};

/// Why an existing protocol attempt cannot continue normally.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcmeOrderRetirementReason {
    /// The retained publication budget ended, independently of CA validity.
    PublicationExpired,
    /// The CA returned a terminally rejected authorisation.
    AuthorizationRejected,
    /// The CA returned an invalid order.
    OrderRejected,
}

impl AcmeOrderMachine {
    /// Returns the retirement reason during cleanup and after cleanup completes.
    #[must_use]
    pub const fn retirement_reason(&self) -> Option<AcmeOrderRetirementReason> {
        match self.phase {
            Phase::RetireChallenge(reason) | Phase::Retired(reason) => Some(reason),
            Phase::DiscoverDirectory
            | Phase::AcquireNonce
            | Phase::CreateAccount
            | Phase::CreateOrder
            | Phase::FetchAuthorization
            | Phase::PublishChallenge
            | Phase::NotifyChallenge
            | Phase::PollAuthorization
            | Phase::CleanupChallenge
            | Phase::FinalizeOrder
            | Phase::PollOrder
            | Phase::DownloadCertificate
            | Phase::Complete => None,
        }
    }

    /// Begins exact cleanup when an unfinished publication reaches its exclusive deadline.
    ///
    /// The caller must derive `receipt_digest` from the retained material through the selected
    /// provider's pure expected-receipt operation. No IO or successful publication is implied.
    /// A valid authorisation already in cleanup continues normal completion instead.
    ///
    /// # Errors
    ///
    /// Rejects negative time, missing publication material and substituted receipt identity.
    pub fn expire_publication(
        &mut self,
        now: UnixMicros,
        receipt_digest: [u8; 32],
    ) -> Result<bool, AcmeMachineError> {
        if now.get() < 0 || receipt_digest == [0; 32] {
            return Err(AcmeMachineError::InvalidInput);
        }
        if !matches!(
            self.phase,
            Phase::PublishChallenge | Phase::NotifyChallenge | Phase::PollAuthorization
        ) {
            return Ok(false);
        }
        let publication = self.publication().ok_or(AcmeMachineError::InvalidInput)?;
        if publication.expires_at() > now {
            return Ok(false);
        }
        if self
            .publication_digest
            .is_some_and(|stored| stored != receipt_digest)
        {
            return Err(AcmeMachineError::InvalidInput);
        }
        self.publication_digest = Some(receipt_digest);
        self.begin_retirement(AcmeOrderRetirementReason::PublicationExpired);
        Ok(true)
    }

    pub(super) fn begin_retirement(&mut self, reason: AcmeOrderRetirementReason) {
        if self.publication_digest.is_some() {
            self.phase = Phase::RetireChallenge(reason);
        } else {
            self.clear_challenge();
            self.phase = Phase::Retired(reason);
        }
    }
}
