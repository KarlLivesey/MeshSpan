// SPDX-License-Identifier: GPL-2.0-only

//! Publication identity survives worker replacement; an old missing lifetime stays explicit.

use serde::{Deserialize, Serialize};

use super::{AcmeMachineError, AcmeOrderMachine, Phase};
use crate::AcmeChallengePublication;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PublicationState {
    #[default]
    Unprepared,
    Legacy {
        order_epoch: u64,
    },
    Retained {
        publication: AcmeChallengePublication,
    },
}

impl AcmeOrderMachine {
    /// Returns the selected publication inputs without changing the current protocol phase.
    ///
    /// A caller may use them to capture immutable material or restore a lost local catalogue;
    /// cleanup must never use this projection to republish an already validated challenge.
    ///
    /// # Errors
    ///
    /// Rejects an incomplete selected challenge in an active challenge phase.
    pub fn publication_action(&self) -> Result<Option<crate::AcmeMachineAction>, AcmeMachineError> {
        if !self.has_challenge_phase() {
            return Ok(None);
        }
        let authorization = self
            .authorization
            .as_ref()
            .ok_or(AcmeMachineError::CorruptState)?;
        Ok(Some(crate::AcmeMachineAction::PublishChallenge {
            dns_name: authorization.dns_name.clone(),
            wildcard: authorization.wildcard,
            challenge: self
                .challenge
                .clone()
                .ok_or(AcmeMachineError::CorruptState)?,
            order_epoch: self.publication_epoch().unwrap_or(self.order_epoch),
        }))
    }

    /// Returns the original publisher receipt digest, never a visibility or worker-authority grant.
    #[must_use]
    pub const fn publication_digest(&self) -> Option<[u8; 32]> {
        self.publication_digest
    }

    /// Returns the immutable material already retained for the selected challenge.
    #[must_use]
    pub fn publication(&self) -> Option<&AcmeChallengePublication> {
        match &self.publication {
            PublicationState::Retained { publication } => Some(publication),
            PublicationState::Legacy { .. } | PublicationState::Unprepared => None,
        }
    }

    /// Returns the original publication epoch, including for a legacy checkpoint without expiry.
    #[must_use]
    pub fn publication_epoch(&self) -> Option<u64> {
        match &self.publication {
            PublicationState::Retained { publication } => Some(publication.order_epoch()),
            PublicationState::Legacy { order_epoch } => Some(*order_epoch),
            PublicationState::Unprepared => None,
        }
    }

    /// Retains exact publication inputs before publisher IO, or after verifying legacy evidence.
    ///
    /// A repeated exact binding is a no-op. A caller recovering legacy material must first verify
    /// its expected receipt against the retained digest; this method grants no worker authority.
    ///
    /// # Errors
    ///
    /// Rejects changed identity/lifetime, unrelated material and phases with no selected challenge.
    pub fn retain_publication(
        &mut self,
        publication: AcmeChallengePublication,
    ) -> Result<(), AcmeMachineError> {
        self.validate_publication_material(&publication)?;
        if publication.order_epoch() != self.publication_epoch().unwrap_or(self.order_epoch)
            || self
                .publication()
                .is_some_and(|stored| stored != &publication)
        {
            return Err(AcmeMachineError::InvalidInput);
        }
        self.publication = PublicationState::Retained { publication };
        Ok(())
    }

    pub(super) fn validate_publication(&self) -> Result<(), AcmeMachineError> {
        match &self.publication {
            PublicationState::Unprepared
                if !self.has_challenge_phase() || self.phase == Phase::PublishChallenge =>
            {
                Ok(())
            }
            PublicationState::Legacy { order_epoch }
                if *order_epoch > 0 && self.has_challenge_phase() =>
            {
                Ok(())
            }
            PublicationState::Unprepared | PublicationState::Legacy { .. } => {
                Err(AcmeMachineError::CorruptState)
            }
            PublicationState::Retained { publication } => {
                self.validate_publication_material(publication)
            }
        }
    }

    fn validate_publication_material(
        &self,
        publication: &AcmeChallengePublication,
    ) -> Result<(), AcmeMachineError> {
        let authorization = self
            .authorization
            .as_ref()
            .ok_or(AcmeMachineError::CorruptState)?;
        let challenge = self
            .challenge
            .as_ref()
            .ok_or(AcmeMachineError::CorruptState)?;
        if !self.has_challenge_phase()
            || !publication.matches_challenge(
                &authorization.dns_name,
                authorization.wildcard,
                challenge,
            )
        {
            return Err(AcmeMachineError::InvalidInput);
        }
        Ok(())
    }

    pub(super) const fn has_challenge_phase(&self) -> bool {
        matches!(
            self.phase,
            Phase::PublishChallenge
                | Phase::NotifyChallenge
                | Phase::PollAuthorization
                | Phase::CleanupChallenge
        )
    }
}
