// SPDX-License-Identifier: GPL-2.0-only

//! Checkpoint-before-publication and exact catalogue restoration, independent of CA progress.

use meshspan_acme::{
    AcmeChallengeExecution, AcmeMachineAction, AcmeMachineEvent, AcmeOrderMachine, AcmeStepOutcome,
    AcmeTransport,
};
use meshspan_contracts::{CertificateChallenge, RequestContext};
use meshspan_domain::{Clock, UnixMicros};

use super::{
    CertificateOrderExecution, CertificateOrderExecutionError, CertificateOrderStepResult,
};

impl<T: AcmeTransport, C: CertificateChallenge> CertificateOrderExecution<T, C> {
    pub(super) fn prepare_publication(
        &self,
        context: RequestContext,
        challenge_expires_at: UnixMicros,
    ) -> Result<Option<AcmeOrderMachine>, CertificateOrderExecutionError> {
        if self.machine.publication().is_some() {
            return Ok(None);
        }
        let Some(action) = self.machine.publication_action()? else {
            return Ok(None);
        };
        let challenge_expires_at = self
            .assignment
            .checkpoint
            .as_ref()
            .filter(|_| self.machine.publication_epoch().is_some())
            .and_then(|checkpoint| checkpoint.legacy_lease_expiry_candidate)
            .unwrap_or(challenge_expires_at);
        let publication = self.executor.prepare_publication(
            &action,
            AcmeChallengeExecution {
                context,
                challenge_expires_at,
                publication: None,
                csr_der: &self.csr_der,
            },
        )?;
        if let Some(digest) = self.machine.publication_digest() {
            // A legacy lifetime is only a candidate. Never guess it after a worker handoff.
            self.executor
                .verify_publication_receipt(&publication, context, digest)?;
        }
        let mut candidate = self.machine.clone();
        candidate.retain_publication(publication)?;
        Ok(Some(candidate))
    }

    pub(super) fn needs_publication_restore(&self) -> Result<bool, CertificateOrderExecutionError> {
        Ok(!self.publication_visible
            && matches!(
                self.machine.action()?,
                AcmeMachineAction::NotifyChallenge { .. }
                    | AcmeMachineAction::PollAuthorization { .. }
            ))
    }

    pub(super) async fn restore_publication(
        &mut self,
        clock: &impl Clock,
        context: RequestContext,
        challenge_expires_at: UnixMicros,
    ) -> Result<CertificateOrderStepResult, CertificateOrderExecutionError> {
        let now = clock.now();
        let publication = self
            .machine
            .publication()
            .ok_or(CertificateOrderExecutionError::InvalidInput)?;
        let digest = self
            .machine
            .publication_digest()
            .ok_or(CertificateOrderExecutionError::InvalidInput)?;
        self.executor
            .verify_publication_receipt(publication, context, digest)?;
        let action = self
            .machine
            .publication_action()?
            .ok_or(CertificateOrderExecutionError::InvalidInput)?;
        let remaining = context
            .deadline
            .get()
            .checked_sub(now.get())
            .filter(|_| now.get() >= 0)
            .and_then(|remaining| u64::try_from(remaining).ok())
            .filter(|remaining| *remaining > 0)
            .ok_or(CertificateOrderExecutionError::DeadlineElapsed)?;
        let outcome = tokio::time::timeout(
            std::time::Duration::from_micros(remaining),
            self.executor.execute(
                &action,
                AcmeChallengeExecution {
                    context,
                    challenge_expires_at,
                    publication: Some(publication),
                    csr_der: &self.csr_der,
                },
            ),
        )
        .await
        .map_err(|_| CertificateOrderExecutionError::DeadlineElapsed)??;
        let received_at = clock.now();
        if received_at < now || received_at >= context.deadline {
            return Err(CertificateOrderExecutionError::DeadlineElapsed);
        }
        match outcome {
            AcmeStepOutcome::Pending => {}
            AcmeStepOutcome::Advanced(AcmeMachineEvent::ChallengePublished {
                publication_digest,
            }) if publication_digest == digest => {
                self.publication_visible = true;
            }
            _ => return Err(CertificateOrderExecutionError::InvalidInput),
        }
        // Restoring visibility never rewinds the phase, changes its polling deadline or notifies
        // the CA. The next driver pass resumes the exact retained protocol action.
        Ok(CertificateOrderStepResult::Pending)
    }
}
