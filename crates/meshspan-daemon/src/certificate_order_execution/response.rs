// SPDX-License-Identifier: GPL-2.0-only

//! Validate external progress without admitting rejected state or disguising local failures.

use meshspan_acme::{AcmeMachineError, AcmeMachineEvent, AcmeOrderMachine, AcmeRetryAfter};
use meshspan_domain::UnixMicros;

use super::CertificateOrderExecutionError;

pub(super) fn advance(
    accepted: &AcmeOrderMachine,
    event: AcmeMachineEvent,
    received_at: UnixMicros,
    retry_after: Option<AcmeRetryAfter>,
) -> Result<AcmeOrderMachine, CertificateOrderExecutionError> {
    let from_ca = match &event {
        AcmeMachineEvent::DirectoryDiscovered(_)
        | AcmeMachineEvent::NonceAcquired(_)
        | AcmeMachineEvent::AccountCreated { .. }
        | AcmeMachineEvent::OrderCreated { .. }
        | AcmeMachineEvent::AuthorizationFetched { .. }
        | AcmeMachineEvent::ChallengeNotified { .. }
        | AcmeMachineEvent::AuthorizationPolled { .. }
        | AcmeMachineEvent::OrderFinalized { .. }
        | AcmeMachineEvent::OrderPolled { .. }
        | AcmeMachineEvent::CertificateDownloaded(_) => true,
        AcmeMachineEvent::ChallengePublished { .. } | AcmeMachineEvent::ChallengeCleaned => false,
    };
    let mut candidate = accepted.clone();
    candidate
        .advance_with_retry(event, received_at, retry_after)
        .map_err(|error| classify(error, from_ca, received_at, retry_after))?;
    Ok(candidate)
}

fn classify(
    error: AcmeMachineError,
    from_ca: bool,
    received_at: UnixMicros,
    retry_after: Option<AcmeRetryAfter>,
) -> CertificateOrderExecutionError {
    let remote_semantics = match error {
        AcmeMachineError::InvalidRemoteState
        | AcmeMachineError::NameMismatch
        | AcmeMachineError::UnsupportedChallenge
        | AcmeMachineError::RemoteRejected
        | AcmeMachineError::Protocol => true,
        AcmeMachineError::InvalidInput
        | AcmeMachineError::InvalidTransition
        | AcmeMachineError::CorruptState => false,
    };
    if from_ca && remote_semantics {
        CertificateOrderExecutionError::RejectedResponse {
            reason: error,
            retry_not_before: retry_after.and_then(|hint| hint.not_before(received_at)),
        }
    } else {
        CertificateOrderExecutionError::Machine(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_remote_semantic_failures_become_rejected_responses() {
        for (reason, remote_semantics) in [
            (AcmeMachineError::InvalidRemoteState, true),
            (AcmeMachineError::NameMismatch, true),
            (AcmeMachineError::UnsupportedChallenge, true),
            (AcmeMachineError::RemoteRejected, true),
            (AcmeMachineError::Protocol, true),
            (AcmeMachineError::InvalidInput, false),
            (AcmeMachineError::InvalidTransition, false),
            (AcmeMachineError::CorruptState, false),
        ] {
            for from_ca in [false, true] {
                let result = classify(reason, from_ca, UnixMicros::new(20_000_000), None);
                if from_ca && remote_semantics {
                    assert!(
                        matches!(result, CertificateOrderExecutionError::RejectedResponse {
                        reason: rejected, retry_not_before: None
                    } if rejected == reason)
                    );
                } else {
                    assert!(
                        matches!(result, CertificateOrderExecutionError::Machine(local)
                        if local == reason)
                    );
                }
            }
        }
    }
}
