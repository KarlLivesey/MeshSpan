// SPDX-License-Identifier: GPL-2.0-only

//! Ordered owner replies are correlated before a gateway may sign an external response.

use super::{federation_backup_relay_digest, response::result_matches};
use crate::TransportError;
use meshspan_domain::UnixMicros;
use meshspan_protocol::{
    ValidatedDataControlEnvelope, WireLimits, decode_federation_frame,
    v1::{
        FederatedBackupPermit, ForwardFederatedBackupRequest,
        data_control_envelope::Message as DataMessage, federation_envelope::Message,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Ready,
    Result,
    Complete,
}

/// Correlation and phase validation only: the caller must authenticate the exact owner via mTLS
/// and recheck current authority before forwarding any bytes or signing these payloads.
pub struct FederationBackupOwnerResponseExpectation {
    digest: [u8; 32],
    permit: FederatedBackupPermit,
    maximum_frame_bytes: u64,
    deadline: i64,
    phase: Phase,
}

impl FederationBackupOwnerResponseExpectation {
    /// Binds responses to the complete original request and this exact forwarding hop.
    ///
    /// # Errors
    /// Rejects malformed wrappers or anything other than signed backup execution.
    pub fn new(
        request: &ForwardFederatedBackupRequest,
        limits: WireLimits,
    ) -> Result<Self, TransportError> {
        let digest = federation_backup_relay_digest(request, limits)?;
        let decoded = decode_federation_frame(&request.request, limits)?;
        let Some(Message::ExecuteBackup(execution)) = &decoded.as_inner().message else {
            return Err(TransportError::InvalidConfiguration);
        };
        Ok(Self {
            digest,
            permit: execution
                .permit
                .clone()
                .ok_or(TransportError::InvalidConfiguration)?,
            maximum_frame_bytes: request.maximum_frame_bytes,
            deadline: request
                .header
                .as_ref()
                .ok_or(TransportError::InvalidConfiguration)?
                .deadline_unix_micros,
            phase: Phase::Ready,
        })
    }

    /// Validates the next unsigned owner payload and advances only after all checks succeed.
    ///
    /// # Errors
    /// Rejects wrong phase/request/permit/object/action/operation, excessive frame offers,
    /// future or expired receipts and any result after rejected admission or completion.
    pub fn accept(
        &mut self,
        envelope: &ValidatedDataControlEnvelope,
        now: UnixMicros,
    ) -> Result<Message, TransportError> {
        if now.get() >= self.deadline || now.get() < self.permit.issued_at_unix_micros {
            return Err(TransportError::StaleFederationMessage);
        }
        let (message, next) = match (self.phase, &envelope.as_inner().message) {
            (Phase::Ready, Some(DataMessage::ForwardFederatedBackupReady(value)))
                if value.request_digest == self.digest =>
            {
                let ready = value.ready.as_ref().ok_or(TransportError::UntrustedPeer)?;
                if ready.permit_digest != self.permit.permit_digest
                    || ready.maximum_frame_bytes > self.maximum_frame_bytes
                {
                    return Err(TransportError::UntrustedPeer);
                }
                let next = if ready.rejection.is_some() {
                    Phase::Complete
                } else {
                    Phase::Result
                };
                (Message::BackupReady(ready.clone()), next)
            }
            (Phase::Result, Some(DataMessage::ForwardFederatedBackupResult(value)))
                if value.request_digest == self.digest =>
            {
                let result = value.result.as_ref().ok_or(TransportError::UntrustedPeer)?;
                if result.permit_digest != self.permit.permit_digest
                    || result.completed_at_unix_micros < self.permit.issued_at_unix_micros
                    || result.completed_at_unix_micros > now.get()
                    || result.completed_at_unix_micros >= self.deadline
                    || !result_matches(&self.permit, result.outcome.as_ref())?
                {
                    return Err(TransportError::UntrustedPeer);
                }
                (Message::BackupResult(result.clone()), Phase::Complete)
            }
            _ => return Err(TransportError::UntrustedPeer),
        };
        self.phase = next;
        Ok(message)
    }
}
