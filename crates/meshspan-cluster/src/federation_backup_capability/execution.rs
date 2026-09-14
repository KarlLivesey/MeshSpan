// SPDX-License-Identifier: GPL-2.0-only

//! Signed backup execution on a blocking provider worker, with bounded QUIC byte adapters.

mod bytes;
mod conversation;
use conversation::Conversation;

pub use conversation::FederationBackupOwnerService;

use super::{FederationBackupCapabilityError, FederationBackupCapabilityService};
use meshspan_contracts::{
    BackupProvider, ContractError, FederatedBackupPermit, FederatedBackupRequest,
};
use meshspan_data_plane::{
    encode_backup_delete_receipt, encode_backup_object_receipt, encode_backup_read_receipt,
    encode_backup_rejection,
};
use meshspan_domain::Clock;
use meshspan_protocol::{
    WireLimits,
    v1::{
        FederatedBackupReady, FederatedBackupResult, federated_backup_result::Outcome,
        federation_envelope::Message,
    },
};
use meshspan_transport::{
    AcceptedStream, AuthenticatedFederationBackupRequest, StreamKind, TransportError,
};
use sha2::{Digest, Sha256};
use std::{future::Future, io::Cursor, time::Duration};

/// Runtime inputs for one owned blocking-worker conversation; never invoke on an async executor.
pub struct FederationBackupStreamContext<'a> {
    /// Runtime used only to await deadline-bounded network IO from the blocking worker.
    pub runtime: &'a tokio::runtime::Handle,
    /// Current trusted mesh time, re-read at authority boundaries.
    pub clock: &'a dyn Clock,
    /// Negotiated frame limits, independent of total object length.
    pub limits: WireLimits,
    /// Fresh signed ready-message nonce.
    pub ready_nonce: [u8; 32],
    /// Distinct fresh signed result-message nonce.
    pub result_nonce: [u8; 32],
}

/// Shared bounded IO environment for owner-node backup execution on a blocking worker.
#[derive(Clone, Copy)]
pub struct FederationBackupOwnerStreamContext<'a> {
    /// Runtime used for deadline-bounded QUIC IO, never from an executor worker.
    pub runtime: &'a tokio::runtime::Handle,
    /// Trusted mesh clock, checked again during every operation.
    pub clock: &'a dyn Clock,
    /// Negotiated control and data framing limits.
    pub limits: WireLimits,
}

impl FederationBackupCapabilityService<'_, '_> {
    /// Executes one already authenticated request using an exact scope-bound backup provider.
    ///
    /// The daemon must call from its bounded blocking worker, retain exclusive provider ownership,
    /// and route the provider to the admitted allocation/target/destination. Store readiness is sent
    /// only after the provider asks for bytes (following capacity admission), or after an exact
    /// already-stored replay. All bytes stay encrypted. No same-swarm node authority is invented.
    ///
    /// # Errors
    /// Rejects expired/revoked authority, invalid nonces, unexpected stream class, malformed bytes,
    /// IO failure or mismatched provider receipts. Lost responses never imply rollback.
    pub fn execute_stream(
        &self,
        authenticated: &AuthenticatedFederationBackupRequest,
        provider: &mut dyn BackupProvider,
        stream: AcceptedStream,
        context: &FederationBackupStreamContext<'_>,
    ) -> Result<(), FederationBackupCapabilityError> {
        if stream.kind != StreamKind::Federation || context.ready_nonce == context.result_nonce {
            return Err(ContractError::InvalidInput.into());
        }
        // Validate both response contexts before provider IO, including zero/reflected nonces.
        authenticated.response_context(context.ready_nonce)?;
        authenticated.response_context(context.result_nonce)?;
        execute(
            Conversation::Direct {
                service: self,
                authenticated,
                ready_nonce: context.ready_nonce,
                result_nonce: context.result_nonce,
            },
            provider,
            stream,
            FederationBackupOwnerStreamContext {
                runtime: context.runtime,
                clock: context.clock,
                limits: context.limits,
            },
        )
    }
}

fn execute(
    conversation: Conversation<'_, '_>,
    provider: &mut dyn BackupProvider,
    mut stream: AcceptedStream,
    context: FederationBackupOwnerStreamContext<'_>,
) -> Result<(), FederationBackupCapabilityError> {
    let admitted = conversation.authorise(context.clock.now())?;
    let expires = conversation.deadline(admitted.permit().expires_at);
    let remaining = expires
        .get()
        .checked_sub(context.clock.now().get())
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(ContractError::DeadlineExceeded)?;
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_micros(remaining))
        .ok_or(ContractError::InvalidInput)?;
    let mut transfer = Transfer {
        conversation,
        permit: admitted.permit().clone(),
        context,
        stream: &mut stream,
        deadline,
        ready: false,
        offset: 0,
        digest: Sha256::new(),
        pending: Cursor::new(Vec::new()),
        finished: false,
    };
    let outcome = transfer.execute(provider);
    transfer.complete(outcome)
}

struct Transfer<'a, 'identity> {
    conversation: Conversation<'a, 'identity>,
    permit: FederatedBackupPermit,
    context: FederationBackupOwnerStreamContext<'a>,
    stream: &'a mut AcceptedStream,
    deadline: tokio::time::Instant,
    ready: bool,
    offset: u64,
    digest: Sha256,
    pending: Cursor<Vec<u8>>,
    finished: bool,
}

impl Transfer<'_, '_> {
    fn execute(&mut self, provider: &mut dyn BackupProvider) -> Result<Outcome, ContractError> {
        let now = self.context.clock.now();
        let request = self.permit.request.clone();
        match request {
            FederatedBackupRequest::Lookup(request) => {
                self.ready(None).map_err(|_| ContractError::Unavailable)?;
                let receipt = provider.lookup_exact(&request, now)?;
                if receipt.operation_id != request.context.operation_id
                    || receipt.object != request.object
                {
                    return Err(ContractError::InternalContract);
                }
                Ok(Outcome::LookedUp(encode_backup_object_receipt(&receipt)))
            }
            FederatedBackupRequest::Store(request) => {
                let receipt = provider.store_exact(request, self, now)?;
                // Providers may return an exact replay without reading its source. Still verify
                // this stream before its result; do not leave unread bytes for another operation.
                std::io::copy(self, &mut std::io::sink())
                    .map_err(|_| ContractError::InvalidInput)?;
                if receipt.operation_id != request.context.operation_id
                    || receipt.object != request.object
                {
                    return Err(ContractError::InternalContract);
                }
                Ok(Outcome::Stored(encode_backup_object_receipt(&receipt)))
            }
            FederatedBackupRequest::Read(request) => {
                self.ready(None).map_err(|_| ContractError::Unavailable)?;
                let receipt = provider.read_exact(&request, self, now)?;
                self.verify_measurement()?;
                if receipt.operation_id != request.context.operation_id
                    || receipt.byte_length != request.object.byte_length
                    || receipt.digest != request.object.digest
                {
                    return Err(ContractError::InternalContract);
                }
                Ok(Outcome::Read(encode_backup_read_receipt(receipt)))
            }
            FederatedBackupRequest::Verify(request) => {
                self.ready(None).map_err(|_| ContractError::Unavailable)?;
                let receipt = provider.verify_exact(&request, now)?;
                if receipt.operation_id != request.context.operation_id
                    || receipt.object != request.object
                    || receipt.object_reference != request.object_reference
                {
                    return Err(ContractError::InternalContract);
                }
                Ok(Outcome::Verified(encode_backup_object_receipt(&receipt)))
            }
            FederatedBackupRequest::Delete(request) => {
                self.ready(None).map_err(|_| ContractError::Unavailable)?;
                self.check().map_err(|_| ContractError::Unauthorized)?;
                let receipt = provider.delete_exact(&request, now)?;
                if receipt.operation_id != request.context.operation_id
                    || receipt.object != request.object
                    || receipt.retirement_revision != request.retirement_revision
                {
                    return Err(ContractError::InternalContract);
                }
                Ok(Outcome::Deleted(encode_backup_delete_receipt(receipt)))
            }
        }
    }

    fn complete(
        &mut self,
        outcome: Result<Outcome, ContractError>,
    ) -> Result<(), FederationBackupCapabilityError> {
        self.check()?;
        if !self.ready {
            // A rejected admission has not consumed caller bytes and must not invite an upload.
            self.ready(outcome.as_ref().err().copied())?;
            if outcome.is_err() {
                self.stream.send.finish().map_err(TransportError::from)?;
                return Ok(());
            }
        }
        let outcome =
            outcome.unwrap_or_else(|error| Outcome::Rejection(encode_backup_rejection(error)));
        self.send(Message::BackupResult(FederatedBackupResult {
            permit_digest: self.permit.permit_digest.to_vec(),
            completed_at_unix_micros: self.context.clock.now().get(),
            signature: Vec::new(),
            outcome: Some(outcome),
        }))?;
        self.stream.send.finish().map_err(TransportError::from)?;
        Ok(())
    }

    fn ready(
        &mut self,
        rejection: Option<ContractError>,
    ) -> Result<(), FederationBackupCapabilityError> {
        if self.ready {
            return Ok(());
        }
        self.check()?;
        self.send(Message::BackupReady(FederatedBackupReady {
            permit_digest: self.permit.permit_digest.to_vec(),
            maximum_frame_bytes: if rejection.is_none() {
                self.context.limits.maximum_data_frame_bytes() as u64
            } else {
                0
            },
            rejection: rejection.map(encode_backup_rejection),
            signature: Vec::new(),
        }))?;
        self.ready = true;
        Ok(())
    }

    fn send(&mut self, message: Message) -> Result<(), FederationBackupCapabilityError> {
        wait(
            self.context.runtime,
            self.deadline,
            self.conversation.send(
                &mut self.stream.send,
                message,
                self.context.limits,
                self.context.clock.now(),
            ),
        )?;
        Ok(())
    }

    fn check(&self) -> Result<(), FederationBackupCapabilityError> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(ContractError::DeadlineExceeded.into());
        }
        self.conversation.authorise(self.context.clock.now())?;
        Ok(())
    }

    fn verify_measurement(&self) -> Result<(), ContractError> {
        let actual: [u8; 32] = self.digest.clone().finalize().into();
        if self.offset != self.permit.request.object().byte_length
            || actual != self.permit.request.object().digest
        {
            return Err(ContractError::Corrupt);
        }
        Ok(())
    }
}

fn wait<T>(
    runtime: &tokio::runtime::Handle,
    deadline: tokio::time::Instant,
    future: impl Future<Output = Result<T, TransportError>>,
) -> Result<T, FederationBackupCapabilityError> {
    runtime.block_on(async {
        tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| ContractError::DeadlineExceeded)?
            .map_err(Into::into)
    })
}
