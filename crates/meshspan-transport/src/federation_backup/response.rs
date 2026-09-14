// SPDX-License-Identifier: GPL-2.0-only

//! Exact response correlation and ordered ready/result transitions for backup exchanges.

use meshspan_domain::UnixMicros;
use meshspan_protocol::v1::{
    FederatedBackupOperation, FederatedBackupPermit, FederationHeader, RemoteBackupAction,
    federated_backup_result::Outcome, federation_envelope::Message,
};
use meshspan_protocol::{ValidatedFederationEnvelope, federation_backup_request_digest_payload};
use sha2::{Digest, Sha256};

#[cfg(test)]
#[path = "response_tests.rs"]
mod tests;

use super::{OutboundFederationBackupMessage, validate_time, verify_signature};
use crate::federation_storage_capability::verify_correlated_response_header;
use crate::{
    FederationExchangeContext, FederationLocalIdentityBinding, FederationPeerRegistry,
    FederationReplayGuard, TransportError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    AllocationPage,
    Capability,
    Ready,
    Result,
}

/// Immutable request and conversation phase which a provider response must match exactly.
#[derive(Clone, Debug, PartialEq)]
pub struct FederationBackupResponseExpectation {
    identity: FederationLocalIdentityBinding,
    context: FederationExchangeContext,
    request: Message,
    phase: Phase,
}

/// Signed response verified against the current TLS peer and exact pending conversation.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedFederationBackupResponse {
    message: Message,
    expected: FederationBackupResponseExpectation,
}

impl AuthenticatedFederationBackupResponse {
    /// Exact provider response, including any authenticated rejection.
    #[must_use]
    pub const fn message(&self) -> &Message {
        &self.message
    }

    /// Advances successful execution admission to the sole permitted result phase.
    ///
    /// # Errors
    /// Rejects capability responses, completed results and rejected admission. Callers cannot
    /// accept a result before receiving an authenticated ready message.
    pub fn result_expectation(
        &self,
    ) -> Result<FederationBackupResponseExpectation, TransportError> {
        if !matches!(&self.message, Message::BackupReady(value) if value.rejection.is_none())
            || self.expected.phase != Phase::Ready
        {
            return Err(TransportError::InvalidConfiguration);
        }
        Ok(FederationBackupResponseExpectation {
            phase: Phase::Result,
            ..self.expected.clone()
        })
    }
}

pub(super) fn expectation(
    outbound: &OutboundFederationBackupMessage,
) -> Result<FederationBackupResponseExpectation, TransportError> {
    let request = outbound
        .envelope
        .message
        .as_ref()
        .ok_or(TransportError::InvalidConfiguration)?;
    let phase = match request {
        Message::FetchBackupAllocations(_) => Phase::AllocationPage,
        Message::RequestBackupCapability(_) => Phase::Capability,
        Message::ExecuteBackup(_) => Phase::Ready,
        _ => return Err(TransportError::InvalidConfiguration),
    };
    Ok(FederationBackupResponseExpectation {
        identity: outbound.identity,
        context: outbound.context,
        request: request.clone(),
        phase,
    })
}

impl FederationPeerRegistry {
    /// Authenticates exactly the next response phase, without trusting the provider's claims.
    ///
    /// # Errors
    /// Rejects wrong phase/correlation, altered object/action/authority, stale identity, future
    /// receipts, invalid signatures and repeated nonces. Records replay only after all checks.
    pub fn authenticate_backup_response(
        &self,
        connection: &quinn::Connection,
        envelope: &ValidatedFederationEnvelope,
        expected: &FederationBackupResponseExpectation,
        now: UnixMicros,
        replay: &mut FederationReplayGuard,
    ) -> Result<AuthenticatedFederationBackupResponse, TransportError> {
        let (binding, _) = self.connection_binding(connection, now)?;
        let envelope = envelope.as_inner();
        let header = envelope
            .header
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        let message = envelope
            .message
            .as_ref()
            .ok_or(TransportError::UntrustedFederationPeer)?;
        verify_correlated_response_header(binding, header, expected.identity, expected.context)?;
        if header.deadline_unix_micros > binding.valid_until.get() {
            return Err(TransportError::UntrustedFederationPeer);
        }
        validate_time(message, now)?;
        verify_response(message, header, expected)?;
        replay.check(binding.relationship_id, header, now)?;
        verify_signature(binding, header, message)?;
        replay.record(binding.relationship_id, header)?;
        Ok(AuthenticatedFederationBackupResponse {
            message: message.clone(),
            expected: expected.clone(),
        })
    }
}

fn verify_response(
    message: &Message,
    header: &FederationHeader,
    expected: &FederationBackupResponseExpectation,
) -> Result<(), TransportError> {
    let valid = match (&expected.request, expected.phase, message) {
        (
            Message::FetchBackupAllocations(request),
            Phase::AllocationPage,
            Message::BackupAllocationPage(page),
        ) => allocation_page_matches(request, page)?,
        (
            Message::RequestBackupCapability(request),
            Phase::Capability,
            Message::BackupCapability(value),
        ) => {
            let digest: [u8; 32] =
                Sha256::digest(federation_backup_request_digest_payload(request)?).into();
            value.request_digest == digest
                && value.permit.as_ref().is_none_or(|permit| {
                    permit.scope == request.scope
                        && permit.operation == request.operation
                        && permit.capability_nonce != header.replay_nonce
                        && permit.capability_nonce != expected.context.replay_nonce
                })
        }
        (Message::ExecuteBackup(request), Phase::Ready, Message::BackupReady(value)) => request
            .permit
            .as_ref()
            .is_some_and(|permit| value.permit_digest == permit.permit_digest),
        (Message::ExecuteBackup(request), Phase::Result, Message::BackupResult(value)) => {
            let permit = request
                .permit
                .as_ref()
                .ok_or(TransportError::UntrustedFederationPeer)?;
            value.permit_digest == permit.permit_digest
                && value.completed_at_unix_micros >= permit.issued_at_unix_micros
                && result_matches(permit, value.outcome.as_ref())?
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(TransportError::UntrustedFederationPeer)
    }
}

fn allocation_page_matches(
    request: &meshspan_protocol::v1::FetchFederatedBackupAllocations,
    page: &meshspan_protocol::v1::FederatedBackupAllocationPage,
) -> Result<bool, TransportError> {
    let digest: [u8; 32] = Sha256::digest(
        meshspan_protocol::federation_backup_allocation_request_digest_payload(request)?,
    )
    .into();
    let cursor = if request.cursor.is_empty() {
        None
    } else {
        Some(meshspan_protocol::decode_backup_allocation_cursor(
            &request.cursor,
        )?)
    };
    let next = if page.next_cursor.is_empty() {
        None
    } else {
        Some(meshspan_protocol::decode_backup_allocation_cursor(
            &page.next_cursor,
        )?)
    };
    Ok(page.request_digest == digest
        && allocation_page_ordered(page, cursor.as_ref(), next.as_ref())
        && page.allocations.len() <= usize::try_from(request.limit).unwrap_or(0)
        && cursor
            .as_ref()
            .is_none_or(|cursor| cursor.snapshot_revision == page.authority_revision)
        && next.as_ref().is_none_or(|next| {
            next.grant_id == request.grant_id
                && next.required_bytes == request.required_bytes
                && cursor.as_ref().is_none_or(|cursor| {
                    allocation_cursor_key(next) > allocation_cursor_key(cursor)
                })
        })
        && page.allocations.iter().all(|allocation| {
            allocation.maximum_bytes >= request.required_bytes
                && allocation
                    .scope
                    .as_ref()
                    .is_some_and(|scope| scope.grant_id == request.grant_id)
        }))
}

fn allocation_cursor_key(
    cursor: &meshspan_protocol::v1::FederatedBackupAllocationCursor,
) -> (i64, i64, &[u8]) {
    (
        cursor.valid_from_unix_micros,
        cursor.valid_until_unix_micros,
        &cursor.allocation_id,
    )
}

fn allocation_page_ordered(
    page: &meshspan_protocol::v1::FederatedBackupAllocationPage,
    after: Option<&meshspan_protocol::v1::FederatedBackupAllocationCursor>,
    next: Option<&meshspan_protocol::v1::FederatedBackupAllocationCursor>,
) -> bool {
    let mut previous = after.map(allocation_cursor_key);
    for allocation in &page.allocations {
        let Some(scope) = &allocation.scope else {
            return false;
        };
        let key = (
            allocation.valid_from_unix_micros,
            allocation.valid_until_unix_micros,
            scope.allocation_id.as_slice(),
        );
        if previous.is_some_and(|previous| key <= previous) {
            return false;
        }
        previous = Some(key);
    }
    next.is_none_or(|next| previous.is_none_or(|previous| allocation_cursor_key(next) >= previous))
}

pub(super) fn result_matches(
    permit: &FederatedBackupPermit,
    result: Option<&Outcome>,
) -> Result<bool, TransportError> {
    let operation = permit
        .operation
        .as_ref()
        .ok_or(TransportError::UntrustedFederationPeer)?;
    let action = RemoteBackupAction::try_from(operation.action)
        .map_err(|_| TransportError::UntrustedFederationPeer)?;
    Ok(match (action, result) {
        (RemoteBackupAction::Store, Some(Outcome::Stored(receipt)))
        | (RemoteBackupAction::Lookup, Some(Outcome::LookedUp(receipt))) => {
            receipt.operation_id == operation.operation_id && receipt.object == operation.object
        }
        (RemoteBackupAction::Verify, Some(Outcome::Verified(receipt))) => {
            receipt.operation_id == operation.operation_id
                && receipt.object == operation.object
                && receipt.object_reference == operation.object_reference
        }
        (RemoteBackupAction::Read, Some(Outcome::Read(receipt))) => {
            receipt.operation_id == operation.operation_id && read_matches(operation, receipt)
        }
        (RemoteBackupAction::Delete, Some(Outcome::Deleted(receipt))) => {
            receipt.operation_id == operation.operation_id
                && receipt.object == operation.object
                && Some(receipt.retirement_revision) == operation.retirement_revision
        }
        (_, Some(Outcome::Rejection(_))) => true,
        _ => false,
    })
}

fn read_matches(
    operation: &FederatedBackupOperation,
    receipt: &meshspan_protocol::v1::BackupReadReceipt,
) -> bool {
    operation.object.as_ref().is_some_and(|object| {
        receipt.byte_length == object.byte_length && receipt.digest == object.digest
    })
}
