// SPDX-License-Identifier: GPL-2.0-only

//! Atomic node-local admission of capacity and its signed federated wire capability.

use rusqlite::TransactionBehavior;
use thiserror::Error;

use crate::federation_storage_capability_ledger::record_in_transaction;
use crate::federation_storage_quota::reserve_in_transaction;
use crate::{
    FederationStorageAllocationAuthority, FederationStorageCapabilityDisposition,
    FederationStorageCapabilityLedgerError, FederationStorageCapabilityPresentation,
    FederationStorageQuotaDisposition, FederationStorageQuotaError,
    FederationStorageWriteReservationRequest, LocalDatabase,
};

impl LocalDatabase {
    /// Atomically records one signed write capability and holds its exact allocation capacity.
    ///
    /// # Errors
    ///
    /// Rejects mismatched presentation/reservation evidence, stale authority, conflicting replay,
    /// exhausted capacity, corrupt local state and SQLite failures without applying either half.
    pub fn admit_federated_storage_write_capability(
        &mut self,
        authority: FederationStorageAllocationAuthority,
        request: FederationStorageWriteReservationRequest,
        presentation: &FederationStorageCapabilityPresentation,
    ) -> Result<
        (
            FederationStorageQuotaDisposition,
            FederationStorageCapabilityDisposition,
        ),
        FederationStorageAdmissionError,
    > {
        validate_joint_evidence(request, presentation)?;
        let node_id = self.node_id();
        let transaction = self
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let capability = record_in_transaction(&transaction, presentation)?;
        let (quota, _) = reserve_in_transaction(&transaction, node_id, authority, request)?;
        transaction.commit()?;
        Ok((quota, capability))
    }
}

fn validate_joint_evidence(
    request: FederationStorageWriteReservationRequest,
    presentation: &FederationStorageCapabilityPresentation,
) -> Result<(), FederationStorageAdmissionError> {
    let permit = presentation.permit;
    let exact = request.operation_id == permit.operation_id
        && request.remote_mesh_id == permit.remote_mesh_id
        && request.scope_digest == permit.scope_digest
        && request.request_digest == permit.request_digest
        && request.capability_nonce == permit.capability_nonce
        && request.shard == permit.shard
        && request.action == permit.action
        && request.permit_digest == permit.permit_digest
        && request.expires_at == permit.expires_at
        && request.issued_at == permit.issued_at;
    exact
        .then_some(())
        .ok_or(FederationStorageAdmissionError::Invalid)
}

/// Stable failure categories for atomic federated write-capability admission.
#[derive(Debug, Error)]
pub enum FederationStorageAdmissionError {
    /// Reservation and signed capability evidence did not describe one exact permit.
    #[error("federated storage admission evidence is invalid")]
    Invalid,
    /// Node-local allocation accounting rejected the reservation.
    #[error("federated storage admission quota failed")]
    Quota(#[from] FederationStorageQuotaError),
    /// Signed capability evidence could not be recorded safely.
    #[error("federated storage admission capability ledger failed")]
    Capability(#[from] FederationStorageCapabilityLedgerError),
    /// SQLite rejected the enclosing atomic transition.
    #[error("federated storage admission database operation failed")]
    Database(#[from] rusqlite::Error),
}
