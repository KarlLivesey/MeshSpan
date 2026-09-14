// SPDX-License-Identifier: GPL-2.0-only

//! Domain-separated canonical signatures for the backup conversation only.

use crate::WireContractError;
use crate::federation_signing::{signing_payload, single_message_payload};
use crate::v1::{FederationHeader, RequestFederatedBackupCapability, federation_envelope::Message};

/// Canonical header and backup message bytes, excluding only the envelope signature.
///
/// Each conversation phase has a distinct signing domain. The embedded provider MAC and
/// capability nonce remain covered. Call framing validation separately for semantic bounds.
///
/// # Errors
/// Rejects other message families and canonical allocation/encoding failure.
pub fn federation_backup_signing_payload(
    header: &FederationHeader,
    message: &Message,
) -> Result<Vec<u8>, WireContractError> {
    match message.clone() {
        Message::FetchBackupAllocations(mut value) => {
            value.signature.clear();
            signing_payload(
                b"meshspan.federation.backup-allocation-fetch.v1\0",
                header,
                &value,
            )
        }
        Message::BackupAllocationPage(mut value) => {
            value.signature.clear();
            signing_payload(
                b"meshspan.federation.backup-allocation-page.v1\0",
                header,
                &value,
            )
        }
        Message::RequestBackupCapability(mut value) => {
            value.signature.clear();
            signing_payload(
                b"meshspan.federation.backup-capability-request.v1\0",
                header,
                &value,
            )
        }
        Message::BackupCapability(mut value) => {
            value.signature.clear();
            signing_payload(
                b"meshspan.federation.backup-capability.v1\0",
                header,
                &value,
            )
        }
        Message::ExecuteBackup(mut value) => {
            value.signature.clear();
            signing_payload(b"meshspan.federation.backup-execute.v1\0", header, &value)
        }
        Message::BackupReady(mut value) => {
            value.signature.clear();
            signing_payload(b"meshspan.federation.backup-ready.v1\0", header, &value)
        }
        Message::BackupResult(mut value) => {
            value.signature.clear();
            signing_payload(b"meshspan.federation.backup-result.v1\0", header, &value)
        }
        _ => return Err(WireContractError::InvalidMessage),
    }
    .map_err(encoding_error)
}

/// Complete logical capability-request bytes, independent of fresh envelope nonces.
///
/// The operation ID, deadline, catalogue revision and all scope dimensions are embedded in
/// the request. The transport hashes these bytes with SHA-256 for response correlation; this
/// is distinct from the provider-only BLAKE3 capability MAC.
///
/// # Errors
/// Reports canonical allocation or encoding failure.
pub fn federation_backup_request_digest_payload(
    request: &RequestFederatedBackupCapability,
) -> Result<Vec<u8>, WireContractError> {
    let mut unsigned = request.clone();
    unsigned.signature.clear();
    single_message_payload(
        b"meshspan.federation.backup-capability-request-digest.v1\0",
        &unsigned,
    )
    .map_err(encoding_error)
}

/// Canonical allocation-discovery query bytes, excluding only its envelope signature.
///
/// # Errors
/// Reports allocation or canonical encoding failure.
pub fn federation_backup_allocation_request_digest_payload(
    request: &crate::v1::FetchFederatedBackupAllocations,
) -> Result<Vec<u8>, WireContractError> {
    let mut unsigned = request.clone();
    unsigned.signature.clear();
    single_message_payload(
        b"meshspan.federation.backup-allocation-query-digest.v1\0",
        &unsigned,
    )
    .map_err(encoding_error)
}

fn encoding_error(error: meshspan_protobuf::EncodeError) -> WireContractError {
    match error {
        meshspan_protobuf::EncodeError::LengthOverflow
        | meshspan_protobuf::EncodeError::AllocationFailed => WireContractError::FrameTooLarge,
        meshspan_protobuf::EncodeError::LengthMismatch => WireContractError::LengthMismatch,
    }
}
