// SPDX-License-Identifier: GPL-2.0-only

//! Canonical cleanup transitions. Decoding preserves evidence; the state machine validates
//! its authority, signatures, reachability and exact committed lifecycle prerequisites.

use super::{Decoder, Encoder, MetadataCommandCodecError};
use crate::{
    AttestVersionCleanup, AuthoriseVersionCleanup, AuthoritativeCommand, CancelVersionCleanup,
    ProposeVersionCleanup, VersionCleanupAttestation,
};
use meshspan_domain::{ContentManifestId, FileVersionId, NodeId, OperationId, Revision, VolumeId};

#[path = "cleanup_inventory.rs"]
mod inventory;
#[path = "cleanup_receipts.rs"]
mod receipts;
#[cfg(test)]
#[path = "cleanup_tests.rs"]
mod tests;

const PROPOSE: u16 = 126;
const ATTEST: u16 = 127;
const AUTHORISE: u16 = 128;
const CANCEL: u16 = 129;
const APPEND: u16 = 130;
const SEAL: u16 = 131;
const ISSUE: u16 = 132;
const COMPLETE: u16 = 133;
const RECLAIM: u16 = 134;

pub(super) fn is_kind(kind: u16) -> bool {
    (PROPOSE..=RECLAIM).contains(&kind)
}

pub(super) fn encode_command(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        AuthoritativeCommand::ProposeVersionCleanup(value) => {
            encoder.u16(PROPOSE)?;
            encode_proposal(encoder, value)?;
        }
        AuthoritativeCommand::AttestVersionCleanup(value) => {
            encoder.u16(ATTEST)?;
            encode_attestation(encoder, &value.attestation)?;
        }
        AuthoritativeCommand::AuthoriseVersionCleanup(value) => {
            encoder.u16(AUTHORISE)?;
            encoder.identifier(value.cleanup_operation_id.as_bytes())?;
            encoder.u64(value.cleanup_revision.get())?;
            encoder.fixed(&value.reachability_subject_digest)?;
        }
        AuthoritativeCommand::CancelVersionCleanup(value) => {
            encoder.u16(CANCEL)?;
            encoder.identifier(value.cleanup_operation_id.as_bytes())?;
            encoder.u64(value.cleanup_revision.get())?;
            encoder.fixed(&value.reachability_subject_digest)?;
        }
        AuthoritativeCommand::AppendVersionCleanupItems(value) => {
            encoder.u16(APPEND)?;
            inventory::encode_append(encoder, value)?;
        }
        AuthoritativeCommand::SealVersionCleanupInventory(value) => {
            encoder.u16(SEAL)?;
            inventory::encode_seal(encoder, value)?;
        }
        AuthoritativeCommand::IssueVersionCleanupPermit(value) => {
            encoder.u16(ISSUE)?;
            receipts::encode_issue(encoder, value)?;
        }
        AuthoritativeCommand::CompleteVersionCleanupItem(value) => {
            encoder.u16(COMPLETE)?;
            receipts::encode_complete(encoder, value)?;
        }
        AuthoritativeCommand::ConfirmVersionCleanupReclamation(value) => {
            encoder.u16(RECLAIM)?;
            receipts::encode_reclamation(encoder, value)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) fn decode_command(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    Ok(match kind {
        PROPOSE => AuthoritativeCommand::ProposeVersionCleanup(decode_proposal(decoder)?),
        ATTEST => AuthoritativeCommand::AttestVersionCleanup(AttestVersionCleanup {
            attestation: decode_attestation(decoder)?,
        }),
        AUTHORISE => AuthoritativeCommand::AuthoriseVersionCleanup(AuthoriseVersionCleanup {
            cleanup_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
            cleanup_revision: Revision::new(decoder.u64()?),
            reachability_subject_digest: decoder.fixed()?,
        }),
        CANCEL => AuthoritativeCommand::CancelVersionCleanup(CancelVersionCleanup {
            cleanup_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
            cleanup_revision: Revision::new(decoder.u64()?),
            reachability_subject_digest: decoder.fixed()?,
        }),
        APPEND => {
            AuthoritativeCommand::AppendVersionCleanupItems(inventory::decode_append(decoder)?)
        }
        SEAL => AuthoritativeCommand::SealVersionCleanupInventory(inventory::decode_seal(decoder)?),
        ISSUE => AuthoritativeCommand::IssueVersionCleanupPermit(receipts::decode_issue(decoder)?),
        COMPLETE => {
            AuthoritativeCommand::CompleteVersionCleanupItem(receipts::decode_complete(decoder)?)
        }
        RECLAIM => AuthoritativeCommand::ConfirmVersionCleanupReclamation(
            receipts::decode_reclamation(decoder)?,
        ),
        _ => return Err(MetadataCommandCodecError::Unsupported),
    })
}

fn encode_proposal(
    encoder: &mut Encoder,
    value: &ProposeVersionCleanup,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.volume_id.as_bytes())?;
    encoder.identifier(value.version_id.as_bytes())?;
    encoder.identifier(value.manifest_id.as_bytes())?;
    encoder.fixed(&value.manifest_root_digest)?;
    encoder.identifier(value.source_scan_operation_id.as_bytes())?;
    encoder.fixed(&value.scan_request_digest)?;
    encoder.fixed(&value.reachability_subject_digest)?;
    encoder.u64(value.retention_policy_sequence)?;
    encoder.u64(value.reachability_revision.get())?;
    encoder.u64(value.retained_root_count)?;
    encoder.fixed(&value.retained_root_digest)?;
    encoder.fixed(&value.retained_root_set_digest)?;
    encoder.fixed(&value.local_roots_digest)?;
    encoder.fixed(&value.proof_result_digest)
}

fn decode_proposal(
    decoder: &mut Decoder<'_>,
) -> Result<ProposeVersionCleanup, MetadataCommandCodecError> {
    Ok(ProposeVersionCleanup {
        volume_id: VolumeId::from_bytes(decoder.identifier()?)?,
        version_id: FileVersionId::from_bytes(decoder.identifier()?)?,
        manifest_id: ContentManifestId::from_bytes(decoder.identifier()?)?,
        manifest_root_digest: decoder.fixed()?,
        source_scan_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
        scan_request_digest: decoder.fixed()?,
        reachability_subject_digest: decoder.fixed()?,
        retention_policy_sequence: decoder.u64()?,
        reachability_revision: Revision::new(decoder.u64()?),
        retained_root_count: decoder.u64()?,
        retained_root_digest: decoder.fixed()?,
        retained_root_set_digest: decoder.fixed()?,
        local_roots_digest: decoder.fixed()?,
        proof_result_digest: decoder.fixed()?,
    })
}

fn encode_attestation(
    encoder: &mut Encoder,
    value: &VersionCleanupAttestation,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.cleanup_operation_id.as_bytes())?;
    encoder.u64(value.cleanup_revision.get())?;
    encoder.identifier(value.node_id.as_bytes())?;
    encoder.u64(value.node_incarnation)?;
    encoder.u64(value.key_generation)?;
    encoder.identifier(value.scan_operation_id.as_bytes())?;
    encoder.fixed(&value.scan_request_digest)?;
    encoder.fixed(&value.reachability_subject_digest)?;
    encoder.fixed(&value.local_roots_digest)?;
    encoder.fixed(&value.scan_result_digest)?;
    encoder.fixed(&value.signature)
}

fn decode_attestation(
    decoder: &mut Decoder<'_>,
) -> Result<VersionCleanupAttestation, MetadataCommandCodecError> {
    Ok(VersionCleanupAttestation {
        cleanup_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
        cleanup_revision: Revision::new(decoder.u64()?),
        node_id: NodeId::from_bytes(decoder.identifier()?)?,
        node_incarnation: decoder.u64()?,
        key_generation: decoder.u64()?,
        scan_operation_id: OperationId::from_bytes(decoder.identifier()?)?,
        scan_request_digest: decoder.fixed()?,
        reachability_subject_digest: decoder.fixed()?,
        local_roots_digest: decoder.fixed()?,
        scan_result_digest: decoder.fixed()?,
        signature: decoder.fixed()?,
    })
}
