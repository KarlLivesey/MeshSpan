// SPDX-License-Identifier: GPL-2.0-only

//! Canonical converged volume-head command encoding.

use meshspan_domain::{NamespaceCommitId, ObjectRevisionId, OperationId, VolumeId};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{CommitConvergedVolumeHead, ConvergedHeadEvidence};

pub(super) const COMMIT_CONVERGED_VOLUME_HEAD: u16 = 35;

pub(super) fn encode(
    encoder: &mut Encoder,
    value: CommitConvergedVolumeHead,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(COMMIT_CONVERGED_VOLUME_HEAD)?;
    encoder.identifier(value.volume_id.as_bytes())?;
    encoder.optional_fixed_16(
        value
            .expected_namespace_commit_id
            .map(NamespaceCommitId::as_bytes),
    )?;
    encoder.identifier(value.namespace_commit_id.as_bytes())?;
    encoder.identifier(value.root_object_revision_id.as_bytes())?;
    encode_evidence(encoder, value.evidence)
}

fn encode_evidence(
    encoder: &mut Encoder,
    evidence: ConvergedHeadEvidence,
) -> Result<(), MetadataCommandCodecError> {
    match evidence {
        ConvergedHeadEvidence::Publication {
            operation_id,
            request_digest,
            result_digest,
        } => {
            encoder.u8(1)?;
            encode_common_evidence(encoder, operation_id, request_digest, result_digest)
        }
        ConvergedHeadEvidence::Reconciliation {
            operation_id,
            request_digest,
            causal_plan_digest,
            replay_plan_digest,
            result_digest,
        } => {
            encoder.u8(2)?;
            encode_common_evidence(encoder, operation_id, request_digest, result_digest)?;
            encoder.fixed(&causal_plan_digest)?;
            encoder.fixed(&replay_plan_digest)
        }
    }
}

fn encode_common_evidence(
    encoder: &mut Encoder,
    operation_id: OperationId,
    request_digest: [u8; 32],
    result_digest: [u8; 32],
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(operation_id.as_bytes())?;
    encoder.fixed(&request_digest)?;
    encoder.fixed(&result_digest)
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<CommitConvergedVolumeHead, MetadataCommandCodecError> {
    Ok(CommitConvergedVolumeHead {
        volume_id: VolumeId::from_bytes(decoder.identifier()?)?,
        expected_namespace_commit_id: decoder
            .optional_fixed_16()?
            .map(NamespaceCommitId::from_bytes)
            .transpose()?,
        namespace_commit_id: NamespaceCommitId::from_bytes(decoder.identifier()?)?,
        root_object_revision_id: ObjectRevisionId::from_bytes(decoder.identifier()?)?,
        evidence: decode_evidence(decoder)?,
    })
}

fn decode_evidence(
    decoder: &mut Decoder<'_>,
) -> Result<ConvergedHeadEvidence, MetadataCommandCodecError> {
    let kind = decoder.u8()?;
    let operation_id = OperationId::from_bytes(decoder.identifier()?)?;
    let request_digest = decoder.fixed()?;
    let result_digest = decoder.fixed()?;
    match kind {
        1 => Ok(ConvergedHeadEvidence::Publication {
            operation_id,
            request_digest,
            result_digest,
        }),
        2 => Ok(ConvergedHeadEvidence::Reconciliation {
            operation_id,
            request_digest,
            causal_plan_digest: decoder.fixed()?,
            replay_plan_digest: decoder.fixed()?,
            result_digest,
        }),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}
