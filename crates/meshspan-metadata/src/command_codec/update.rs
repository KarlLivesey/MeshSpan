// SPDX-License-Identifier: GPL-2.0-only

use super::{MetadataCommandCodecError, decoder::Decoder, encoder::Encoder};
use crate::{
    AdvanceUpdateNode, AuthoritativeCommand, ConfigureUpdateSigner, ControlUpdateRollout,
    StartUpdateRollout, UpdateNodePhase, UpdateRolloutControl,
};
use crate::{UpdateReadyNode, UpdateRestartReadiness};
use meshspan_domain::{ComponentInstanceId, NodeId, UnixMicros, WorkId};

pub(super) const CONFIGURE: u16 = 84;
pub(super) const START: u16 = 85;
pub(super) const ADVANCE: u16 = 86;
pub(super) const CONTROL: u16 = 87;
pub(super) const PUBLISH_ARTIFACT: u16 = 88;

pub(super) fn encode(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        AuthoritativeCommand::ConfigureUpdateSigner(value) => {
            encoder.u16(CONFIGURE)?;
            encoder.identifier(value.signer_id.as_bytes())?;
            encoder.u64(value.expected_sequence)?;
            encoder.fixed(&value.public_key)?;
            encoder.bool(value.enabled)?;
        }
        AuthoritativeCommand::StartUpdateRollout(value) => {
            encoder.u16(START)?;
            encoder.identifier(value.rollout_id.as_bytes())?;
            encoder.identifier(value.signer_id.as_bytes())?;
            encoder.u64(value.signer_sequence)?;
            encoder.bytes(&value.manifest, 16384)?;
            encoder.bytes(&value.signature, 72)?;
            encoder.bool(value.allow_service_interruption)?;
        }
        AuthoritativeCommand::AdvanceUpdateNode(value) => {
            encoder.u16(ADVANCE)?;
            encoder.identifier(value.rollout_id.as_bytes())?;
            encoder.identifier(value.node_id.as_bytes())?;
            encoder.u64(value.incarnation)?;
            encoder.u64(value.expected_sequence)?;
            encoder.u8(value.phase as u8)?;
            encoder.text(&value.target, 64)?;
            encoder.fixed(&value.evidence_digest)?;
            encode_readiness(encoder, value.restart_readiness.as_ref())?;
        }
        AuthoritativeCommand::ControlUpdateRollout(value) => {
            encoder.u16(CONTROL)?;
            encoder.identifier(value.rollout_id.as_bytes())?;
            encoder.u64(value.expected_sequence)?;
            encoder.u8(value.action as u8)?;
        }
        AuthoritativeCommand::PublishUpdateArtifact(value) => {
            encoder.u16(PUBLISH_ARTIFACT)?;
            encoder.identifier(value.rollout_id.as_bytes())?;
            encoder.identifier(value.node_id.as_bytes())?;
            encoder.u64(value.incarnation)?;
            encoder.text(&value.target, 64)?;
            encoder.u64(value.byte_length)?;
            encoder.text(&value.sha256, 64)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) fn decode(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    Ok(match kind {
        CONFIGURE => AuthoritativeCommand::ConfigureUpdateSigner(ConfigureUpdateSigner {
            signer_id: ComponentInstanceId::from_bytes(decoder.identifier()?)?,
            expected_sequence: decoder.u64()?,
            public_key: decoder.fixed()?,
            enabled: decoder.bool()?,
        }),
        START => AuthoritativeCommand::StartUpdateRollout(StartUpdateRollout {
            rollout_id: WorkId::from_bytes(decoder.identifier()?)?,
            signer_id: ComponentInstanceId::from_bytes(decoder.identifier()?)?,
            signer_sequence: decoder.u64()?,
            manifest: decoder.bytes(16384)?,
            signature: decoder.bytes(72)?,
            allow_service_interruption: decoder.bool()?,
        }),
        ADVANCE => AuthoritativeCommand::AdvanceUpdateNode(AdvanceUpdateNode {
            rollout_id: WorkId::from_bytes(decoder.identifier()?)?,
            node_id: NodeId::from_bytes(decoder.identifier()?)?,
            incarnation: decoder.u64()?,
            expected_sequence: decoder.u64()?,
            phase: match decoder.u8()? {
                2 => UpdateNodePhase::Staged,
                3 => UpdateNodePhase::Restarting,
                4 => UpdateNodePhase::Verified,
                5 => UpdateNodePhase::Failed,
                _ => return Err(MetadataCommandCodecError::Invalid),
            },
            target: decoder.text(64)?,
            evidence_digest: decoder.fixed()?,
            restart_readiness: decode_readiness(decoder)?,
        }),
        CONTROL => AuthoritativeCommand::ControlUpdateRollout(ControlUpdateRollout {
            rollout_id: WorkId::from_bytes(decoder.identifier()?)?,
            expected_sequence: decoder.u64()?,
            action: match decoder.u8()? {
                1 => UpdateRolloutControl::Pause,
                2 => UpdateRolloutControl::Resume,
                3 => UpdateRolloutControl::Cancel,
                _ => return Err(MetadataCommandCodecError::Invalid),
            },
        }),
        PUBLISH_ARTIFACT => {
            AuthoritativeCommand::PublishUpdateArtifact(crate::PublishUpdateArtifact {
                rollout_id: WorkId::from_bytes(decoder.identifier()?)?,
                node_id: NodeId::from_bytes(decoder.identifier()?)?,
                incarnation: decoder.u64()?,
                target: decoder.text(64)?,
                byte_length: decoder.u64()?,
                sha256: decoder.text(64)?,
            })
        }
        _ => return Err(MetadataCommandCodecError::Invalid),
    })
}

fn encode_readiness(
    encoder: &mut Encoder,
    value: Option<&UpdateRestartReadiness>,
) -> Result<(), MetadataCommandCodecError> {
    encoder.bool(value.is_some())?;
    if let Some(value) = value {
        if value.ready_nodes.len() > 19 {
            return Err(MetadataCommandCodecError::Invalid);
        }
        encoder.fixed(&value.quorum_plan_digest)?;
        encoder.i64(value.observed_at.get())?;
        encoder.u8(u8::try_from(value.ready_nodes.len())
            .map_err(|_| MetadataCommandCodecError::Invalid)?)?;
        for node in &value.ready_nodes {
            encoder.identifier(node.node_id.as_bytes())?;
            encoder.u64(node.incarnation)?;
            encoder.u64(node.applied_index)?;
        }
    }
    Ok(())
}

fn decode_readiness(
    decoder: &mut Decoder<'_>,
) -> Result<Option<UpdateRestartReadiness>, MetadataCommandCodecError> {
    if !decoder.bool()? {
        return Ok(None);
    }
    let quorum_plan_digest = decoder.fixed()?;
    let observed_at = UnixMicros::new(decoder.i64()?);
    let count = decoder.u8()?;
    if count > 19 {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let mut ready_nodes = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        ready_nodes.push(UpdateReadyNode {
            node_id: NodeId::from_bytes(decoder.identifier()?)?,
            incarnation: decoder.u64()?,
            applied_index: decoder.u64()?,
        });
    }
    Ok(Some(UpdateRestartReadiness {
        quorum_plan_digest,
        observed_at,
        ready_nodes,
    }))
}
