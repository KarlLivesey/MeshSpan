// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{AuditEventId, ComponentInstanceId, NodeId, WorkId};

use super::{MetadataCommandCodecError, decoder::Decoder, encoder::Encoder};
use crate::{
    AuthoritativeCommand, ClaimNotification, CompleteNotification, ConfigureNotificationChannel,
    NotificationChannelKind, NotificationDeliveryOutcome, QueueNotification, RecordName,
    SecretGenerationReference,
};

pub(super) const CONFIGURE: u16 = 80;
pub(super) const QUEUE: u16 = 81;
pub(super) const CLAIM: u16 = 82;
pub(super) const COMPLETE: u16 = 83;

pub(super) fn encode(
    encoder: &mut Encoder,
    command: &AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        AuthoritativeCommand::ConfigureNotificationChannel(value) => {
            encoder.u16(CONFIGURE)?;
            encoder.identifier(value.channel_id.as_bytes())?;
            encoder.u64(value.expected_sequence)?;
            encoder.text(value.display_name.display(), 256)?;
            encoder.u8(value.kind as u8)?;
            encoder.identifier(value.settings.secret_id)?;
            encoder.u64(value.settings.generation)?;
            encoder.fixed(&value.settings_commitment)?;
            encoder.bool(value.new_settings.is_some())?;
            if let Some(secret) = &value.new_settings {
                super::secret_generation::encode_payload(encoder, secret)?;
            }
            encoder.bool(value.enabled)?;
            encoder.u8(value.event_filter)?;
        }
        AuthoritativeCommand::QueueNotification(value) => {
            encoder.u16(QUEUE)?;
            encoder.identifier(value.channel_id.as_bytes())?;
            encoder.identifier(value.event_id.as_bytes())?;
            encoder.u64(value.channel_sequence)?;
        }
        AuthoritativeCommand::ClaimNotification(value) => {
            encoder.u16(CLAIM)?;
            encoder.identifier(value.delivery_id.as_bytes())?;
            encoder.u64(value.expected_attempt)?;
            encoder.identifier(value.worker_node_id.as_bytes())?;
            encoder.u64(value.worker_incarnation)?;
        }
        AuthoritativeCommand::CompleteNotification(value) => {
            encoder.u16(COMPLETE)?;
            encoder.identifier(value.delivery_id.as_bytes())?;
            encoder.u64(value.attempt)?;
            encoder.identifier(value.worker_node_id.as_bytes())?;
            encoder.u64(value.worker_incarnation)?;
            encoder.u8(value.outcome as u8)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) fn decode(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<AuthoritativeCommand, MetadataCommandCodecError> {
    match kind {
        CONFIGURE => {
            let channel_id = ComponentInstanceId::from_bytes(decoder.identifier()?)?;
            let expected_sequence = decoder.u64()?;
            let display_name = RecordName::new(&decoder.text(256)?)?;
            let kind = match decoder.u8()? {
                1 => NotificationChannelKind::Webhook,
                2 => NotificationChannelKind::Email,
                _ => return Err(MetadataCommandCodecError::Invalid),
            };
            let settings = SecretGenerationReference {
                secret_id: decoder.identifier()?,
                generation: decoder.u64()?,
            };
            let settings_commitment = decoder.fixed()?;
            let new_settings = if decoder.bool()? {
                Some(Box::new(super::secret_generation::decode_payload(decoder)?))
            } else {
                None
            };
            let enabled = decoder.bool()?;
            let event_filter = decoder.u8()?;
            if settings.generation == 0 || !(1..=15).contains(&event_filter) {
                return Err(MetadataCommandCodecError::Invalid);
            }
            Ok(AuthoritativeCommand::ConfigureNotificationChannel(
                ConfigureNotificationChannel {
                    channel_id,
                    expected_sequence,
                    display_name,
                    kind,
                    settings,
                    settings_commitment,
                    new_settings,
                    enabled,
                    event_filter,
                },
            ))
        }
        QUEUE => Ok(AuthoritativeCommand::QueueNotification(QueueNotification {
            channel_id: ComponentInstanceId::from_bytes(decoder.identifier()?)?,
            event_id: AuditEventId::from_bytes(decoder.identifier()?)?,
            channel_sequence: decoder.u64()?,
        })),
        CLAIM => Ok(AuthoritativeCommand::ClaimNotification(ClaimNotification {
            delivery_id: WorkId::from_bytes(decoder.identifier()?)?,
            expected_attempt: decoder.u64()?,
            worker_node_id: NodeId::from_bytes(decoder.identifier()?)?,
            worker_incarnation: decoder.u64()?,
        })),
        COMPLETE => {
            let delivery_id = WorkId::from_bytes(decoder.identifier()?)?;
            let attempt = decoder.u64()?;
            let worker_node_id = NodeId::from_bytes(decoder.identifier()?)?;
            let worker_incarnation = decoder.u64()?;
            let outcome = match decoder.u8()? {
                1 => NotificationDeliveryOutcome::Accepted,
                2 => NotificationDeliveryOutcome::Retry,
                3 => NotificationDeliveryOutcome::Rejected,
                _ => return Err(MetadataCommandCodecError::Invalid),
            };
            Ok(AuthoritativeCommand::CompleteNotification(
                CompleteNotification {
                    delivery_id,
                    attempt,
                    worker_node_id,
                    worker_incarnation,
                    outcome,
                },
            ))
        }
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}
