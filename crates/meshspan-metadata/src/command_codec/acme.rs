// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{AcmeConfigurationId, CertificateOrderId, NodeId, UnixMicros};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use super::secret_generation;
use crate::{
    ACME_ACCOUNT_KEY_SECRET_KIND, ACME_CHALLENGE_SETTINGS_SECRET_KIND,
    AcknowledgePublicCertificateInstallation, AcmeChallengeKind, AdvanceManualDnsTask,
    CertificateOrderCompletion, CheckpointCertificateOrder, ClaimCertificateOrder,
    CompleteCertificateOrder, ConfigureAcme, MAXIMUM_CERTIFICATE_ORDER_CHECKPOINT_BYTES,
    MAXIMUM_MANUAL_DNS_VALUE_BYTES, ManualDnsTaskPhase, PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
    ProvisionAcme, QueueCertificateOrder, RenewCertificateOrder, SecretGenerationReference,
};

pub(super) const CONFIGURE_ACME: u16 = 49;
pub(super) const QUEUE_CERTIFICATE_ORDER: u16 = 50;
pub(super) const CLAIM_CERTIFICATE_ORDER: u16 = 51;
pub(super) const RENEW_CERTIFICATE_ORDER: u16 = 52;
pub(super) const COMPLETE_CERTIFICATE_ORDER: u16 = 53;
pub(super) const ACKNOWLEDGE_PUBLIC_CERTIFICATE_INSTALLATION: u16 = 54;
pub(super) const CHECKPOINT_CERTIFICATE_ORDER: u16 = 55;
pub(super) const ADVANCE_MANUAL_DNS_TASK: u16 = 56;
pub(super) const PROVISION_ACME: u16 = 57;

const MAXIMUM_DIRECTORY_URL_BYTES: usize = 2_048;
const MAXIMUM_CERTIFICATE_NAMES: usize = 256;
const MAXIMUM_DNS_NAME_BYTES: usize = 253;

pub(super) fn encode_command(
    encoder: &mut Encoder,
    command: &crate::AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        crate::AuthoritativeCommand::ProvisionAcme(value) => encode_provision(encoder, value)?,
        crate::AuthoritativeCommand::ConfigureAcme(value) => encode_configure(encoder, value)?,
        crate::AuthoritativeCommand::QueueCertificateOrder(value) => encode_queue(encoder, *value)?,
        crate::AuthoritativeCommand::ClaimCertificateOrder(value) => encode_claim(encoder, *value)?,
        crate::AuthoritativeCommand::RenewCertificateOrder(value) => encode_renew(encoder, *value)?,
        crate::AuthoritativeCommand::CheckpointCertificateOrder(value) => {
            encode_checkpoint(encoder, value)?;
        }
        crate::AuthoritativeCommand::AdvanceManualDnsTask(value) => {
            encode_manual_dns_task(encoder, value)?;
        }
        crate::AuthoritativeCommand::CompleteCertificateOrder(value) => {
            encode_complete(encoder, value)?;
        }
        crate::AuthoritativeCommand::AcknowledgePublicCertificateInstallation(value) => {
            encode_installation(encoder, *value)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) const fn is_command_kind(kind: u16) -> bool {
    matches!(
        kind,
        CONFIGURE_ACME
            | QUEUE_CERTIFICATE_ORDER
            | CLAIM_CERTIFICATE_ORDER
            | RENEW_CERTIFICATE_ORDER
            | COMPLETE_CERTIFICATE_ORDER
            | ACKNOWLEDGE_PUBLIC_CERTIFICATE_INSTALLATION
            | CHECKPOINT_CERTIFICATE_ORDER
            | ADVANCE_MANUAL_DNS_TASK
            | PROVISION_ACME
    )
}

pub(super) fn decode_command(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<crate::AuthoritativeCommand, MetadataCommandCodecError> {
    match kind {
        PROVISION_ACME => decode_provision(decoder)
            .map(Box::new)
            .map(crate::AuthoritativeCommand::ProvisionAcme),
        CONFIGURE_ACME => decode_configure(decoder).map(crate::AuthoritativeCommand::ConfigureAcme),
        QUEUE_CERTIFICATE_ORDER => {
            decode_queue(decoder).map(crate::AuthoritativeCommand::QueueCertificateOrder)
        }
        CLAIM_CERTIFICATE_ORDER => {
            decode_claim(decoder).map(crate::AuthoritativeCommand::ClaimCertificateOrder)
        }
        RENEW_CERTIFICATE_ORDER => {
            decode_renew(decoder).map(crate::AuthoritativeCommand::RenewCertificateOrder)
        }
        CHECKPOINT_CERTIFICATE_ORDER => {
            decode_checkpoint(decoder).map(crate::AuthoritativeCommand::CheckpointCertificateOrder)
        }
        ADVANCE_MANUAL_DNS_TASK => {
            decode_manual_dns_task(decoder).map(crate::AuthoritativeCommand::AdvanceManualDnsTask)
        }
        COMPLETE_CERTIFICATE_ORDER => {
            decode_complete(decoder).map(crate::AuthoritativeCommand::CompleteCertificateOrder)
        }
        ACKNOWLEDGE_PUBLIC_CERTIFICATE_INSTALLATION => decode_installation(decoder)
            .map(crate::AuthoritativeCommand::AcknowledgePublicCertificateInstallation),
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}

fn encode_provision(
    encoder: &mut Encoder,
    value: &ProvisionAcme,
) -> Result<(), MetadataCommandCodecError> {
    validate_provision(value)?;
    encoder.u16(PROVISION_ACME)?;
    encoder.fixed(&value.intent_digest)?;
    encode_configuration_payload(encoder, &value.configuration)?;
    secret_generation::encode_payload(encoder, &value.account_key_generation)?;
    encoder.bool(value.challenge_settings_generation.is_some())?;
    if let Some(settings) = &value.challenge_settings_generation {
        secret_generation::encode_payload(encoder, settings)?;
    }
    encode_queue_payload(encoder, value.initial_order)
}

fn decode_provision(decoder: &mut Decoder<'_>) -> Result<ProvisionAcme, MetadataCommandCodecError> {
    let intent_digest = decoder.fixed()?;
    let configuration = decode_configuration_payload(decoder)?;
    let account_key_generation = Box::new(secret_generation::decode_payload(decoder)?);
    let challenge_settings_generation = decoder
        .bool()?
        .then(|| secret_generation::decode_payload(decoder))
        .transpose()?
        .map(Box::new);
    let initial_order = decode_queue_payload(decoder)?;
    let value = ProvisionAcme {
        intent_digest,
        configuration,
        account_key_generation,
        challenge_settings_generation,
        initial_order,
    };
    validate_provision(&value)?;
    Ok(value)
}

fn validate_provision(value: &ProvisionAcme) -> Result<(), MetadataCommandCodecError> {
    validate_configuration(&value.configuration)?;
    secret_generation::validate(&value.account_key_generation)?;
    if let Some(settings) = &value.challenge_settings_generation {
        secret_generation::validate(settings)?;
    }
    let account = &value.account_key_generation.secret.context;
    let account_reference = value.configuration.account_key;
    if value.intent_digest == [0; 32]
        || account.kind() != ACME_ACCOUNT_KEY_SECRET_KIND
        || account.id() != account_reference.secret_id
        || account.generation() != account_reference.generation
        || value.initial_order.config_id != value.configuration.config_id
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    match (
        value.configuration.challenge_settings,
        value.challenge_settings_generation.as_deref(),
    ) {
        (None, None) => {}
        (Some(reference), Some(generation))
            if generation.secret.context.kind() == ACME_CHALLENGE_SETTINGS_SECRET_KIND
                && generation.secret.context.id() == reference.secret_id
                && generation.secret.context.generation() == reference.generation => {}
        _ => return Err(MetadataCommandCodecError::Invalid),
    }
    Ok(())
}

fn encode_manual_dns_task(
    encoder: &mut Encoder,
    value: &AdvanceManualDnsTask,
) -> Result<(), MetadataCommandCodecError> {
    validate_manual_dns_task(value)?;
    encoder.u16(ADVANCE_MANUAL_DNS_TASK)?;
    encoder.fixed(&value.task_digest)?;
    encode_claim_identity(
        encoder,
        value.order_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    encoder.text(&value.record_name, MAXIMUM_DNS_NAME_BYTES)?;
    encoder.bytes(&value.record_value, MAXIMUM_MANUAL_DNS_VALUE_BYTES)?;
    encoder.i64(value.expires_at.get())?;
    encoder.u8(manual_dns_phase_code(value.phase))
}

fn decode_manual_dns_task(
    decoder: &mut Decoder<'_>,
) -> Result<AdvanceManualDnsTask, MetadataCommandCodecError> {
    let task_digest = decoder.fixed()?;
    let identity = decode_claim_identity(decoder)?;
    let value = AdvanceManualDnsTask {
        task_digest,
        order_id: identity.order_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        record_name: decoder.text(MAXIMUM_DNS_NAME_BYTES)?,
        record_value: decoder.bytes(MAXIMUM_MANUAL_DNS_VALUE_BYTES)?,
        expires_at: UnixMicros::new(decoder.i64()?),
        phase: match decoder.u8()? {
            1 => ManualDnsTaskPhase::AwaitingPublication,
            2 => ManualDnsTaskPhase::PublicationObserved,
            3 => ManualDnsTaskPhase::AwaitingRemoval,
            4 => ManualDnsTaskPhase::Complete,
            _ => return Err(MetadataCommandCodecError::Invalid),
        },
    };
    validate_manual_dns_task(&value)?;
    Ok(value)
}

fn validate_manual_dns_task(value: &AdvanceManualDnsTask) -> Result<(), MetadataCommandCodecError> {
    if value.task_digest == [0; 32]
        || value.claim_generation == 0
        || value.worker_incarnation == 0
        || value.fence == 0
        || value.expires_at.get() <= 0
        || meshspan_acme::Dns01Payload::new(&value.record_name, &value.record_value).is_err()
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    Ok(())
}

const fn manual_dns_phase_code(value: ManualDnsTaskPhase) -> u8 {
    match value {
        ManualDnsTaskPhase::AwaitingPublication => 1,
        ManualDnsTaskPhase::PublicationObserved => 2,
        ManualDnsTaskPhase::AwaitingRemoval => 3,
        ManualDnsTaskPhase::Complete => 4,
    }
}

fn encode_checkpoint(
    encoder: &mut Encoder,
    value: &CheckpointCertificateOrder,
) -> Result<(), MetadataCommandCodecError> {
    validate_checkpoint(value)?;
    encoder.u16(CHECKPOINT_CERTIFICATE_ORDER)?;
    encode_claim_identity(
        encoder,
        value.order_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    encode_secret(encoder, value.certificate_key)?;
    encoder.bytes(
        &value.checkpoint,
        MAXIMUM_CERTIFICATE_ORDER_CHECKPOINT_BYTES,
    )
}

fn decode_checkpoint(
    decoder: &mut Decoder<'_>,
) -> Result<CheckpointCertificateOrder, MetadataCommandCodecError> {
    let identity = decode_claim_identity(decoder)?;
    let value = CheckpointCertificateOrder {
        order_id: identity.order_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        certificate_key: decode_secret(decoder)?,
        checkpoint: decoder.bytes(MAXIMUM_CERTIFICATE_ORDER_CHECKPOINT_BYTES)?,
    };
    validate_checkpoint(&value)?;
    Ok(value)
}

fn validate_checkpoint(
    value: &CheckpointCertificateOrder,
) -> Result<(), MetadataCommandCodecError> {
    if value.certificate_key.secret_id != value.order_id.as_bytes()
        || value.certificate_key.generation != 1
        || value.checkpoint.is_empty()
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let machine = meshspan_acme::AcmeOrderMachine::decode_checkpoint(&value.checkpoint)
        .map_err(|_| MetadataCommandCodecError::Invalid)?;
    if machine.order_epoch() != value.fence {
        return Err(MetadataCommandCodecError::Invalid);
    }
    Ok(())
}

fn encode_installation(
    encoder: &mut Encoder,
    value: AcknowledgePublicCertificateInstallation,
) -> Result<(), MetadataCommandCodecError> {
    validate_installation(value)?;
    encoder.u16(ACKNOWLEDGE_PUBLIC_CERTIFICATE_INSTALLATION)?;
    encoder.identifier(value.order_id.as_bytes())?;
    encoder.identifier(value.gateway_node_id.as_bytes())?;
    encoder.u64(value.gateway_incarnation)?;
    encode_secret(encoder, value.certificate)?;
    encoder.fixed(&value.bundle_digest)?;
    encoder.u64(value.observed_order_revision.get())
}

fn decode_installation(
    decoder: &mut Decoder<'_>,
) -> Result<AcknowledgePublicCertificateInstallation, MetadataCommandCodecError> {
    let value = AcknowledgePublicCertificateInstallation {
        order_id: CertificateOrderId::from_bytes(decoder.identifier()?)?,
        gateway_node_id: NodeId::from_bytes(decoder.identifier()?)?,
        gateway_incarnation: decoder.u64()?,
        certificate: decode_secret(decoder)?,
        bundle_digest: decoder.fixed()?,
        observed_order_revision: meshspan_domain::Revision::new(decoder.u64()?),
    };
    validate_installation(value)?;
    Ok(value)
}

fn validate_installation(
    value: AcknowledgePublicCertificateInstallation,
) -> Result<(), MetadataCommandCodecError> {
    if value.gateway_incarnation == 0
        || value.certificate.secret_id != value.order_id.as_bytes()
        || value.certificate.generation == 0
        || value.bundle_digest == [0; 32]
        || value.observed_order_revision == meshspan_domain::Revision::ZERO
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn encode_configure(
    encoder: &mut Encoder,
    value: &ConfigureAcme,
) -> Result<(), MetadataCommandCodecError> {
    validate_configuration(value)?;
    encoder.u16(CONFIGURE_ACME)?;
    encode_configuration_payload(encoder, value)
}

fn encode_configuration_payload(
    encoder: &mut Encoder,
    value: &ConfigureAcme,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.config_id.as_bytes())?;
    encoder.text(&value.directory_url, MAXIMUM_DIRECTORY_URL_BYTES)?;
    encode_secret(encoder, value.account_key)?;
    encoder.u8(challenge_code(value.challenge_kind))?;
    encode_optional_secret(encoder, value.challenge_settings)?;
    encoder.u16(
        u16::try_from(value.certificate_names.len())
            .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?,
    )?;
    for name in value.certificate_names.as_slice() {
        encoder.text(name, MAXIMUM_DNS_NAME_BYTES)?;
    }
    Ok(())
}

fn decode_configure(decoder: &mut Decoder<'_>) -> Result<ConfigureAcme, MetadataCommandCodecError> {
    decode_configuration_payload(decoder)
}

fn decode_configuration_payload(
    decoder: &mut Decoder<'_>,
) -> Result<ConfigureAcme, MetadataCommandCodecError> {
    let config_id = AcmeConfigurationId::from_bytes(decoder.identifier()?)?;
    let directory_url = decoder.text(MAXIMUM_DIRECTORY_URL_BYTES)?;
    let account_key = decode_secret(decoder)?;
    let challenge_kind = match decoder.u8()? {
        1 => AcmeChallengeKind::Http01,
        2 => AcmeChallengeKind::Dns01,
        _ => return Err(MetadataCommandCodecError::Invalid),
    };
    let challenge_settings = decode_optional_secret(decoder)?;
    let count = usize::from(decoder.u16()?);
    if count == 0 || count > MAXIMUM_CERTIFICATE_NAMES {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        names.push(decoder.text(MAXIMUM_DNS_NAME_BYTES)?);
    }
    let value = ConfigureAcme {
        config_id,
        directory_url,
        account_key,
        challenge_kind,
        challenge_settings,
        certificate_names: BoundedItems::new(names, MAXIMUM_CERTIFICATE_NAMES)?,
    };
    validate_configuration(&value)?;
    Ok(value)
}

fn encode_queue(
    encoder: &mut Encoder,
    value: QueueCertificateOrder,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(QUEUE_CERTIFICATE_ORDER)?;
    encode_queue_payload(encoder, value)
}

fn encode_queue_payload(
    encoder: &mut Encoder,
    value: QueueCertificateOrder,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.order_id.as_bytes())?;
    encoder.identifier(value.config_id.as_bytes())?;
    encoder.i64(value.next_attempt_at.get())
}

fn decode_queue(
    decoder: &mut Decoder<'_>,
) -> Result<QueueCertificateOrder, MetadataCommandCodecError> {
    decode_queue_payload(decoder)
}

fn decode_queue_payload(
    decoder: &mut Decoder<'_>,
) -> Result<QueueCertificateOrder, MetadataCommandCodecError> {
    Ok(QueueCertificateOrder {
        order_id: CertificateOrderId::from_bytes(decoder.identifier()?)?,
        config_id: AcmeConfigurationId::from_bytes(decoder.identifier()?)?,
        next_attempt_at: UnixMicros::new(decoder.i64()?),
    })
}

fn encode_claim(
    encoder: &mut Encoder,
    value: ClaimCertificateOrder,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(CLAIM_CERTIFICATE_ORDER)?;
    encode_claim_identity(
        encoder,
        value.order_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    encoder.i64(value.lease_expires_at.get())
}

fn decode_claim(
    decoder: &mut Decoder<'_>,
) -> Result<ClaimCertificateOrder, MetadataCommandCodecError> {
    let identity = decode_claim_identity(decoder)?;
    Ok(ClaimCertificateOrder {
        order_id: identity.order_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        lease_expires_at: UnixMicros::new(decoder.i64()?),
    })
}

fn encode_renew(
    encoder: &mut Encoder,
    value: RenewCertificateOrder,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(RENEW_CERTIFICATE_ORDER)?;
    encode_claim_identity(
        encoder,
        value.order_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    encoder.i64(value.lease_expires_at.get())
}

fn decode_renew(
    decoder: &mut Decoder<'_>,
) -> Result<RenewCertificateOrder, MetadataCommandCodecError> {
    let identity = decode_claim_identity(decoder)?;
    Ok(RenewCertificateOrder {
        order_id: identity.order_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        lease_expires_at: UnixMicros::new(decoder.i64()?),
    })
}

fn encode_complete(
    encoder: &mut Encoder,
    value: &CompleteCertificateOrder,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(COMPLETE_CERTIFICATE_ORDER)?;
    encode_claim_identity(
        encoder,
        value.order_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    match &value.outcome {
        CertificateOrderCompletion::Retry {
            failure_digest,
            retry_at,
        } => {
            nonzero_digest(*failure_digest)?;
            encoder.u8(1)?;
            encoder.fixed(failure_digest)?;
            encoder.i64(retry_at.get())
        }
        CertificateOrderCompletion::Restart {
            failure_digest,
            retry_at,
            retired_checkpoint_digest,
        } => {
            nonzero_digest(*failure_digest)?;
            nonzero_digest(*retired_checkpoint_digest)?;
            encoder.u8(3)?;
            encoder.fixed(failure_digest)?;
            encoder.i64(retry_at.get())?;
            encoder.fixed(retired_checkpoint_digest)
        }
        CertificateOrderCompletion::Issued {
            certificate,
            not_before,
            not_after,
            result_digest,
        } => {
            validate_issued(
                value.order_id,
                certificate,
                *not_before,
                *not_after,
                *result_digest,
            )?;
            encoder.u8(2)?;
            super::secret_generation::encode_payload(encoder, certificate)?;
            encoder.i64(not_before.get())?;
            encoder.i64(not_after.get())?;
            encoder.fixed(result_digest)
        }
    }
}

fn decode_complete(
    decoder: &mut Decoder<'_>,
) -> Result<CompleteCertificateOrder, MetadataCommandCodecError> {
    let identity = decode_claim_identity(decoder)?;
    let outcome = match decoder.u8()? {
        3 => CertificateOrderCompletion::Restart {
            failure_digest: nonzero_digest(decoder.fixed()?)?,
            retry_at: UnixMicros::new(decoder.i64()?),
            retired_checkpoint_digest: nonzero_digest(decoder.fixed()?)?,
        },
        1 => CertificateOrderCompletion::Retry {
            failure_digest: nonzero_digest(decoder.fixed()?)?,
            retry_at: UnixMicros::new(decoder.i64()?),
        },
        2 => {
            let certificate = Box::new(super::secret_generation::decode_payload(decoder)?);
            let not_before = UnixMicros::new(decoder.i64()?);
            let not_after = UnixMicros::new(decoder.i64()?);
            let result_digest = decoder.fixed()?;
            validate_issued(
                identity.order_id,
                &certificate,
                not_before,
                not_after,
                result_digest,
            )?;
            CertificateOrderCompletion::Issued {
                certificate,
                not_before,
                not_after,
                result_digest,
            }
        }
        _ => return Err(MetadataCommandCodecError::Invalid),
    };
    Ok(CompleteCertificateOrder {
        order_id: identity.order_id,
        claim_generation: identity.claim_generation,
        worker_node_id: identity.worker_node_id,
        worker_incarnation: identity.worker_incarnation,
        fence: identity.fence,
        outcome,
    })
}

fn validate_configuration(value: &ConfigureAcme) -> Result<(), MetadataCommandCodecError> {
    if !valid_directory_url(&value.directory_url)
        || value.account_key.generation == 0
        || value.account_key.secret_id == [0; 16]
        || value.certificate_names.is_empty()
        || value.certificate_names.len() > MAXIMUM_CERTIFICATE_NAMES
        || value
            .challenge_settings
            .is_some_and(|secret| secret.generation == 0 || secret.secret_id == [0; 16])
        || matches!(value.challenge_kind, AcmeChallengeKind::Http01)
            && value.challenge_settings.is_some()
    {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let mut previous: Option<&str> = None;
    for name in value.certificate_names.as_slice() {
        if !valid_dns_name(name) || previous.is_some_and(|prior| prior >= name.as_str()) {
            return Err(MetadataCommandCodecError::Invalid);
        }
        previous = Some(name);
    }
    Ok(())
}

fn valid_directory_url(value: &str) -> bool {
    value.starts_with("https://")
        && value.len() <= MAXIMUM_DIRECTORY_URL_BYTES
        && value.len() > "https://".len()
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        && !value.contains('#')
}

fn valid_dns_name(value: &str) -> bool {
    let name = value.strip_prefix("*.").unwrap_or(value);
    !name.is_empty()
        && value.len() <= MAXIMUM_DNS_NAME_BYTES
        && name.is_ascii()
        && name.contains('.')
        && name.split('.').all(valid_dns_label)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'*')
        })
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn challenge_code(kind: AcmeChallengeKind) -> u8 {
    match kind {
        AcmeChallengeKind::Http01 => 1,
        AcmeChallengeKind::Dns01 => 2,
    }
}

fn encode_secret(
    encoder: &mut Encoder,
    secret: SecretGenerationReference,
) -> Result<(), MetadataCommandCodecError> {
    if secret.secret_id == [0; 16] || secret.generation == 0 {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.identifier(secret.secret_id)?;
    encoder.u64(secret.generation)
}

fn decode_secret(
    decoder: &mut Decoder<'_>,
) -> Result<SecretGenerationReference, MetadataCommandCodecError> {
    let value = SecretGenerationReference {
        secret_id: decoder.identifier()?,
        generation: decoder.u64()?,
    };
    if value.secret_id == [0; 16] || value.generation == 0 {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(value)
    }
}

fn encode_optional_secret(
    encoder: &mut Encoder,
    value: Option<SecretGenerationReference>,
) -> Result<(), MetadataCommandCodecError> {
    encoder.bool(value.is_some())?;
    value.map_or(Ok(()), |secret| encode_secret(encoder, secret))
}

fn decode_optional_secret(
    decoder: &mut Decoder<'_>,
) -> Result<Option<SecretGenerationReference>, MetadataCommandCodecError> {
    if decoder.bool()? {
        decode_secret(decoder).map(Some)
    } else {
        Ok(None)
    }
}

fn validate_issued(
    order_id: CertificateOrderId,
    certificate: &crate::CommitSecretGeneration,
    not_before: UnixMicros,
    not_after: UnixMicros,
    digest: [u8; 32],
) -> Result<(), MetadataCommandCodecError> {
    if certificate.secret.context.kind() != PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND
        || certificate.secret.context.id() != order_id.as_bytes()
        || certificate.secret.context.generation() != 1
        || not_after <= not_before
        || digest == [0; 32]
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn nonzero_digest(value: [u8; 32]) -> Result<[u8; 32], MetadataCommandCodecError> {
    if value == [0; 32] {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(value)
    }
}

struct ClaimIdentity {
    order_id: CertificateOrderId,
    claim_generation: u64,
    worker_node_id: NodeId,
    worker_incarnation: u64,
    fence: u64,
}

fn encode_claim_identity(
    encoder: &mut Encoder,
    order_id: CertificateOrderId,
    claim_generation: u64,
    worker_node_id: NodeId,
    worker_incarnation: u64,
    fence: u64,
) -> Result<(), MetadataCommandCodecError> {
    if claim_generation == 0 || worker_incarnation == 0 || fence == 0 {
        return Err(MetadataCommandCodecError::Invalid);
    }
    encoder.identifier(order_id.as_bytes())?;
    encoder.u64(claim_generation)?;
    encoder.identifier(worker_node_id.as_bytes())?;
    encoder.u64(worker_incarnation)?;
    encoder.u64(fence)
}

fn decode_claim_identity(
    decoder: &mut Decoder<'_>,
) -> Result<ClaimIdentity, MetadataCommandCodecError> {
    let value = ClaimIdentity {
        order_id: CertificateOrderId::from_bytes(decoder.identifier()?)?,
        claim_generation: decoder.u64()?,
        worker_node_id: NodeId::from_bytes(decoder.identifier()?)?,
        worker_incarnation: decoder.u64()?,
        fence: decoder.u64()?,
    };
    if value.claim_generation == 0 || value.worker_incarnation == 0 || value.fence == 0 {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(value)
    }
}
