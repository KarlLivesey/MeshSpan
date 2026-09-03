// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{AcmeConfigurationId, CertificateOrderId, NodeId, UnixMicros};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    AcmeChallengeKind, CertificateOrderCompletion, ClaimCertificateOrder, CompleteCertificateOrder,
    ConfigureAcme, PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, QueueCertificateOrder,
    RenewCertificateOrder, SecretGenerationReference,
};

pub(super) const CONFIGURE_ACME: u16 = 49;
pub(super) const QUEUE_CERTIFICATE_ORDER: u16 = 50;
pub(super) const CLAIM_CERTIFICATE_ORDER: u16 = 51;
pub(super) const RENEW_CERTIFICATE_ORDER: u16 = 52;
pub(super) const COMPLETE_CERTIFICATE_ORDER: u16 = 53;

const MAXIMUM_DIRECTORY_URL_BYTES: usize = 2_048;
const MAXIMUM_CERTIFICATE_NAMES: usize = 256;
const MAXIMUM_DNS_NAME_BYTES: usize = 253;

pub(super) fn encode_command(
    encoder: &mut Encoder,
    command: &crate::AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        crate::AuthoritativeCommand::ConfigureAcme(value) => encode_configure(encoder, value)?,
        crate::AuthoritativeCommand::QueueCertificateOrder(value) => encode_queue(encoder, *value)?,
        crate::AuthoritativeCommand::ClaimCertificateOrder(value) => encode_claim(encoder, *value)?,
        crate::AuthoritativeCommand::RenewCertificateOrder(value) => encode_renew(encoder, *value)?,
        crate::AuthoritativeCommand::CompleteCertificateOrder(value) => {
            encode_complete(encoder, value)?;
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
    )
}

pub(super) fn decode_command(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<crate::AuthoritativeCommand, MetadataCommandCodecError> {
    match kind {
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
        COMPLETE_CERTIFICATE_ORDER => {
            decode_complete(decoder).map(crate::AuthoritativeCommand::CompleteCertificateOrder)
        }
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}

fn encode_configure(
    encoder: &mut Encoder,
    value: &ConfigureAcme,
) -> Result<(), MetadataCommandCodecError> {
    validate_configuration(value)?;
    encoder.u16(CONFIGURE_ACME)?;
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
    encoder.identifier(value.order_id.as_bytes())?;
    encoder.identifier(value.config_id.as_bytes())?;
    encoder.i64(value.next_attempt_at.get())
}

fn decode_queue(
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
