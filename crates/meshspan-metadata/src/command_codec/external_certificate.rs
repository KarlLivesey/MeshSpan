// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ExternalCertificatePublicationId, NodeId, PublicCertificateId, Revision, UnixMicros,
};

use super::decoder::Decoder;
use super::encoder::Encoder;
use super::{MetadataCommandCodecError, secret_generation};
use crate::{
    AcknowledgeExternalCertificateInstallation, MAXIMUM_EXTERNAL_CERTIFICATE_NAMES,
    PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, PublishExternalCertificate, SecretGenerationReference,
};

pub(super) const PUBLISH_EXTERNAL_CERTIFICATE: u16 = 58;
pub(super) const ACKNOWLEDGE_EXTERNAL_CERTIFICATE_INSTALLATION: u16 = 59;
const MAXIMUM_DNS_NAME_BYTES: usize = 253;

pub(super) fn encode_command(
    encoder: &mut Encoder,
    command: &crate::AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        crate::AuthoritativeCommand::PublishExternalCertificate(value) => {
            validate_publication(value)?;
            encoder.u16(PUBLISH_EXTERNAL_CERTIFICATE)?;
            encoder.identifier(value.publication_id.as_bytes())?;
            encoder.identifier(value.certificate_id.as_bytes())?;
            encoder.u64(value.generation)?;
            encoder.u16(
                u16::try_from(value.certificate_names.len())
                    .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?,
            )?;
            for name in value.certificate_names.as_slice() {
                encoder.text(name, MAXIMUM_DNS_NAME_BYTES)?;
            }
            secret_generation::encode_payload(encoder, &value.certificate)?;
            encoder.fixed(&value.bundle_digest)?;
            encoder.fixed(&value.chain_digest)?;
            encoder.fixed(&value.public_key_fingerprint)?;
            encoder.i64(value.not_before.get())?;
            encoder.i64(value.not_after.get())?;
        }
        crate::AuthoritativeCommand::AcknowledgeExternalCertificateInstallation(value) => {
            validate_installation(*value)?;
            encoder.u16(ACKNOWLEDGE_EXTERNAL_CERTIFICATE_INSTALLATION)?;
            encoder.identifier(value.publication_id.as_bytes())?;
            encoder.identifier(value.gateway_node_id.as_bytes())?;
            encoder.u64(value.gateway_incarnation)?;
            encoder.identifier(value.certificate.secret_id)?;
            encoder.u64(value.certificate.generation)?;
            encoder.fixed(&value.bundle_digest)?;
            encoder.u64(value.observed_publication_revision.get())?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub(super) const fn is_command_kind(kind: u16) -> bool {
    matches!(
        kind,
        PUBLISH_EXTERNAL_CERTIFICATE | ACKNOWLEDGE_EXTERNAL_CERTIFICATE_INSTALLATION
    )
}

pub(super) fn decode_command(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<crate::AuthoritativeCommand, MetadataCommandCodecError> {
    match kind {
        PUBLISH_EXTERNAL_CERTIFICATE => decode_publication(decoder)
            .map(Box::new)
            .map(crate::AuthoritativeCommand::PublishExternalCertificate),
        ACKNOWLEDGE_EXTERNAL_CERTIFICATE_INSTALLATION => decode_installation(decoder)
            .map(crate::AuthoritativeCommand::AcknowledgeExternalCertificateInstallation),
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}

fn decode_publication(
    decoder: &mut Decoder<'_>,
) -> Result<PublishExternalCertificate, MetadataCommandCodecError> {
    let publication_id = ExternalCertificatePublicationId::from_bytes(decoder.identifier()?)?;
    let certificate_id = PublicCertificateId::from_bytes(decoder.identifier()?)?;
    let generation = decoder.u64()?;
    let count = usize::from(decoder.u16()?);
    if count == 0 || count > MAXIMUM_EXTERNAL_CERTIFICATE_NAMES {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        names.push(decoder.text(MAXIMUM_DNS_NAME_BYTES)?);
    }
    let value = PublishExternalCertificate {
        publication_id,
        certificate_id,
        generation,
        certificate_names: BoundedItems::new(names, MAXIMUM_EXTERNAL_CERTIFICATE_NAMES)?,
        certificate: Box::new(secret_generation::decode_payload(decoder)?),
        bundle_digest: decoder.fixed()?,
        chain_digest: decoder.fixed()?,
        public_key_fingerprint: decoder.fixed()?,
        not_before: UnixMicros::new(decoder.i64()?),
        not_after: UnixMicros::new(decoder.i64()?),
    };
    validate_publication(&value)?;
    Ok(value)
}

fn decode_installation(
    decoder: &mut Decoder<'_>,
) -> Result<AcknowledgeExternalCertificateInstallation, MetadataCommandCodecError> {
    let value = AcknowledgeExternalCertificateInstallation {
        publication_id: ExternalCertificatePublicationId::from_bytes(decoder.identifier()?)?,
        gateway_node_id: NodeId::from_bytes(decoder.identifier()?)?,
        gateway_incarnation: decoder.u64()?,
        certificate: SecretGenerationReference {
            secret_id: decoder.identifier()?,
            generation: decoder.u64()?,
        },
        bundle_digest: decoder.fixed()?,
        observed_publication_revision: Revision::new(decoder.u64()?),
    };
    validate_installation(value)?;
    Ok(value)
}

fn validate_publication(
    value: &PublishExternalCertificate,
) -> Result<(), MetadataCommandCodecError> {
    secret_generation::validate(&value.certificate)?;
    let secret_context = value.certificate.secret.context;
    if value.generation == 0
        || value.certificate_names.is_empty()
        || value.certificate_names.len() > MAXIMUM_EXTERNAL_CERTIFICATE_NAMES
        || secret_context.kind() != PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND
        || secret_context.id() != value.certificate_id.as_bytes()
        || secret_context.generation() != value.generation
        || value.bundle_digest == [0; 32]
        || value.chain_digest == [0; 32]
        || value.public_key_fingerprint == [0; 32]
        || value.not_before.get() < 0
        || value.not_after <= value.not_before
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

fn validate_installation(
    value: AcknowledgeExternalCertificateInstallation,
) -> Result<(), MetadataCommandCodecError> {
    if value.gateway_incarnation == 0
        || value.certificate.secret_id == [0; 16]
        || value.certificate.generation == 0
        || value.bundle_digest == [0; 32]
        || value.observed_publication_revision == Revision::ZERO
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
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
