// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    MeshLocalCertificateAuthorityId, MeshLocalCertificateIssuanceId, NodeId, PublicCertificateId,
    Revision, UnixMicros,
};

use super::certificate_name::{MAXIMUM_DNS_NAME_BYTES, valid_dns_name};
use super::decoder::Decoder;
use super::encoder::Encoder;
use super::{MetadataCommandCodecError, secret_generation};
use crate::{
    AcknowledgeMeshLocalCertificateInstallation, CreateMeshLocalCertificateAuthority,
    IssueMeshLocalCertificate, MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES,
    MAXIMUM_MESH_LOCAL_CERTIFICATE_NAMES, MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND,
    PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, SecretGenerationReference,
};

pub(super) const CREATE_MESH_LOCAL_CERTIFICATE_AUTHORITY: u16 = 60;
pub(super) const ISSUE_MESH_LOCAL_CERTIFICATE: u16 = 61;
pub(super) const ACKNOWLEDGE_MESH_LOCAL_CERTIFICATE_INSTALLATION: u16 = 62;

pub(super) fn encode_command(
    encoder: &mut Encoder,
    command: &crate::AuthoritativeCommand,
) -> Result<bool, MetadataCommandCodecError> {
    match command {
        crate::AuthoritativeCommand::CreateMeshLocalCertificateAuthority(value) => {
            encode_authority(encoder, value)?;
        }
        crate::AuthoritativeCommand::IssueMeshLocalCertificate(value) => {
            encode_issuance(encoder, value)?;
        }
        crate::AuthoritativeCommand::AcknowledgeMeshLocalCertificateInstallation(value) => {
            encode_installation(encoder, *value)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn encode_authority(
    encoder: &mut Encoder,
    value: &CreateMeshLocalCertificateAuthority,
) -> Result<(), MetadataCommandCodecError> {
    validate_authority(value)?;
    encoder.u16(CREATE_MESH_LOCAL_CERTIFICATE_AUTHORITY)?;
    encoder.identifier(value.authority_id.as_bytes())?;
    encoder.u64(value.generation)?;
    encoder.bytes(
        &value.certificate_der,
        MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES,
    )?;
    secret_generation::encode_payload(encoder, &value.authority_key)?;
    encoder.fixed(&value.certificate_digest)?;
    encoder.i64(value.not_before.get())?;
    encoder.i64(value.not_after.get())
}

fn encode_issuance(
    encoder: &mut Encoder,
    value: &IssueMeshLocalCertificate,
) -> Result<(), MetadataCommandCodecError> {
    validate_issuance(value)?;
    encoder.u16(ISSUE_MESH_LOCAL_CERTIFICATE)?;
    encoder.identifier(value.issuance_id.as_bytes())?;
    encoder.identifier(value.authority_id.as_bytes())?;
    encoder.u64(value.authority_generation)?;
    encoder.fixed(&value.authority_certificate_digest)?;
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
    encoder.fixed(&value.public_key_fingerprint)?;
    encoder.i64(value.not_before.get())?;
    encoder.i64(value.not_after.get())
}

fn encode_installation(
    encoder: &mut Encoder,
    value: AcknowledgeMeshLocalCertificateInstallation,
) -> Result<(), MetadataCommandCodecError> {
    validate_installation(value)?;
    encoder.u16(ACKNOWLEDGE_MESH_LOCAL_CERTIFICATE_INSTALLATION)?;
    encoder.identifier(value.issuance_id.as_bytes())?;
    encoder.identifier(value.gateway_node_id.as_bytes())?;
    encoder.u64(value.gateway_incarnation)?;
    encoder.identifier(value.certificate.secret_id)?;
    encoder.u64(value.certificate.generation)?;
    encoder.fixed(&value.bundle_digest)?;
    encoder.u64(value.observed_issuance_revision.get())
}

pub(super) const fn is_command_kind(kind: u16) -> bool {
    matches!(
        kind,
        CREATE_MESH_LOCAL_CERTIFICATE_AUTHORITY
            | ISSUE_MESH_LOCAL_CERTIFICATE
            | ACKNOWLEDGE_MESH_LOCAL_CERTIFICATE_INSTALLATION
    )
}

pub(super) fn decode_command(
    kind: u16,
    decoder: &mut Decoder<'_>,
) -> Result<crate::AuthoritativeCommand, MetadataCommandCodecError> {
    match kind {
        CREATE_MESH_LOCAL_CERTIFICATE_AUTHORITY => decode_authority(decoder)
            .map(Box::new)
            .map(crate::AuthoritativeCommand::CreateMeshLocalCertificateAuthority),
        ISSUE_MESH_LOCAL_CERTIFICATE => decode_issuance(decoder)
            .map(Box::new)
            .map(crate::AuthoritativeCommand::IssueMeshLocalCertificate),
        ACKNOWLEDGE_MESH_LOCAL_CERTIFICATE_INSTALLATION => decode_installation(decoder)
            .map(crate::AuthoritativeCommand::AcknowledgeMeshLocalCertificateInstallation),
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}

fn decode_authority(
    decoder: &mut Decoder<'_>,
) -> Result<CreateMeshLocalCertificateAuthority, MetadataCommandCodecError> {
    let value = CreateMeshLocalCertificateAuthority {
        authority_id: MeshLocalCertificateAuthorityId::from_bytes(decoder.identifier()?)?,
        generation: decoder.u64()?,
        certificate_der: decoder.bytes(MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES)?,
        authority_key: Box::new(secret_generation::decode_payload(decoder)?),
        certificate_digest: decoder.fixed()?,
        not_before: UnixMicros::new(decoder.i64()?),
        not_after: UnixMicros::new(decoder.i64()?),
    };
    validate_authority(&value)?;
    Ok(value)
}

fn decode_issuance(
    decoder: &mut Decoder<'_>,
) -> Result<IssueMeshLocalCertificate, MetadataCommandCodecError> {
    let issuance_id = MeshLocalCertificateIssuanceId::from_bytes(decoder.identifier()?)?;
    let authority_id = MeshLocalCertificateAuthorityId::from_bytes(decoder.identifier()?)?;
    let authority_generation = decoder.u64()?;
    let authority_certificate_digest = decoder.fixed()?;
    let certificate_id = PublicCertificateId::from_bytes(decoder.identifier()?)?;
    let generation = decoder.u64()?;
    let count = usize::from(decoder.u16()?);
    if count == 0 || count > MAXIMUM_MESH_LOCAL_CERTIFICATE_NAMES {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        names.push(decoder.text(MAXIMUM_DNS_NAME_BYTES)?);
    }
    let value = IssueMeshLocalCertificate {
        issuance_id,
        authority_id,
        authority_generation,
        authority_certificate_digest,
        certificate_id,
        generation,
        certificate_names: BoundedItems::new(names, MAXIMUM_MESH_LOCAL_CERTIFICATE_NAMES)?,
        certificate: Box::new(secret_generation::decode_payload(decoder)?),
        bundle_digest: decoder.fixed()?,
        public_key_fingerprint: decoder.fixed()?,
        not_before: UnixMicros::new(decoder.i64()?),
        not_after: UnixMicros::new(decoder.i64()?),
    };
    validate_issuance(&value)?;
    Ok(value)
}

fn decode_installation(
    decoder: &mut Decoder<'_>,
) -> Result<AcknowledgeMeshLocalCertificateInstallation, MetadataCommandCodecError> {
    let value = AcknowledgeMeshLocalCertificateInstallation {
        issuance_id: MeshLocalCertificateIssuanceId::from_bytes(decoder.identifier()?)?,
        gateway_node_id: NodeId::from_bytes(decoder.identifier()?)?,
        gateway_incarnation: decoder.u64()?,
        certificate: SecretGenerationReference {
            secret_id: decoder.identifier()?,
            generation: decoder.u64()?,
        },
        bundle_digest: decoder.fixed()?,
        observed_issuance_revision: Revision::new(decoder.u64()?),
    };
    validate_installation(value)?;
    Ok(value)
}

fn validate_authority(
    value: &CreateMeshLocalCertificateAuthority,
) -> Result<(), MetadataCommandCodecError> {
    secret_generation::validate(&value.authority_key)?;
    let secret_context = value.authority_key.secret.context;
    if value.generation != 1
        || value.certificate_der.is_empty()
        || value.certificate_der.len() > MAXIMUM_MESH_LOCAL_CA_CERTIFICATE_BYTES
        || value.certificate_der.first() != Some(&0x30)
        || value.certificate_digest == [0; 32]
        || value.not_before.get() < 0
        || value.not_after <= value.not_before
        || secret_context.kind() != MESH_LOCAL_CERTIFICATE_AUTHORITY_KEY_SECRET_KIND
        || secret_context.id() != value.authority_id.as_bytes()
        || secret_context.generation() != value.generation
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_issuance(value: &IssueMeshLocalCertificate) -> Result<(), MetadataCommandCodecError> {
    secret_generation::validate(&value.certificate)?;
    let secret_context = value.certificate.secret.context;
    if value.authority_generation == 0
        || value.authority_certificate_digest == [0; 32]
        || value.generation == 0
        || value.certificate_names.is_empty()
        || value.certificate_names.len() > MAXIMUM_MESH_LOCAL_CERTIFICATE_NAMES
        || secret_context.kind() != PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND
        || secret_context.id() != value.certificate_id.as_bytes()
        || secret_context.generation() != value.generation
        || value.bundle_digest == [0; 32]
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
    value: AcknowledgeMeshLocalCertificateInstallation,
) -> Result<(), MetadataCommandCodecError> {
    if value.gateway_incarnation == 0
        || value.certificate.secret_id == [0; 16]
        || value.certificate.generation == 0
        || value.bundle_digest == [0; 32]
        || value.observed_issuance_revision == Revision::ZERO
    {
        Err(MetadataCommandCodecError::Invalid)
    } else {
        Ok(())
    }
}
