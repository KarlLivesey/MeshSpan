// SPDX-License-Identifier: GPL-2.0-only

use meshspan_secret_envelope::{
    EncryptedSecret, EncryptedSecretParts, MAXIMUM_SECRET_BYTES, MAXIMUM_SECRET_RECIPIENTS,
    RecipientEnvelopeParts, RecipientKeyEnvelope, SecretContext,
};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::CommitSecretGeneration;

pub(super) const COMMIT_SECRET_GENERATION: u16 = 14;
const MAXIMUM_CIPHERTEXT_BYTES: usize = MAXIMUM_SECRET_BYTES + 16;
const WRAPPED_KEY_CIPHERTEXT_BYTES: usize = 48;

pub(super) fn encode(
    encoder: &mut Encoder,
    value: &CommitSecretGeneration,
) -> Result<(), MetadataCommandCodecError> {
    validate(value)?;
    encoder.u16(COMMIT_SECRET_GENERATION)?;
    encode_secret(encoder, &value.secret)?;
    encoder.u64(
        u64::try_from(value.recipients.len())
            .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?,
    )?;
    for recipient in &value.recipients {
        encode_recipient(encoder, recipient)?;
    }
    Ok(())
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<CommitSecretGeneration, MetadataCommandCodecError> {
    let secret = decode_secret(decoder)?;
    let count =
        usize::try_from(decoder.u64()?).map_err(|_| MetadataCommandCodecError::CapacityExceeded)?;
    if count == 0 || count > MAXIMUM_SECRET_RECIPIENTS {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut recipients = Vec::with_capacity(count);
    for _ in 0..count {
        recipients.push(decode_recipient(decoder)?);
    }
    let value = CommitSecretGeneration { secret, recipients };
    validate(&value)?;
    Ok(value)
}

pub(super) fn validate(value: &CommitSecretGeneration) -> Result<(), MetadataCommandCodecError> {
    EncryptedSecret::from_parts(value.secret.clone())
        .map_err(|_| MetadataCommandCodecError::Invalid)?;
    if value.recipients.is_empty() || value.recipients.len() > MAXIMUM_SECRET_RECIPIENTS {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut previous = None;
    for recipient in &value.recipients {
        let envelope = RecipientKeyEnvelope::from_parts(recipient.clone())
            .map_err(|_| MetadataCommandCodecError::Invalid)?;
        if envelope.context() != value.secret.context {
            return Err(MetadataCommandCodecError::Invalid);
        }
        let fingerprint = envelope
            .recipient_fingerprint()
            .map_err(|_| MetadataCommandCodecError::Invalid)?;
        if previous.is_some_and(|prior| prior >= fingerprint) {
            return Err(MetadataCommandCodecError::Invalid);
        }
        previous = Some(fingerprint);
    }
    Ok(())
}

fn encode_secret(
    encoder: &mut Encoder,
    secret: &EncryptedSecretParts,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u8(secret.format_version)?;
    encode_context(encoder, secret.context)?;
    encoder.fixed(&secret.nonce)?;
    encoder.bytes(&secret.ciphertext, MAXIMUM_CIPHERTEXT_BYTES)?;
    encoder.fixed(&secret.digest)
}

fn decode_secret(
    decoder: &mut Decoder<'_>,
) -> Result<EncryptedSecretParts, MetadataCommandCodecError> {
    Ok(EncryptedSecretParts {
        format_version: decoder.u8()?,
        context: decode_context(decoder)?,
        nonce: decoder.fixed()?,
        ciphertext: decoder.bytes(MAXIMUM_CIPHERTEXT_BYTES)?,
        digest: decoder.fixed()?,
    })
}

fn encode_recipient(
    encoder: &mut Encoder,
    recipient: &RecipientEnvelopeParts,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u8(recipient.format_version)?;
    encode_context(encoder, recipient.context)?;
    encoder.fixed(&recipient.recipient_public_key)?;
    encoder.fixed(&recipient.ephemeral_public_key)?;
    encoder.fixed(&recipient.salt)?;
    encoder.fixed(&recipient.nonce)?;
    encoder.bytes(&recipient.ciphertext, WRAPPED_KEY_CIPHERTEXT_BYTES)?;
    encoder.fixed(&recipient.digest)
}

fn decode_recipient(
    decoder: &mut Decoder<'_>,
) -> Result<RecipientEnvelopeParts, MetadataCommandCodecError> {
    Ok(RecipientEnvelopeParts {
        format_version: decoder.u8()?,
        context: decode_context(decoder)?,
        recipient_public_key: decoder.fixed()?,
        ephemeral_public_key: decoder.fixed()?,
        salt: decoder.fixed()?,
        nonce: decoder.fixed()?,
        ciphertext: decoder.bytes(WRAPPED_KEY_CIPHERTEXT_BYTES)?,
        digest: decoder.fixed()?,
    })
}

fn encode_context(
    encoder: &mut Encoder,
    context: SecretContext,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(context.kind())?;
    encoder.identifier(context.id())?;
    encoder.u64(context.generation())
}

fn decode_context(decoder: &mut Decoder<'_>) -> Result<SecretContext, MetadataCommandCodecError> {
    SecretContext::new(decoder.u16()?, decoder.identifier()?, decoder.u64()?)
        .map_err(|_| MetadataCommandCodecError::Invalid)
}
