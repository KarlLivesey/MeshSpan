// SPDX-License-Identifier: GPL-2.0-only

//! Offline journal framing reuses the canonical secret codec without inventing a command actor.

use super::{MetadataCommandCodecError, decoder::Decoder, encoder::Encoder, secret_generation};
use crate::{CommitSecretGeneration, RecoveryControlKeys};

const MAGIC: [u8; 7] = *b"MSRKEY\x01";
const MAXIMUM_BYTES: usize = 1024 * 1024;
const SECRET_MAGIC: [u8; 7] = *b"MSRSEC\x01";

pub(crate) fn encode(value: &RecoveryControlKeys) -> Result<Vec<u8>, MetadataCommandCodecError> {
    let mut encoder = Encoder::new(MAXIMUM_BYTES);
    encoder.fixed(&MAGIC)?;
    encoder.bytes(&value.online_certificate_der, 8192)?;
    secret_generation::encode_payload(&mut encoder, &value.online_authority_key)?;
    secret_generation::encode_payload(&mut encoder, &value.storage_permit_key)?;
    Ok(encoder.finish())
}

pub(crate) fn decode(bytes: &[u8]) -> Result<RecoveryControlKeys, MetadataCommandCodecError> {
    if bytes.len() > MAXIMUM_BYTES {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.fixed::<7>()? != MAGIC {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let value = RecoveryControlKeys {
        online_certificate_der: decoder.bytes(8192)?,
        online_authority_key: secret_generation::decode_payload(&mut decoder)?,
        storage_permit_key: secret_generation::decode_payload(&mut decoder)?,
    };
    decoder.finish()?;
    Ok(value)
}

pub(crate) fn encode_secret(
    value: &CommitSecretGeneration,
) -> Result<Vec<u8>, MetadataCommandCodecError> {
    let mut encoder = Encoder::new(MAXIMUM_BYTES);
    encoder.fixed(&SECRET_MAGIC)?;
    secret_generation::encode_payload(&mut encoder, value)?;
    Ok(encoder.finish())
}

pub(crate) fn decode_secret(
    bytes: &[u8],
) -> Result<CommitSecretGeneration, MetadataCommandCodecError> {
    if bytes.len() > MAXIMUM_BYTES {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.fixed::<7>()? != SECRET_MAGIC {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let value = secret_generation::decode_payload(&mut decoder)?;
    decoder.finish()?;
    Ok(value)
}
