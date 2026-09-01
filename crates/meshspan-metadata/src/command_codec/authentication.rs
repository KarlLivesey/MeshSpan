// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{ApiKeyId, AuthenticationMethodId, PrincipalId, RecoveryCodeId, UnixMicros};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    CreateAuthenticationMethod, NewAuthenticationCredential, NewRecoveryCode, TotpAlgorithm,
};

const CREATE_AUTHENTICATION_METHOD: u16 = 6;
const PASSKEY: u8 = 1;
const TOTP: u8 = 2;
const RECOVERY_CODES: u8 = 3;
const API_KEY: u8 = 4;
const MAXIMUM_LABEL_BYTES: usize = 256;
const MAXIMUM_CREDENTIAL_BYTES: usize = 256 * 1024;
const MAXIMUM_RECOVERY_CODES: usize = 1024;

pub(super) fn encode_create(
    encoder: &mut Encoder,
    value: &CreateAuthenticationMethod,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(CREATE_AUTHENTICATION_METHOD)?;
    encode_payload(encoder, value)
}

pub(super) fn decode_create(
    decoder: &mut Decoder<'_>,
) -> Result<CreateAuthenticationMethod, MetadataCommandCodecError> {
    decode_payload(decoder)
}

pub(super) fn encode_payload(
    encoder: &mut Encoder,
    value: &CreateAuthenticationMethod,
) -> Result<(), MetadataCommandCodecError> {
    encoder.identifier(value.method_id.as_bytes())?;
    encoder.identifier(value.principal_id.as_bytes())?;
    encoder.text(&value.label, MAXIMUM_LABEL_BYTES)?;
    encoder.u8(value.service_scope)?;
    encoder.optional_i64(value.expires_at.map(UnixMicros::get))?;
    encode_credential(encoder, &value.credential)
}

pub(super) fn decode_payload(
    decoder: &mut Decoder<'_>,
) -> Result<CreateAuthenticationMethod, MetadataCommandCodecError> {
    Ok(CreateAuthenticationMethod {
        method_id: AuthenticationMethodId::from_bytes(decoder.identifier()?)?,
        principal_id: PrincipalId::from_bytes(decoder.identifier()?)?,
        label: decoder.text(MAXIMUM_LABEL_BYTES)?,
        service_scope: decoder.u8()?,
        expires_at: decoder.optional_i64()?.map(UnixMicros::new),
        credential: decode_credential(decoder)?,
    })
}

fn encode_credential(
    encoder: &mut Encoder,
    value: &NewAuthenticationCredential,
) -> Result<(), MetadataCommandCodecError> {
    match value {
        NewAuthenticationCredential::Passkey {
            credential_id,
            public_key_algorithm,
            public_key,
            signature_counter,
            authenticator_guid,
            transports,
            backup_eligible,
            backup_state,
        } => {
            encoder.u8(PASSKEY)?;
            encoder.bytes(credential_id, MAXIMUM_CREDENTIAL_BYTES)?;
            encoder.i32(*public_key_algorithm)?;
            encoder.bytes(public_key, MAXIMUM_CREDENTIAL_BYTES)?;
            encoder.u64(*signature_counter)?;
            encoder.optional_fixed_16(*authenticator_guid)?;
            encoder.u8(*transports)?;
            encoder.bool(*backup_eligible)?;
            encoder.bool(*backup_state)
        }
        NewAuthenticationCredential::Totp {
            secret_ciphertext,
            algorithm,
            digits,
            period_seconds,
            accepted_step_window,
        } => {
            encoder.u8(TOTP)?;
            encoder.bytes(secret_ciphertext, MAXIMUM_CREDENTIAL_BYTES)?;
            encoder.u8(*algorithm as u8)?;
            encoder.u8(*digits)?;
            encoder.u16(*period_seconds)?;
            encoder.u8(*accepted_step_window)
        }
        NewAuthenticationCredential::RecoveryCodes { codes } => {
            if codes.len() > MAXIMUM_RECOVERY_CODES {
                return Err(MetadataCommandCodecError::CapacityExceeded);
            }
            encoder.u8(RECOVERY_CODES)?;
            encoder.u16(
                u16::try_from(codes.len())
                    .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?,
            )?;
            for code in codes.as_slice() {
                encoder.identifier(code.code_id.as_bytes())?;
                encoder.fixed(&code.code_digest)?;
            }
            Ok(())
        }
        NewAuthenticationCredential::ApiKey {
            key_id,
            key_digest,
            scopes,
            valid_from,
        } => {
            encoder.u8(API_KEY)?;
            encoder.identifier(key_id.as_bytes())?;
            encoder.fixed(key_digest)?;
            encoder.u64(*scopes)?;
            encoder.i64(valid_from.get())
        }
    }
}

fn decode_credential(
    decoder: &mut Decoder<'_>,
) -> Result<NewAuthenticationCredential, MetadataCommandCodecError> {
    match decoder.u8()? {
        PASSKEY => Ok(NewAuthenticationCredential::Passkey {
            credential_id: decoder.bytes(MAXIMUM_CREDENTIAL_BYTES)?,
            public_key_algorithm: decoder.i32()?,
            public_key: decoder.bytes(MAXIMUM_CREDENTIAL_BYTES)?,
            signature_counter: decoder.u64()?,
            authenticator_guid: decoder.optional_fixed_16()?,
            transports: decoder.u8()?,
            backup_eligible: decoder.bool()?,
            backup_state: decoder.bool()?,
        }),
        TOTP => Ok(NewAuthenticationCredential::Totp {
            secret_ciphertext: decoder.bytes(MAXIMUM_CREDENTIAL_BYTES)?,
            algorithm: decode_totp_algorithm(decoder.u8()?)?,
            digits: decoder.u8()?,
            period_seconds: decoder.u16()?,
            accepted_step_window: decoder.u8()?,
        }),
        RECOVERY_CODES => {
            let count = usize::from(decoder.u16()?);
            if count > MAXIMUM_RECOVERY_CODES {
                return Err(MetadataCommandCodecError::CapacityExceeded);
            }
            let mut codes = Vec::with_capacity(count);
            for _ in 0..count {
                codes.push(NewRecoveryCode {
                    code_id: RecoveryCodeId::from_bytes(decoder.identifier()?)?,
                    code_digest: decoder.fixed()?,
                });
            }
            Ok(NewAuthenticationCredential::RecoveryCodes {
                codes: BoundedItems::new(codes, MAXIMUM_RECOVERY_CODES)?,
            })
        }
        API_KEY => Ok(NewAuthenticationCredential::ApiKey {
            key_id: ApiKeyId::from_bytes(decoder.identifier()?)?,
            key_digest: decoder.fixed()?,
            scopes: decoder.u64()?,
            valid_from: UnixMicros::new(decoder.i64()?),
        }),
        _ => Err(MetadataCommandCodecError::Unsupported),
    }
}

fn decode_totp_algorithm(value: u8) -> Result<TotpAlgorithm, MetadataCommandCodecError> {
    match value {
        1 => Ok(TotpAlgorithm::Sha1),
        2 => Ok(TotpAlgorithm::Sha256),
        3 => Ok(TotpAlgorithm::Sha512),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}
