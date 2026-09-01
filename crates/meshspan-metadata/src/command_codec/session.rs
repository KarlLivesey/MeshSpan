// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ApiKeyId, AuthenticationMethodId, AuthenticationService, PrincipalId, RecoveryCodeId, Revision,
    SessionId, UnixMicros,
};

use super::MetadataCommandCodecError;
use super::decoder::Decoder;
use super::encoder::Encoder;
use crate::{
    IssueAuthenticationSession, RevokeAuthenticationMethod, RevokeAuthenticationSession,
    SessionAuthenticationFactor, SessionClientLabel, StepUpAuthenticationSession,
};

const ISSUE_SESSION: u16 = 7;
const STEP_UP_SESSION: u16 = 8;
const REVOKE_SESSION: u16 = 9;
const REVOKE_METHOD: u16 = 10;
const PASSKEY: u8 = 1;
const TOTP: u8 = 2;
const RECOVERY_CODE: u8 = 3;
const API_KEY: u8 = 4;
const MAXIMUM_FACTORS: usize = 8;
const MAXIMUM_LABEL_BYTES: usize = 256;
const MAXIMUM_CREDENTIAL_ID_BYTES: usize = 256 * 1024;
const MAXIMUM_REASON_BYTES: usize = 4096;

pub(super) fn encode_issue(
    encoder: &mut Encoder,
    value: &IssueAuthenticationSession,
) -> Result<(), MetadataCommandCodecError> {
    if value.factors.is_empty() || value.factors.len() > MAXIMUM_FACTORS {
        return Err(MetadataCommandCodecError::CapacityExceeded);
    }
    encoder.u16(ISSUE_SESSION)?;
    encoder.identifier(value.session_id.as_bytes())?;
    encoder.identifier(value.principal_id.as_bytes())?;
    encoder.fixed(&value.token_digest)?;
    encoder.fixed(&value.csrf_digest)?;
    encode_client_label(encoder, &value.client_label)?;
    encoder.bool(value.persistent_cookie)?;
    encoder.u8(value.service as u8)?;
    encoder.u8(u8::try_from(value.factors.len())
        .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?)?;
    for factor in value.factors.as_slice() {
        encode_factor(encoder, factor)?;
    }
    encoder.i64(value.expires_at.get())
}

pub(super) fn decode_issue(
    decoder: &mut Decoder<'_>,
) -> Result<IssueAuthenticationSession, MetadataCommandCodecError> {
    let session_id = SessionId::from_bytes(decoder.identifier()?)?;
    let principal_id = PrincipalId::from_bytes(decoder.identifier()?)?;
    let token_digest = decoder.fixed()?;
    let csrf_digest = decoder.fixed()?;
    let client_label = decode_client_label(decoder)?;
    let persistent_cookie = decoder.bool()?;
    let service = decode_service(decoder.u8()?)?;
    let count = usize::from(decoder.u8()?);
    if count == 0 || count > MAXIMUM_FACTORS {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let mut factors = Vec::with_capacity(count);
    for _ in 0..count {
        factors.push(decode_factor(decoder)?);
    }
    Ok(IssueAuthenticationSession {
        session_id,
        principal_id,
        token_digest,
        csrf_digest,
        client_label,
        persistent_cookie,
        service,
        factors: BoundedItems::new(factors, MAXIMUM_FACTORS)?,
        expires_at: UnixMicros::new(decoder.i64()?),
    })
}

pub(super) fn encode_step_up(
    encoder: &mut Encoder,
    value: &StepUpAuthenticationSession,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(STEP_UP_SESSION)?;
    encoder.identifier(value.source_session_id.as_bytes())?;
    encoder.identifier(value.replacement_session_id.as_bytes())?;
    encoder.identifier(value.principal_id.as_bytes())?;
    encoder.fixed(&value.token_digest)?;
    encoder.fixed(&value.csrf_digest)?;
    encode_factor(encoder, &value.additional_factor)?;
    encoder.i64(value.expires_at.get())
}

pub(super) fn decode_step_up(
    decoder: &mut Decoder<'_>,
) -> Result<StepUpAuthenticationSession, MetadataCommandCodecError> {
    Ok(StepUpAuthenticationSession {
        source_session_id: SessionId::from_bytes(decoder.identifier()?)?,
        replacement_session_id: SessionId::from_bytes(decoder.identifier()?)?,
        principal_id: PrincipalId::from_bytes(decoder.identifier()?)?,
        token_digest: decoder.fixed()?,
        csrf_digest: decoder.fixed()?,
        additional_factor: decode_factor(decoder)?,
        expires_at: UnixMicros::new(decoder.i64()?),
    })
}

pub(super) fn encode_revoke_session(
    encoder: &mut Encoder,
    value: &RevokeAuthenticationSession,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(REVOKE_SESSION)?;
    encoder.identifier(value.session_id.as_bytes())?;
    encoder.identifier(value.principal_id.as_bytes())
}

pub(super) fn decode_revoke_session(
    decoder: &mut Decoder<'_>,
) -> Result<RevokeAuthenticationSession, MetadataCommandCodecError> {
    Ok(RevokeAuthenticationSession {
        session_id: SessionId::from_bytes(decoder.identifier()?)?,
        principal_id: PrincipalId::from_bytes(decoder.identifier()?)?,
    })
}

pub(super) fn encode_revoke_method(
    encoder: &mut Encoder,
    value: &RevokeAuthenticationMethod,
) -> Result<(), MetadataCommandCodecError> {
    encoder.u16(REVOKE_METHOD)?;
    encoder.identifier(value.method_id.as_bytes())?;
    encoder.identifier(value.principal_id.as_bytes())?;
    encoder.text(&value.reason, MAXIMUM_REASON_BYTES)
}

pub(super) fn decode_revoke_method(
    decoder: &mut Decoder<'_>,
) -> Result<RevokeAuthenticationMethod, MetadataCommandCodecError> {
    Ok(RevokeAuthenticationMethod {
        method_id: AuthenticationMethodId::from_bytes(decoder.identifier()?)?,
        principal_id: PrincipalId::from_bytes(decoder.identifier()?)?,
        reason: decoder.text(MAXIMUM_REASON_BYTES)?,
    })
}

fn encode_client_label(
    encoder: &mut Encoder,
    label: &SessionClientLabel,
) -> Result<(), MetadataCommandCodecError> {
    match label {
        SessionClientLabel::Missing => encoder.u8(0),
        SessionClientLabel::Null => encoder.u8(1),
        SessionClientLabel::Value(value) => {
            encoder.u8(2)?;
            encoder.text(value, MAXIMUM_LABEL_BYTES)
        }
    }
}

fn decode_client_label(
    decoder: &mut Decoder<'_>,
) -> Result<SessionClientLabel, MetadataCommandCodecError> {
    match decoder.u8()? {
        0 => Ok(SessionClientLabel::Missing),
        1 => Ok(SessionClientLabel::Null),
        2 => Ok(SessionClientLabel::Value(
            decoder.text(MAXIMUM_LABEL_BYTES)?,
        )),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}

fn encode_factor(
    encoder: &mut Encoder,
    factor: &SessionAuthenticationFactor,
) -> Result<(), MetadataCommandCodecError> {
    let (kind, method_id, generation, revision) = match factor {
        SessionAuthenticationFactor::Passkey {
            method_id,
            credential_generation,
            method_revision,
            ..
        } => (PASSKEY, method_id, credential_generation, method_revision),
        SessionAuthenticationFactor::Totp {
            method_id,
            credential_generation,
            method_revision,
            ..
        } => (TOTP, method_id, credential_generation, method_revision),
        SessionAuthenticationFactor::RecoveryCode {
            method_id,
            credential_generation,
            method_revision,
            ..
        } => (
            RECOVERY_CODE,
            method_id,
            credential_generation,
            method_revision,
        ),
        SessionAuthenticationFactor::ApiKey {
            method_id,
            credential_generation,
            method_revision,
            ..
        } => (API_KEY, method_id, credential_generation, method_revision),
    };
    encoder.u8(kind)?;
    encoder.identifier(method_id.as_bytes())?;
    encoder.u64(*generation)?;
    encoder.u64(revision.get())?;
    match factor {
        SessionAuthenticationFactor::Passkey {
            credential_id,
            signature_counter,
            backup_state,
            ..
        } => {
            encoder.bytes(credential_id, MAXIMUM_CREDENTIAL_ID_BYTES)?;
            encoder.u64(*signature_counter)?;
            encoder.bool(*backup_state)
        }
        SessionAuthenticationFactor::Totp { accepted_step, .. } => encoder.u64(*accepted_step),
        SessionAuthenticationFactor::RecoveryCode { code_id, .. } => {
            encoder.identifier(code_id.as_bytes())
        }
        SessionAuthenticationFactor::ApiKey { key_id, .. } => encoder.identifier(key_id.as_bytes()),
    }
}

fn decode_factor(
    decoder: &mut Decoder<'_>,
) -> Result<SessionAuthenticationFactor, MetadataCommandCodecError> {
    let kind = decoder.u8()?;
    let method_id = AuthenticationMethodId::from_bytes(decoder.identifier()?)?;
    let credential_generation = decoder.u64()?;
    let method_revision = Revision::new(decoder.u64()?);
    match kind {
        PASSKEY => Ok(SessionAuthenticationFactor::Passkey {
            method_id,
            credential_generation,
            method_revision,
            credential_id: decoder.bytes(MAXIMUM_CREDENTIAL_ID_BYTES)?,
            signature_counter: decoder.u64()?,
            backup_state: decoder.bool()?,
        }),
        TOTP => Ok(SessionAuthenticationFactor::Totp {
            method_id,
            credential_generation,
            method_revision,
            accepted_step: decoder.u64()?,
        }),
        RECOVERY_CODE => Ok(SessionAuthenticationFactor::RecoveryCode {
            method_id,
            credential_generation,
            method_revision,
            code_id: RecoveryCodeId::from_bytes(decoder.identifier()?)?,
        }),
        API_KEY => Ok(SessionAuthenticationFactor::ApiKey {
            method_id,
            credential_generation,
            method_revision,
            key_id: ApiKeyId::from_bytes(decoder.identifier()?)?,
        }),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}

fn decode_service(value: u8) -> Result<AuthenticationService, MetadataCommandCodecError> {
    match value {
        1 => Ok(AuthenticationService::Https),
        2 => Ok(AuthenticationService::HeadlessApi),
        4 => Ok(AuthenticationService::Smb),
        _ => Err(MetadataCommandCodecError::Invalid),
    }
}
