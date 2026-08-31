// SPDX-License-Identifier: GPL-2.0-only

//! Canonical TOTP registration models, bindings and authority command construction.

use meshspan_api_contract::{
    AuthenticationMethodId as PublicMethodId, CreateTotpRegistrationChallengeRequest,
    CreateTotpRegistrationChallengeResponse, CreateTotpRegistrationRequest,
    CreateTotpRegistrationResponse, TotpRegistrationAlgorithm, TotpRegistrationChallengeId,
};
use meshspan_domain::{
    AuditEventId, AuthenticationChallengeId, AuthenticationService, OperationId, RandomSource,
    UnixMicros,
};
use meshspan_metadata::{
    AuthenticationCeremonyRecord, AuthoritativeCommand, CommandContext, CreateAuthenticationMethod,
    NewAuthenticationCredential, SessionAccessCapability, TotpAlgorithm,
};
use sha2::{Digest, Sha256};

use crate::create_mesh_setup::parse_uuid;
use crate::totp_registration_state::{FrozenTotpRegistrationState, TotpRegistrationBinding};
use crate::{TotpRegistrationCommit, TotpRegistrationConfiguration, TotpRegistrationError};

pub(crate) const SECRET_BYTES: usize = 20;
pub(crate) const ALGORITHM_CODE: u8 = 1;
pub(crate) const DIGITS: u8 = 6;
pub(crate) const PERIOD_SECONDS: u16 = 30;
pub(crate) const ACCEPTED_STEP_WINDOW: u8 = 1;
const MINIMUM_LIFETIME_MICROS: u64 = 30_000_000;

pub(crate) fn challenge_response(
    request: &CreateTotpRegistrationChallengeRequest,
    challenge_id: AuthenticationChallengeId,
    expires_at: UnixMicros,
    state: &FrozenTotpRegistrationState,
) -> Result<CreateTotpRegistrationChallengeResponse, TotpRegistrationError> {
    let secret = encode_base32(state.secret.as_ref());
    let account = percent_encode(&state.account_name);
    let issuer = percent_encode(&state.issuer);
    let provisioning_uri = format!(
        "otpauth://totp/{issuer}%3A{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    );
    Ok(CreateTotpRegistrationChallengeResponse {
        operation_id: request.operation_id.clone(),
        challenge_id: TotpRegistrationChallengeId::from_uuid_bytes(challenge_id.as_bytes())
            .ok_or(TotpRegistrationError::InvalidReceipt)?,
        secret,
        provisioning_uri,
        algorithm: TotpRegistrationAlgorithm::Sha1,
        digits: DIGITS,
        period_seconds: PERIOD_SECONDS,
        expires_at_epoch_micros: expires_at.get(),
    })
}

pub(crate) fn registration_command(state: &FrozenTotpRegistrationState) -> AuthoritativeCommand {
    AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
        method_id: state.method_id,
        principal_id: state.principal_id,
        label: state.label.clone(),
        service_scope: AuthenticationService::Https.scope_bit()
            | AuthenticationService::HeadlessApi.scope_bit(),
        expires_at: None,
        credential: NewAuthenticationCredential::Totp {
            secret_ciphertext: state.secret_ciphertext.clone(),
            algorithm: TotpAlgorithm::Sha1,
            digits: state.digits,
            period_seconds: state.period_seconds,
            accepted_step_window: state.accepted_step_window,
        },
    })
}

pub(crate) fn registration_response(
    request: &CreateTotpRegistrationRequest,
    commit: TotpRegistrationCommit,
) -> Result<CreateTotpRegistrationResponse, TotpRegistrationError> {
    Ok(CreateTotpRegistrationResponse {
        operation_id: request.operation_id.clone(),
        method_id: PublicMethodId::from_uuid_bytes(commit.method_id.as_bytes())
            .ok_or(TotpRegistrationError::InvalidReceipt)?,
        created_at_epoch_micros: commit.created_at.get(),
    })
}

pub(crate) fn validate_commit(
    state: &FrozenTotpRegistrationState,
    record: &AuthenticationCeremonyRecord,
    commit: TotpRegistrationCommit,
    expected_request_digest: [u8; 32],
) -> Result<(), TotpRegistrationError> {
    if commit.request_digest != expected_request_digest
        || commit.result_digest == [0; 32]
        || commit.method_id != state.method_id
        || commit.principal_id != state.principal_id
        || commit.created_at < record.created_at
        || record
            .authority_result_digest
            .is_some_and(|digest| digest != commit.result_digest)
    {
        Err(TotpRegistrationError::Conflict)
    } else {
        Ok(())
    }
}

pub(crate) fn require_capability(
    state: &FrozenTotpRegistrationState,
    capability: SessionAccessCapability,
) -> Result<(), TotpRegistrationError> {
    if state.principal_id != capability.principal_id
        || state.session_id != capability.session_id
        || state.identity_revision != capability.identity_revision
        || state.capability_digest != capability.capability_digest
    {
        Err(TotpRegistrationError::Rejected)
    } else {
        Ok(())
    }
}

pub(crate) fn challenge_expiry(
    now: UnixMicros,
    session_expiry: UnixMicros,
    configuration: &TotpRegistrationConfiguration,
) -> Result<UnixMicros, TotpRegistrationError> {
    let configured = now
        .checked_add(configuration.lifetime())
        .ok_or(TotpRegistrationError::InvalidTime)?;
    let expires_at = configured.min(session_expiry);
    let remaining = expires_at
        .get()
        .checked_sub(now.get())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(TotpRegistrationError::InvalidTime)?;
    if remaining < MINIMUM_LIFETIME_MICROS {
        Err(TotpRegistrationError::Rejected)
    } else {
        Ok(expires_at)
    }
}

pub(crate) fn challenge_request_digest(
    state: &FrozenTotpRegistrationState,
    configuration: &TotpRegistrationConfiguration,
) -> Result<[u8; 32], TotpRegistrationError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.authentication.totp-registration-challenge.v1\0");
    digest.update(configuration.digest()?);
    digest.update(state.principal_id.as_bytes());
    digest.update(state.session_id.as_bytes());
    digest.update(state.identity_revision.get().to_be_bytes());
    digest.update(state.capability_digest);
    digest.update(state.method_id.as_bytes());
    digest_text(&mut digest, &state.label)?;
    digest_text(&mut digest, &state.account_name)?;
    digest_text(&mut digest, &state.issuer)?;
    digest.update([state.algorithm, state.digits, state.accepted_step_window]);
    digest.update(state.period_seconds.to_be_bytes());
    digest_bytes(&mut digest, &state.secret_ciphertext)?;
    Ok(digest.finalize().into())
}

pub(crate) fn registration_response_digest(
    request: &CreateTotpRegistrationRequest,
) -> Result<[u8; 32], TotpRegistrationError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.authentication.totp-registration-response.v1\0");
    digest_text(&mut digest, &request.code)?;
    Ok(digest.finalize().into())
}

pub(crate) fn registration_context(
    operation_id: OperationId,
    state: &FrozenTotpRegistrationState,
    occurred_at: UnixMicros,
) -> Result<CommandContext, TotpRegistrationError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.authentication.totp-registration-audit-id.v1\0");
    digest.update(operation_id.as_bytes());
    digest.update(state.method_id.as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| TotpRegistrationError::InvalidReceipt)?;
    version_uuid(&mut bytes);
    Ok(CommandContext {
        operation_id,
        actor_principal_id: state.principal_id,
        audit_event_id: AuditEventId::from_bytes(bytes)
            .map_err(|_| TotpRegistrationError::InvalidReceipt)?,
        occurred_at,
        expected_revision: None,
    })
}

pub(crate) fn binding(record: &AuthenticationCeremonyRecord) -> TotpRegistrationBinding {
    TotpRegistrationBinding {
        challenge_id: record.challenge_id,
        creation_operation_id: record.creation_operation_id,
        request_digest: record.request_digest,
        created_at: record.created_at,
        expires_at: record.expires_at,
    }
}

pub(crate) fn parse_operation(value: &str) -> Result<OperationId, TotpRegistrationError> {
    OperationId::from_bytes(parse_uuid(value).map_err(|_| TotpRegistrationError::InvalidRequest)?)
        .map_err(|_| TotpRegistrationError::InvalidRequest)
}

pub(crate) fn parse_challenge(
    value: &str,
) -> Result<AuthenticationChallengeId, TotpRegistrationError> {
    AuthenticationChallengeId::from_bytes(
        parse_uuid(value).map_err(|_| TotpRegistrationError::InvalidRequest)?,
    )
    .map_err(|_| TotpRegistrationError::InvalidRequest)
}

pub(crate) fn random_uuid(
    random: &mut impl RandomSource,
) -> Result<[u8; 16], TotpRegistrationError> {
    let mut bytes = random_nonzero(random)?;
    version_uuid(&mut bytes);
    Ok(bytes)
}

pub(crate) fn random_nonzero<const N: usize>(
    random: &mut impl RandomSource,
) -> Result<[u8; N], TotpRegistrationError> {
    let mut bytes = [0_u8; N];
    random
        .fill_bytes(&mut bytes)
        .map_err(|_| TotpRegistrationError::Unavailable)?;
    if bytes == [0; N] {
        Err(TotpRegistrationError::Unavailable)
    } else {
        Ok(bytes)
    }
}

fn encode_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut buffer = 0_u16;
    let mut bits = 0_u8;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits -= 5;
            output.push(char::from(ALPHABET[usize::from((buffer >> bits) & 0x1f)]));
        }
    }
    if bits != 0 {
        output.push(char::from(
            ALPHABET[usize::from((buffer << (5 - bits)) & 0x1f)],
        ));
    }
    output
}

fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    output
}

fn digest_text(digest: &mut Sha256, value: &str) -> Result<(), TotpRegistrationError> {
    digest_bytes(digest, value.as_bytes())
}

fn digest_bytes(digest: &mut Sha256, value: &[u8]) -> Result<(), TotpRegistrationError> {
    digest.update(
        u32::try_from(value.len())
            .map_err(|_| TotpRegistrationError::InvalidRequest)?
            .to_be_bytes(),
    );
    digest.update(value);
    Ok(())
}

const fn version_uuid(bytes: &mut [u8; 16]) {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
}

#[cfg(test)]
mod tests {
    use super::{encode_base32, percent_encode};

    #[test]
    fn provisioning_encoders_are_canonical() {
        assert_eq!(encode_base32(b"Hello!\xde\xad\xbe\xef"), "JBSWY3DPEHPK3PXP");
        assert_eq!(
            percent_encode("Mesh Span:admin@example.test"),
            "Mesh%20Span%3Aadmin%40example.test"
        );
    }
}
