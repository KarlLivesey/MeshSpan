// SPDX-License-Identifier: GPL-2.0-only

//! Canonical public models, command construction and bindings for passkey registration.

use meshspan_api_contract::{
    AuthenticationMethodId as ApiAuthenticationMethodId, CreatePasskeyRegistrationChallengeRequest,
    CreatePasskeyRegistrationChallengeResponse, CreatePasskeyRegistrationRequest,
    CreatePasskeyRegistrationResponse, PasskeyAttestation, PasskeyChallengeId,
    PasskeyCredentialDescriptor, PasskeyCredentialParameter, PasskeyCredentialType,
    PasskeyResidentKey, PasskeyTransport, PasskeyUserVerification,
};
use meshspan_domain::{
    AuditEventId, AuthenticationChallengeId, AuthenticationMethodId, AuthenticationService,
    OperationId, RandomSource, UnixMicros,
};
use meshspan_metadata::{
    AuthenticationCeremonyRecord, AuthoritativeCommand, CommandContext, CreateAuthenticationMethod,
    NewAuthenticationCredential, SessionAccessCapability,
};
use meshspan_passkey::{RegistrationOutcome, encode_credential_id, encode_user_handle};
use sha2::{Digest, Sha256};

use crate::create_mesh_setup::parse_uuid;
use crate::passkey_challenge_configuration::{MICROS_PER_MILLISECOND, MINIMUM_LIFETIME_MICROS};
use crate::passkey_registration_state::{
    FrozenPasskeyRegistrationState, MAXIMUM_EXCLUDED_CREDENTIAL_BYTES, PasskeyRegistrationBinding,
};
use crate::{
    PasskeyRegistrationCommit, PasskeyRegistrationConfiguration, PasskeyRegistrationError,
};

pub(crate) fn challenge_response(
    request: &CreatePasskeyRegistrationChallengeRequest,
    challenge_id: AuthenticationChallengeId,
    created_at: UnixMicros,
    expires_at: UnixMicros,
    state: &FrozenPasskeyRegistrationState,
) -> Result<CreatePasskeyRegistrationChallengeResponse, PasskeyRegistrationError> {
    let lifetime = expires_at
        .get()
        .checked_sub(created_at.get())
        .and_then(|value| u32::try_from(value / i64::try_from(MICROS_PER_MILLISECOND).ok()?).ok())
        .ok_or(PasskeyRegistrationError::InvalidTime)?;
    let exclude_credentials = state
        .exclude_credential_ids
        .iter()
        .map(|credential_id| {
            Ok(PasskeyCredentialDescriptor {
                credential_type: PasskeyCredentialType::PublicKey,
                id: encode_credential_id(credential_id)
                    .map_err(|_| PasskeyRegistrationError::State)?,
            })
        })
        .collect::<Result<Vec<_>, PasskeyRegistrationError>>()?;
    Ok(CreatePasskeyRegistrationChallengeResponse {
        operation_id: request.operation_id.clone(),
        challenge_id: PasskeyChallengeId::from_uuid_bytes(challenge_id.as_bytes())
            .ok_or(PasskeyRegistrationError::InvalidReceipt)?,
        challenge: state.challenge.to_base64url(),
        relying_party_id: state.relying_party_id.clone(),
        relying_party_name: state.relying_party_name.clone(),
        user_id: encode_user_handle(&state.principal_id.as_bytes()),
        user_name: state.user_name.clone(),
        user_display_name: state.user_display_name.clone(),
        timeout_milliseconds: lifetime,
        user_verification: PasskeyUserVerification::Required,
        resident_key: PasskeyResidentKey::Required,
        attestation: PasskeyAttestation::None,
        public_key_parameters: vec![PasskeyCredentialParameter {
            credential_type: PasskeyCredentialType::PublicKey,
            algorithm: -7,
        }],
        exclude_credentials,
    })
}

pub(crate) fn registration_command(
    request: &CreatePasskeyRegistrationRequest,
    state: &FrozenPasskeyRegistrationState,
    outcome: RegistrationOutcome,
) -> Result<AuthoritativeCommand, PasskeyRegistrationError> {
    Ok(AuthoritativeCommand::CreateAuthenticationMethod(
        CreateAuthenticationMethod {
            method_id: state.method_id,
            principal_id: state.principal_id,
            label: request.label.as_str().to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::Passkey {
                credential_id: outcome.credential_id,
                public_key_algorithm: -7,
                public_key: outcome.public_key.as_bytes().to_vec(),
                signature_counter: u64::from(outcome.sign_count),
                authenticator_guid: Some(outcome.aaguid),
                transports: transport_bits(&request.transports)?,
                backup_eligible: outcome.backup_eligible,
                backup_state: outcome.backup_state,
            },
        },
    ))
}

pub(crate) fn registration_response(
    request: &CreatePasskeyRegistrationRequest,
    commit: PasskeyRegistrationCommit,
) -> Result<CreatePasskeyRegistrationResponse, PasskeyRegistrationError> {
    Ok(CreatePasskeyRegistrationResponse {
        operation_id: request.operation_id.clone(),
        method_id: ApiAuthenticationMethodId::from_uuid_bytes(commit.method_id.as_bytes())
            .ok_or(PasskeyRegistrationError::InvalidReceipt)?,
        created_at_epoch_micros: commit.created_at.get(),
    })
}

pub(crate) fn validate_commit(
    state: &FrozenPasskeyRegistrationState,
    record: &AuthenticationCeremonyRecord,
    commit: PasskeyRegistrationCommit,
    expected_request_digest: [u8; 32],
) -> Result<(), PasskeyRegistrationError> {
    if commit.request_digest != expected_request_digest
        || commit.result_digest == [0; 32]
        || commit.method_id != state.method_id
        || commit.principal_id != state.principal_id
        || commit.created_at < record.created_at
        || record
            .authority_result_digest
            .is_some_and(|digest| digest != commit.result_digest)
    {
        Err(PasskeyRegistrationError::Conflict)
    } else {
        Ok(())
    }
}

pub(crate) fn require_capability(
    state: &FrozenPasskeyRegistrationState,
    capability: SessionAccessCapability,
) -> Result<(), PasskeyRegistrationError> {
    if state.principal_id != capability.principal_id
        || state.session_id != capability.session_id
        || state.identity_revision != capability.identity_revision
        || state.capability_digest != capability.capability_digest
    {
        Err(PasskeyRegistrationError::Rejected)
    } else {
        Ok(())
    }
}

pub(crate) fn challenge_expiry(
    now: UnixMicros,
    session_expiry: UnixMicros,
    configuration: &PasskeyRegistrationConfiguration,
) -> Result<UnixMicros, PasskeyRegistrationError> {
    let configured = now
        .checked_add(configuration.lifetime())
        .ok_or(PasskeyRegistrationError::InvalidTime)?;
    let expires_at = if configured < session_expiry {
        configured
    } else {
        session_expiry
    };
    let remaining = expires_at
        .get()
        .checked_sub(now.get())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(PasskeyRegistrationError::InvalidTime)?;
    if remaining < MINIMUM_LIFETIME_MICROS {
        Err(PasskeyRegistrationError::Rejected)
    } else {
        Ok(expires_at)
    }
}

pub(crate) fn challenge_request_digest(
    state: &FrozenPasskeyRegistrationState,
    configuration: &PasskeyRegistrationConfiguration,
) -> Result<[u8; 32], PasskeyRegistrationError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.authentication.passkey-registration-challenge.v1\0");
    digest.update(configuration.digest()?);
    digest.update(state.principal_id.as_bytes());
    digest.update(state.session_id.as_bytes());
    digest.update(state.identity_revision.get().to_be_bytes());
    digest.update(state.capability_digest);
    digest_text(&mut digest, &state.user_name)?;
    digest_text(&mut digest, &state.user_display_name)?;
    for credential_id in &state.exclude_credential_ids {
        digest_bytes(&mut digest, credential_id)?;
    }
    Ok(digest.finalize().into())
}

pub(crate) fn registration_response_digest(
    request: &CreatePasskeyRegistrationRequest,
) -> Result<[u8; 32], PasskeyRegistrationError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.authentication.passkey-registration-response.v1\0");
    digest_text(&mut digest, request.label.as_str())?;
    digest_text(&mut digest, &request.credential_id)?;
    digest_text(&mut digest, &request.client_data_json)?;
    digest_text(&mut digest, &request.attestation_object)?;
    digest.update(
        u8::try_from(request.transports.len())
            .map_err(|_| PasskeyRegistrationError::InvalidRequest)?
            .to_be_bytes(),
    );
    for transport in &request.transports {
        digest.update([transport_code(*transport)]);
    }
    Ok(digest.finalize().into())
}

pub(crate) fn registration_context(
    operation_id: OperationId,
    state: &FrozenPasskeyRegistrationState,
    occurred_at: UnixMicros,
) -> Result<CommandContext, PasskeyRegistrationError> {
    Ok(CommandContext {
        operation_id,
        actor_principal_id: state.principal_id,
        audit_event_id: registration_audit_event_id(operation_id, state.method_id)?,
        occurred_at,
        expected_revision: None,
    })
}

pub(crate) fn bounded_exclusions(values: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut total = 0_usize;
    values
        .into_iter()
        .take_while(|value| {
            let Some(next) = total.checked_add(value.len()) else {
                return false;
            };
            if next > MAXIMUM_EXCLUDED_CREDENTIAL_BYTES {
                false
            } else {
                total = next;
                true
            }
        })
        .collect()
}

pub(crate) fn binding(record: &AuthenticationCeremonyRecord) -> PasskeyRegistrationBinding {
    PasskeyRegistrationBinding {
        challenge_id: record.challenge_id,
        creation_operation_id: record.creation_operation_id,
        request_digest: record.request_digest,
        created_at: record.created_at,
        expires_at: record.expires_at,
    }
}

pub(crate) fn parse_operation(value: &str) -> Result<OperationId, PasskeyRegistrationError> {
    OperationId::from_bytes(
        parse_uuid(value).map_err(|_| PasskeyRegistrationError::InvalidRequest)?,
    )
    .map_err(|_| PasskeyRegistrationError::InvalidRequest)
}

pub(crate) fn parse_challenge(
    value: &str,
) -> Result<AuthenticationChallengeId, PasskeyRegistrationError> {
    AuthenticationChallengeId::from_bytes(
        parse_uuid(value).map_err(|_| PasskeyRegistrationError::InvalidRequest)?,
    )
    .map_err(|_| PasskeyRegistrationError::InvalidRequest)
}

pub(crate) fn random_uuid(random: &mut impl RandomSource) -> Result<[u8; 16], ()> {
    let mut bytes = random_nonzero(random).map_err(|_| ())?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(bytes)
}

pub(crate) fn random_nonzero<const N: usize>(
    random: &mut impl RandomSource,
) -> Result<[u8; N], PasskeyRegistrationError> {
    let mut bytes = [0_u8; N];
    random
        .fill_bytes(&mut bytes)
        .map_err(|_| PasskeyRegistrationError::Unavailable)?;
    if bytes == [0; N] {
        Err(PasskeyRegistrationError::Unavailable)
    } else {
        Ok(bytes)
    }
}

fn registration_audit_event_id(
    operation_id: OperationId,
    method_id: AuthenticationMethodId,
) -> Result<AuditEventId, PasskeyRegistrationError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.authentication.passkey-registration-audit-id.v1");
    digest.update(operation_id.as_bytes());
    digest.update(method_id.as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| PasskeyRegistrationError::InvalidReceipt)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    AuditEventId::from_bytes(bytes).map_err(|_| PasskeyRegistrationError::InvalidReceipt)
}

fn transport_bits(transports: &[PasskeyTransport]) -> Result<u8, PasskeyRegistrationError> {
    let mut bits = 0_u8;
    for transport in transports {
        let bit = 1_u8
            .checked_shl(u32::from(transport_code(*transport)))
            .ok_or(PasskeyRegistrationError::InvalidRequest)?;
        if bits & bit != 0 {
            return Err(PasskeyRegistrationError::InvalidRequest);
        }
        bits |= bit;
    }
    Ok(bits)
}

const fn transport_code(transport: PasskeyTransport) -> u8 {
    match transport {
        PasskeyTransport::Usb => 0,
        PasskeyTransport::Nfc => 1,
        PasskeyTransport::Ble => 2,
        PasskeyTransport::SmartCard => 3,
        PasskeyTransport::Hybrid => 4,
        PasskeyTransport::Internal => 5,
    }
}

fn digest_text(digest: &mut Sha256, value: &str) -> Result<(), PasskeyRegistrationError> {
    digest_bytes(digest, value.as_bytes())
}

fn digest_bytes(digest: &mut Sha256, value: &[u8]) -> Result<(), PasskeyRegistrationError> {
    digest.update(
        u32::try_from(value.len())
            .map_err(|_| PasskeyRegistrationError::InvalidRequest)?
            .to_be_bytes(),
    );
    digest.update(value);
    Ok(())
}
