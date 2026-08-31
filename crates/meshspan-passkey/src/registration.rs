// SPDX-License-Identifier: GPL-2.0-only

//! None-attestation ES256 `WebAuthn` credential registration.

use sha2::{Digest, Sha256};

use crate::cbor::Decoder;
use crate::client_data::{self, constant_time_equal};
use crate::{
    Es256PublicKey, MAXIMUM_ATTESTATION_OBJECT_BYTES, MAXIMUM_CLIENT_DATA_BYTES,
    MAXIMUM_CREDENTIAL_ID_BYTES, PasskeyError, PasskeyErrorKind, UserVerification,
};

const MINIMUM_AUTHENTICATOR_DATA_LENGTH: usize = 55;
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_BACKUP_STATE: u8 = 0x10;
const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;
const FLAG_EXTENSIONS: u8 = 0x80;

/// One hostile browser registration response.
pub struct Registration<'a> {
    /// Browser-returned credential identity, independently matched to authenticator data.
    pub credential_id: &'a [u8],
    /// Exact collected-client-data JSON bytes.
    pub client_data_json: &'a [u8],
    /// Exact CBOR attestation object.
    pub attestation_object: &'a [u8],
}

/// Server state fixed before creating a credential.
pub struct RegistrationExpectation<'a> {
    /// Random server-issued challenge bytes.
    pub challenge: &'a [u8],
    /// Relying-party identifier supplied to the browser.
    pub relying_party_id: &'a str,
    /// Exact allowed origin serialisations for this relying party.
    pub allowed_origins: &'a [&'a str],
    /// User-verification requirement fixed at challenge creation.
    pub user_verification: UserVerification,
}

/// Validated credential evidence safe to commit to authoritative metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationOutcome {
    /// Exact opaque credential identity.
    pub credential_id: Vec<u8>,
    /// Canonical uncompressed P-256 public key.
    pub public_key: Es256PublicKey,
    /// Authenticator model identifier; zero for privacy-preserving implementations when applicable.
    pub aaguid: [u8; 16],
    /// Initial authenticator signature counter.
    pub sign_count: u32,
    /// Whether authenticator-local user verification occurred.
    pub user_verified: bool,
    /// Whether this credential is eligible for backup/synchronisation.
    pub backup_eligible: bool,
    /// Whether this credential was backed up at registration time.
    pub backup_state: bool,
}

/// Verifies a complete none-attestation ES256 registration response.
///
/// # Errors
///
/// Rejects excess, malformed/non-minimal CBOR, duplicate fields, binding mismatches,
/// missing interaction, unsupported attestation/extensions/algorithms and invalid keys.
pub fn verify_registration(
    registration: &Registration<'_>,
    expected: &RegistrationExpectation<'_>,
) -> Result<RegistrationOutcome, PasskeyError> {
    validate_bounds(registration, expected)?;
    let _client = client_data::verify(
        registration.client_data_json,
        expected.challenge,
        expected.allowed_origins,
        "webauthn.create",
    )?;
    let auth_data = parse_attestation_object(registration.attestation_object)?;
    let relying_party_hash: [u8; 32] = Sha256::digest(expected.relying_party_id.as_bytes()).into();
    parse_registration_authenticator_data(
        auth_data,
        registration.credential_id,
        &relying_party_hash,
        expected.user_verification,
    )
}

fn parse_attestation_object(input: &[u8]) -> Result<&[u8], PasskeyError> {
    let mut decoder = Decoder::new(input);
    let count = decoder.map_length()?;
    if count != 3 {
        return Err(malformed());
    }
    let mut format = None;
    let mut auth_data = None;
    let mut statement_seen = false;
    let mut empty_statement = false;
    for _ in 0..count {
        match decoder.text()? {
            "fmt" if format.is_none() => format = Some(decoder.text()?),
            "authData" if auth_data.is_none() => auth_data = Some(decoder.bytes()?),
            "attStmt" if !statement_seen => {
                statement_seen = true;
                empty_statement = decoder.map_length()? == 0;
            }
            _ => return Err(malformed()),
        }
    }
    if !decoder.is_empty() || format != Some("none") || !empty_statement {
        return Err(PasskeyError::new(PasskeyErrorKind::UnsupportedCredential));
    }
    auth_data.ok_or_else(malformed)
}

fn parse_registration_authenticator_data(
    input: &[u8],
    outer_credential_id: &[u8],
    relying_party_hash: &[u8; 32],
    user_verification: UserVerification,
) -> Result<RegistrationOutcome, PasskeyError> {
    if input.len() < MINIMUM_AUTHENTICATOR_DATA_LENGTH
        || !constant_time_equal(&input[..32], relying_party_hash)
    {
        return Err(PasskeyError::new(PasskeyErrorKind::BindingMismatch));
    }
    let flags = input[32];
    let user_verified = flags & FLAG_USER_VERIFIED != 0;
    let backup_eligible = flags & FLAG_BACKUP_ELIGIBLE != 0;
    let backup_state = flags & FLAG_BACKUP_STATE != 0;
    if flags & FLAG_USER_PRESENT == 0
        || flags & FLAG_ATTESTED_CREDENTIAL_DATA == 0
        || (user_verification == UserVerification::Required && !user_verified)
        || (backup_state && !backup_eligible)
    {
        return Err(PasskeyError::new(PasskeyErrorKind::UserInteractionRequired));
    }
    if flags & FLAG_EXTENSIONS != 0 {
        return Err(PasskeyError::new(PasskeyErrorKind::UnsupportedCredential));
    }
    let sign_count = u32::from_be_bytes(input[33..37].try_into().map_err(|_| malformed())?);
    let aaguid = input[37..53].try_into().map_err(|_| malformed())?;
    let credential_length = usize::from(u16::from_be_bytes(
        input[53..55].try_into().map_err(|_| malformed())?,
    ));
    if credential_length == 0 || credential_length > MAXIMUM_CREDENTIAL_ID_BYTES {
        return Err(PasskeyError::new(PasskeyErrorKind::LimitExceeded));
    }
    let credential_end = 55_usize
        .checked_add(credential_length)
        .ok_or_else(malformed)?;
    let credential_id = input.get(55..credential_end).ok_or_else(malformed)?;
    if !constant_time_equal(credential_id, outer_credential_id) {
        return Err(PasskeyError::new(PasskeyErrorKind::BindingMismatch));
    }
    let public_key = parse_es256_cose_key(input.get(credential_end..).ok_or_else(malformed)?)?;
    Ok(RegistrationOutcome {
        credential_id: credential_id.to_vec(),
        public_key,
        aaguid,
        sign_count,
        user_verified,
        backup_eligible,
        backup_state,
    })
}

fn parse_es256_cose_key(input: &[u8]) -> Result<Es256PublicKey, PasskeyError> {
    let mut decoder = Decoder::new(input);
    let count = decoder.map_length()?;
    let mut seen = Vec::new();
    let mut key_type = None;
    let mut algorithm = None;
    let mut curve = None;
    let mut x = None;
    let mut y = None;
    for _ in 0..count {
        let label = decoder.integer()?;
        if seen.contains(&label) {
            return Err(malformed());
        }
        seen.push(label);
        match label {
            1 => key_type = Some(decoder.integer()?),
            3 => algorithm = Some(decoder.integer()?),
            -1 => curve = Some(decoder.integer()?),
            -2 => x = Some(exact_coordinate(decoder.bytes()?)?),
            -3 => y = Some(exact_coordinate(decoder.bytes()?)?),
            _ => decoder.skip()?,
        }
    }
    if !decoder.is_empty() || key_type != Some(2) || algorithm != Some(-7) || curve != Some(1) {
        return Err(PasskeyError::new(PasskeyErrorKind::UnsupportedCredential));
    }
    let mut sec1 = [0_u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x.ok_or_else(malformed)?);
    sec1[33..65].copy_from_slice(&y.ok_or_else(malformed)?);
    Es256PublicKey::from_sec1_bytes(&sec1)
}

fn exact_coordinate(value: &[u8]) -> Result<[u8; 32], PasskeyError> {
    value.try_into().map_err(|_| malformed())
}

fn validate_bounds(
    registration: &Registration<'_>,
    expected: &RegistrationExpectation<'_>,
) -> Result<(), PasskeyError> {
    if registration.credential_id.is_empty()
        || registration.credential_id.len() > MAXIMUM_CREDENTIAL_ID_BYTES
        || registration.client_data_json.is_empty()
        || registration.client_data_json.len() > MAXIMUM_CLIENT_DATA_BYTES
        || registration.attestation_object.is_empty()
        || registration.attestation_object.len() > MAXIMUM_ATTESTATION_OBJECT_BYTES
        || expected.challenge.len() < 16
        || expected.challenge.len() > 64
        || expected.relying_party_id.is_empty()
        || expected.relying_party_id.len() > 253
        || expected.allowed_origins.is_empty()
        || expected.allowed_origins.len() > 16
    {
        return Err(PasskeyError::new(PasskeyErrorKind::LimitExceeded));
    }
    Ok(())
}

fn malformed() -> PasskeyError {
    PasskeyError::new(PasskeyErrorKind::Malformed)
}
