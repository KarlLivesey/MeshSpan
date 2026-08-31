// SPDX-License-Identifier: GPL-2.0-only

//! Authentication authenticator-data parsing and policy validation.

use crate::client_data::constant_time_equal;
use crate::{MAXIMUM_AUTHENTICATOR_DATA_BYTES, PasskeyError, PasskeyErrorKind, UserVerification};

const MINIMUM_LENGTH: usize = 37;
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_BACKUP_STATE: u8 = 0x10;
const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;
const FLAG_EXTENSIONS: u8 = 0x80;

pub(crate) struct AuthenticatorData {
    pub(crate) sign_count: u32,
    pub(crate) user_verified: bool,
    pub(crate) backup_eligible: bool,
    pub(crate) backup_state: bool,
}

pub(crate) fn verify(
    input: &[u8],
    relying_party_hash: &[u8; 32],
    user_verification: UserVerification,
) -> Result<AuthenticatorData, PasskeyError> {
    if input.len() < MINIMUM_LENGTH || input.len() > MAXIMUM_AUTHENTICATOR_DATA_BYTES {
        return Err(PasskeyError::new(PasskeyErrorKind::LimitExceeded));
    }
    if !constant_time_equal(&input[..32], relying_party_hash) {
        return Err(PasskeyError::new(PasskeyErrorKind::BindingMismatch));
    }
    let flags = input[32];
    let user_present = flags & FLAG_USER_PRESENT != 0;
    let user_verified = flags & FLAG_USER_VERIFIED != 0;
    let backup_eligible = flags & FLAG_BACKUP_ELIGIBLE != 0;
    let backup_state = flags & FLAG_BACKUP_STATE != 0;
    if !user_present
        || (user_verification == UserVerification::Required && !user_verified)
        || (backup_state && !backup_eligible)
        || flags & FLAG_ATTESTED_CREDENTIAL_DATA != 0
    {
        return Err(PasskeyError::new(PasskeyErrorKind::UserInteractionRequired));
    }
    if flags & FLAG_EXTENSIONS != 0 {
        return Err(PasskeyError::new(PasskeyErrorKind::UnsupportedCredential));
    }
    if input.len() != MINIMUM_LENGTH {
        return Err(PasskeyError::new(PasskeyErrorKind::Malformed));
    }
    let sign_count = u32::from_be_bytes(
        input[33..37]
            .try_into()
            .map_err(|_| PasskeyError::new(PasskeyErrorKind::Malformed))?,
    );
    Ok(AuthenticatorData {
        sign_count,
        user_verified,
        backup_eligible,
        backup_state,
    })
}
