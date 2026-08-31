// SPDX-License-Identifier: GPL-2.0-only

//! Collected-client-data parsing and exact ceremony binding.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::base64url;
use crate::{MAXIMUM_CLIENT_DATA_BYTES, PasskeyError, PasskeyErrorKind};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectedClientData {
    r#type: String,
    challenge: String,
    origin: String,
    #[serde(default)]
    cross_origin: bool,
    #[serde(default)]
    top_origin: Option<String>,
}

pub(crate) struct VerifiedClientData {
    pub(crate) hash: [u8; 32],
}

pub(crate) fn verify(
    input: &[u8],
    expected_challenge: &[u8],
    expected_origins: &[&str],
    ceremony_type: &str,
) -> Result<VerifiedClientData, PasskeyError> {
    if input.is_empty() || input.len() > MAXIMUM_CLIENT_DATA_BYTES || expected_origins.is_empty() {
        return Err(PasskeyError::new(PasskeyErrorKind::LimitExceeded));
    }
    let value = serde_json::from_slice::<CollectedClientData>(input)
        .map_err(|_| PasskeyError::new(PasskeyErrorKind::Malformed))?;
    if value.r#type != ceremony_type
        || value.cross_origin
        || value.top_origin.is_some()
        || !expected_origins.contains(&value.origin.as_str())
    {
        return Err(PasskeyError::new(PasskeyErrorKind::BindingMismatch));
    }
    let challenge = base64url::decode(&value.challenge, expected_challenge.len())?;
    if !constant_time_equal(&challenge, expected_challenge) {
        return Err(PasskeyError::new(PasskeyErrorKind::BindingMismatch));
    }
    Ok(VerifiedClientData {
        hash: Sha256::digest(input).into(),
    })
}

pub(crate) fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    bool::from(left.ct_eq(right))
}
