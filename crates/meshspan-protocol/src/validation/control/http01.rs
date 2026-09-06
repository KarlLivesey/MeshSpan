// SPDX-License-Identifier: GPL-2.0-only

//! Closed bounds for the public ACME proof relay, not an arbitrary metadata reader.

use crate::{framing::WireContractError, v1::Http01ChallengeResult};

pub(super) fn token(value: &str) -> Result<(), WireContractError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(WireContractError::InvalidMessage);
    }
    Ok(())
}

pub(super) fn result(value: &Http01ChallengeResult) -> Result<(), WireContractError> {
    token(&value.token)?;
    match (&value.key_authorization, value.expires_at_unix_micros) {
        (None, None) => Ok(()),
        (Some(body), Some(expiry))
            if expiry > 0
                && body.len() <= 512
                && body.starts_with(format!("{}.", value.token).as_bytes())
                && body.len() > value.token.len() + 1
                && body.is_ascii()
                && !body.iter().any(u8::is_ascii_whitespace) =>
        {
            Ok(())
        }
        _ => Err(WireContractError::InvalidMessage),
    }
}
