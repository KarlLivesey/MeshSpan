// SPDX-License-Identifier: GPL-2.0-only

//! Strict unpadded base64url decoding for `WebAuthn` JSON fields.

use crate::{PasskeyError, PasskeyErrorKind};

pub(crate) fn decode(value: &str, maximum_bytes: usize) -> Result<Vec<u8>, PasskeyError> {
    if value.is_empty() || value.as_bytes().contains(&b'=') || value.len() % 4 == 1 {
        return Err(PasskeyError::new(PasskeyErrorKind::Malformed));
    }
    let maximum_encoded = maximum_bytes
        .checked_mul(4)
        .and_then(|length| length.checked_add(2))
        .map(|length| length / 3)
        .ok_or_else(|| PasskeyError::new(PasskeyErrorKind::LimitExceeded))?;
    if value.len() > maximum_encoded {
        return Err(PasskeyError::new(PasskeyErrorKind::LimitExceeded));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(maximum_decoded_length(value.len())?)
        .map_err(|_| PasskeyError::new(PasskeyErrorKind::LimitExceeded))?;
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    for byte in value.bytes() {
        accumulator = (accumulator << 6) | u32::from(symbol(byte)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits).to_le_bytes()[0]);
            accumulator &= (1_u32 << bits) - 1;
        }
    }
    if accumulator != 0 || output.len() > maximum_bytes {
        return Err(PasskeyError::new(PasskeyErrorKind::Malformed));
    }
    Ok(output)
}

fn maximum_decoded_length(encoded_length: usize) -> Result<usize, PasskeyError> {
    encoded_length
        .checked_mul(3)
        .map(|length| length / 4)
        .ok_or_else(|| PasskeyError::new(PasskeyErrorKind::LimitExceeded))
}

fn symbol(byte: u8) -> Result<u8, PasskeyError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(PasskeyError::new(PasskeyErrorKind::Malformed)),
    }
}

#[cfg(test)]
mod tests {
    use super::decode;
    use crate::PasskeyErrorKind;

    #[test]
    fn canonical_unpadded_values_decode_exactly() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(decode("AA", 1)?, [0]);
        assert_eq!(decode("AQI", 2)?, [1, 2]);
        assert_eq!(decode("AQID", 3)?, [1, 2, 3]);
        Ok(())
    }

    #[test]
    fn padding_alphabet_and_non_zero_tail_bits_fail() {
        for value in ["AA==", "AA+", "AB", "A"] {
            let error = decode(value, 8).err().map(crate::PasskeyError::kind);
            assert_eq!(error, Some(PasskeyErrorKind::Malformed), "{value}");
        }
    }
}
