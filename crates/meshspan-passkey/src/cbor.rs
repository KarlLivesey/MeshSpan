// SPDX-License-Identifier: GPL-2.0-only

//! Minimal bounded deterministic-CBOR reader for attestation and COSE records.

use crate::{PasskeyError, PasskeyErrorKind};

const MAXIMUM_CONTAINER_ITEMS: usize = 32;
const MAXIMUM_DEPTH: usize = 8;

pub(crate) struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.position == self.input.len()
    }

    pub(crate) fn map_length(&mut self) -> Result<usize, PasskeyError> {
        self.container_length(5)
    }

    pub(crate) fn integer(&mut self) -> Result<i64, PasskeyError> {
        let (major, value) = self.header()?;
        match major {
            0 => i64::try_from(value).map_err(|_| malformed()),
            1 => i64::try_from(value)
                .ok()
                .and_then(|number| number.checked_add(1))
                .and_then(i64::checked_neg)
                .ok_or_else(malformed),
            _ => Err(malformed()),
        }
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], PasskeyError> {
        let length = self.length_for_major(2)?;
        self.take(length)
    }

    pub(crate) fn text(&mut self) -> Result<&'a str, PasskeyError> {
        let length = self.length_for_major(3)?;
        let bytes = self.take(length)?;
        core::str::from_utf8(bytes).map_err(|_| malformed())
    }

    pub(crate) fn skip(&mut self) -> Result<(), PasskeyError> {
        self.skip_at_depth(0)
    }

    fn skip_at_depth(&mut self, depth: usize) -> Result<(), PasskeyError> {
        if depth > MAXIMUM_DEPTH {
            return Err(PasskeyError::new(PasskeyErrorKind::LimitExceeded));
        }
        let (major, value) = self.header()?;
        match major {
            0 | 1 => Ok(()),
            2 | 3 => {
                let length = usize::try_from(value).map_err(|_| malformed())?;
                self.take(length).map(|_| ())
            }
            4 => self.skip_items(value, depth, false),
            5 => self.skip_items(value, depth, true),
            _ => Err(malformed()),
        }
    }

    fn skip_items(
        &mut self,
        encoded_count: u64,
        depth: usize,
        map: bool,
    ) -> Result<(), PasskeyError> {
        let count = usize::try_from(encoded_count).map_err(|_| malformed())?;
        if count > MAXIMUM_CONTAINER_ITEMS {
            return Err(PasskeyError::new(PasskeyErrorKind::LimitExceeded));
        }
        let values = if map {
            count
                .checked_mul(2)
                .ok_or_else(|| PasskeyError::new(PasskeyErrorKind::LimitExceeded))?
        } else {
            count
        };
        for _ in 0..values {
            self.skip_at_depth(depth + 1)?;
        }
        Ok(())
    }

    fn container_length(&mut self, expected_major: u8) -> Result<usize, PasskeyError> {
        let length = self.length_for_major(expected_major)?;
        if length > MAXIMUM_CONTAINER_ITEMS {
            return Err(PasskeyError::new(PasskeyErrorKind::LimitExceeded));
        }
        Ok(length)
    }

    fn length_for_major(&mut self, expected_major: u8) -> Result<usize, PasskeyError> {
        let (major, value) = self.header()?;
        if major != expected_major {
            return Err(malformed());
        }
        usize::try_from(value).map_err(|_| malformed())
    }

    fn header(&mut self) -> Result<(u8, u64), PasskeyError> {
        let first = self.byte()?;
        let major = first >> 5;
        let additional = first & 0x1f;
        let value = match additional {
            0..=23 => u64::from(additional),
            24 => {
                let value = u64::from(self.byte()?);
                if value < 24 {
                    return Err(malformed());
                }
                value
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.array()?));
                if u8::try_from(value).is_ok() {
                    return Err(malformed());
                }
                value
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.array()?));
                if u16::try_from(value).is_ok() {
                    return Err(malformed());
                }
                value
            }
            27 => {
                let value = u64::from_be_bytes(self.array()?);
                if u32::try_from(value).is_ok() {
                    return Err(malformed());
                }
                value
            }
            _ => return Err(malformed()),
        };
        Ok((major, value))
    }

    fn byte(&mut self) -> Result<u8, PasskeyError> {
        let byte = self
            .input
            .get(self.position)
            .copied()
            .ok_or_else(malformed)?;
        self.position += 1;
        Ok(byte)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PasskeyError> {
        self.take(N)?.try_into().map_err(|_| malformed())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PasskeyError> {
        let end = self.position.checked_add(length).ok_or_else(malformed)?;
        let value = self.input.get(self.position..end).ok_or_else(malformed)?;
        self.position = end;
        Ok(value)
    }
}

fn malformed() -> PasskeyError {
    PasskeyError::new(PasskeyErrorKind::Malformed)
}

#[cfg(test)]
mod tests {
    use super::Decoder;
    use crate::PasskeyErrorKind;

    #[test]
    fn integers_and_lengths_require_shortest_definite_encoding()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut decoder = Decoder::new(&[0x20, 0x38, 0x18]);
        assert_eq!(decoder.integer()?, -1);
        assert_eq!(decoder.integer()?, -25);
        assert!(decoder.is_empty());
        for invalid in [&[0x18, 0x17][..], &[0x5f][..], &[0x19, 0x00, 0xff][..]] {
            let kind = Decoder::new(invalid)
                .skip()
                .err()
                .map(crate::PasskeyError::kind);
            assert_eq!(kind, Some(PasskeyErrorKind::Malformed));
        }
        Ok(())
    }

    #[test]
    fn nested_excess_and_truncation_fail_closed() {
        let excessive_map = [0xb8, 33];
        let kind = Decoder::new(&excessive_map)
            .skip()
            .err()
            .map(crate::PasskeyError::kind);
        assert_eq!(kind, Some(PasskeyErrorKind::LimitExceeded));
        let kind = Decoder::new(&[0x43, 1, 2])
            .skip()
            .err()
            .map(crate::PasskeyError::kind);
        assert_eq!(kind, Some(PasskeyErrorKind::Malformed));
    }
}
