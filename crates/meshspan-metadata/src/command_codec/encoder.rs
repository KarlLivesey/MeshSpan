// SPDX-License-Identifier: GPL-2.0-only

use super::MetadataCommandCodecError;

pub(super) struct Encoder {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Encoder {
    pub(super) fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    pub(super) fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub(super) fn fixed(&mut self, value: &[u8]) -> Result<(), MetadataCommandCodecError> {
        self.extend(value)
    }

    pub(super) fn identifier(&mut self, value: [u8; 16]) -> Result<(), MetadataCommandCodecError> {
        self.extend(&value)
    }

    pub(super) fn u8(&mut self, value: u8) -> Result<(), MetadataCommandCodecError> {
        self.extend(&[value])
    }

    pub(super) fn bool(&mut self, value: bool) -> Result<(), MetadataCommandCodecError> {
        self.u8(u8::from(value))
    }

    pub(super) fn u16(&mut self, value: u16) -> Result<(), MetadataCommandCodecError> {
        self.extend(&value.to_be_bytes())
    }

    pub(super) fn i32(&mut self, value: i32) -> Result<(), MetadataCommandCodecError> {
        self.extend(&value.to_be_bytes())
    }

    pub(super) fn u64(&mut self, value: u64) -> Result<(), MetadataCommandCodecError> {
        self.extend(&value.to_be_bytes())
    }

    pub(super) fn i64(&mut self, value: i64) -> Result<(), MetadataCommandCodecError> {
        self.extend(&value.to_be_bytes())
    }

    pub(super) fn optional_u64(
        &mut self,
        value: Option<u64>,
    ) -> Result<(), MetadataCommandCodecError> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.u64(value)
            }
            None => self.u8(0),
        }
    }

    pub(super) fn optional_i64(
        &mut self,
        value: Option<i64>,
    ) -> Result<(), MetadataCommandCodecError> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.i64(value)
            }
            None => self.u8(0),
        }
    }

    pub(super) fn optional_fixed_16(
        &mut self,
        value: Option<[u8; 16]>,
    ) -> Result<(), MetadataCommandCodecError> {
        match value {
            Some(value) => {
                self.u8(1)?;
                self.fixed(&value)
            }
            None => self.u8(0),
        }
    }

    pub(super) fn bytes(
        &mut self,
        value: &[u8],
        maximum: usize,
    ) -> Result<(), MetadataCommandCodecError> {
        if value.len() > maximum {
            return Err(MetadataCommandCodecError::CapacityExceeded);
        }
        let length =
            u32::try_from(value.len()).map_err(|_| MetadataCommandCodecError::CapacityExceeded)?;
        self.extend(&length.to_be_bytes())?;
        self.extend(value)
    }

    pub(super) fn text(
        &mut self,
        value: &str,
        maximum: usize,
    ) -> Result<(), MetadataCommandCodecError> {
        self.bytes(value.as_bytes(), maximum)
    }

    fn extend(&mut self, value: &[u8]) -> Result<(), MetadataCommandCodecError> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(MetadataCommandCodecError::CapacityExceeded)?;
        if next > self.maximum {
            return Err(MetadataCommandCodecError::CapacityExceeded);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }
}
