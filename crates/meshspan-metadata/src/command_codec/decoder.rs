// SPDX-License-Identifier: GPL-2.0-only

use super::MetadataCommandCodecError;

pub(super) struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    pub(super) fn finish(self) -> Result<(), MetadataCommandCodecError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(MetadataCommandCodecError::Invalid)
        }
    }

    pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], MetadataCommandCodecError> {
        let bytes = self.take(N)?;
        bytes
            .try_into()
            .map_err(|_| MetadataCommandCodecError::Invalid)
    }

    pub(super) fn identifier(&mut self) -> Result<[u8; 16], MetadataCommandCodecError> {
        self.fixed()
    }

    pub(super) fn u8(&mut self) -> Result<u8, MetadataCommandCodecError> {
        Ok(self.fixed::<1>()?[0])
    }

    pub(super) fn bool(&mut self) -> Result<bool, MetadataCommandCodecError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(MetadataCommandCodecError::Invalid),
        }
    }

    pub(super) fn u16(&mut self) -> Result<u16, MetadataCommandCodecError> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    pub(super) fn i32(&mut self) -> Result<i32, MetadataCommandCodecError> {
        Ok(i32::from_be_bytes(self.fixed()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, MetadataCommandCodecError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    pub(super) fn i64(&mut self) -> Result<i64, MetadataCommandCodecError> {
        Ok(i64::from_be_bytes(self.fixed()?))
    }

    pub(super) fn optional_u64(&mut self) -> Result<Option<u64>, MetadataCommandCodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.u64().map(Some),
            _ => Err(MetadataCommandCodecError::Invalid),
        }
    }

    pub(super) fn optional_i64(&mut self) -> Result<Option<i64>, MetadataCommandCodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.i64().map(Some),
            _ => Err(MetadataCommandCodecError::Invalid),
        }
    }

    pub(super) fn optional_fixed_16(
        &mut self,
    ) -> Result<Option<[u8; 16]>, MetadataCommandCodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.fixed().map(Some),
            _ => Err(MetadataCommandCodecError::Invalid),
        }
    }

    pub(super) fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, MetadataCommandCodecError> {
        let length = usize::try_from(u32::from_be_bytes(self.fixed()?))
            .map_err(|_| MetadataCommandCodecError::CapacityExceeded)?;
        if length > maximum {
            return Err(MetadataCommandCodecError::CapacityExceeded);
        }
        Ok(self.take(length)?.to_vec())
    }

    pub(super) fn text(&mut self, maximum: usize) -> Result<String, MetadataCommandCodecError> {
        String::from_utf8(self.bytes(maximum)?).map_err(|_| MetadataCommandCodecError::Invalid)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], MetadataCommandCodecError> {
        if self.remaining.len() < length {
            return Err(MetadataCommandCodecError::Invalid);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }
}
