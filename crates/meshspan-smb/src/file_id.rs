// SPDX-License-Identifier: GPL-2.0-only

//! Connection-visible SMB file identity.

/// Exact 128-bit `SMB2_FILEID` assigned to one open handle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SmbFileId {
    persistent: u64,
    volatile: u64,
}

impl SmbFileId {
    /// Constructs a non-reserved file identity.
    ///
    /// # Errors
    ///
    /// Rejects the all-zero and all-ones values reserved by the protocol.
    pub const fn new(persistent: u64, volatile: u64) -> Result<Self, SmbFileIdError> {
        if (persistent == 0 && volatile == 0) || (persistent == u64::MAX && volatile == u64::MAX) {
            Err(SmbFileIdError)
        } else {
            Ok(Self {
                persistent,
                volatile,
            })
        }
    }

    /// Decodes one exact little-endian wire identity.
    ///
    /// # Errors
    ///
    /// Rejects reserved identities.
    pub fn from_wire(bytes: [u8; 16]) -> Result<Self, SmbFileIdError> {
        let (persistent, volatile) = bytes.split_at(8);
        let persistent = u64::from_le_bytes(persistent.try_into().map_err(|_| SmbFileIdError)?);
        let volatile = u64::from_le_bytes(volatile.try_into().map_err(|_| SmbFileIdError)?);
        Self::new(persistent, volatile)
    }

    /// Returns the exact little-endian wire identity.
    #[must_use]
    pub fn to_wire(self) -> [u8; 16] {
        let mut output = [0_u8; 16];
        output[..8].copy_from_slice(&self.persistent.to_le_bytes());
        output[8..].copy_from_slice(&self.volatile.to_le_bytes());
        output
    }

    /// Returns opaque bytes suitable for deriving a connector-neutral handle identity.
    #[must_use]
    pub fn identity_bytes(self) -> [u8; 16] {
        self.to_wire()
    }
}

/// Reserved or malformed `SMB2_FILEID`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("SMB file identity is reserved")]
pub struct SmbFileIdError;

#[cfg(test)]
mod tests {
    use super::{SmbFileId, SmbFileIdError};

    #[test]
    fn file_identity_round_trips_and_rejects_reserved_values() -> Result<(), SmbFileIdError> {
        let identity = SmbFileId::new(7, 11)?;
        assert_eq!(SmbFileId::from_wire(identity.to_wire())?, identity);
        assert_eq!(SmbFileId::from_wire([0; 16]), Err(SmbFileIdError));
        assert_eq!(SmbFileId::from_wire([0xff; 16]), Err(SmbFileIdError));
        Ok(())
    }
}
