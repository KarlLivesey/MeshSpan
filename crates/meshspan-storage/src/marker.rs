// SPDX-License-Identifier: GPL-2.0-only

//! Fixed, checksummed registered-target marker encoding.

use meshspan_domain::{MeshId, TargetId};

use crate::StorageFolderError;

const MAGIC: [u8; 8] = *b"MSPNTGT1";
const FORMAT_VERSION: u32 = 1;
pub(super) const MARKER_BYTES: usize = 116;
const CHECKSUM_OFFSET: usize = MARKER_BYTES - 32;

/// Stable digest used by metadata and local state to recognise returning media.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarkerFingerprint([u8; 32]);

impl MarkerFingerprint {
    /// Reconstructs an exact fingerprint already validated by its authoritative journal.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Durable identity stored inside one private provider directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetMarker {
    mesh_id: MeshId,
    target_id: TargetId,
    generation: u64,
    nonce: [u8; 32],
    fingerprint: MarkerFingerprint,
}

impl TargetMarker {
    pub(super) fn new(
        mesh_id: MeshId,
        target_id: TargetId,
        generation: u64,
        nonce: [u8; 32],
    ) -> Result<Self, StorageFolderError> {
        if generation == 0 {
            return Err(StorageFolderError::InvalidRegistration);
        }
        let mut marker = Self {
            mesh_id,
            target_id,
            generation,
            nonce,
            fingerprint: MarkerFingerprint([0; 32]),
        };
        let bytes = marker.encode_prefix();
        marker.fingerprint = MarkerFingerprint(blake3::hash(&bytes).into());
        Ok(marker)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, StorageFolderError> {
        if bytes.len() != MARKER_BYTES || bytes[..8] != MAGIC {
            return Err(StorageFolderError::CorruptMarker);
        }
        let version = u32::from_be_bytes(copy_array(&bytes[8..12])?);
        if version != FORMAT_VERSION {
            return Err(StorageFolderError::CorruptMarker);
        }
        let mesh_id = MeshId::from_bytes(copy_array(&bytes[12..28])?)
            .map_err(|_| StorageFolderError::CorruptMarker)?;
        let target_id = TargetId::from_bytes(copy_array(&bytes[28..44])?)
            .map_err(|_| StorageFolderError::CorruptMarker)?;
        let generation = u64::from_be_bytes(copy_array(&bytes[44..52])?);
        let nonce = copy_array(&bytes[52..84])?;
        let stored = copy_array(&bytes[CHECKSUM_OFFSET..])?;
        let calculated: [u8; 32] = blake3::hash(&bytes[..CHECKSUM_OFFSET]).into();
        if generation == 0 || stored != calculated {
            return Err(StorageFolderError::CorruptMarker);
        }
        Ok(Self {
            mesh_id,
            target_id,
            generation,
            nonce,
            fingerprint: MarkerFingerprint(stored),
        })
    }

    pub(super) fn encode(self) -> [u8; MARKER_BYTES] {
        let prefix = self.encode_prefix();
        let mut bytes = [0; MARKER_BYTES];
        bytes[..CHECKSUM_OFFSET].copy_from_slice(&prefix);
        bytes[CHECKSUM_OFFSET..].copy_from_slice(&self.fingerprint.0);
        bytes
    }

    fn encode_prefix(self) -> [u8; CHECKSUM_OFFSET] {
        let mut bytes = [0; CHECKSUM_OFFSET];
        bytes[..8].copy_from_slice(&MAGIC);
        bytes[8..12].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
        bytes[12..28].copy_from_slice(&self.mesh_id.as_bytes());
        bytes[28..44].copy_from_slice(&self.target_id.as_bytes());
        bytes[44..52].copy_from_slice(&self.generation.to_be_bytes());
        bytes[52..84].copy_from_slice(&self.nonce);
        bytes
    }

    /// Returns the mesh that owns this target.
    #[must_use]
    pub const fn mesh_id(self) -> MeshId {
        self.mesh_id
    }

    /// Returns the stable target identity independent of its current path.
    #[must_use]
    pub const fn target_id(self) -> TargetId {
        self.target_id
    }

    /// Returns the authority-fenced target generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the stable fingerprint for return/relocation validation.
    #[must_use]
    pub const fn fingerprint(self) -> MarkerFingerprint {
        self.fingerprint
    }
}

fn copy_array<const LENGTH: usize>(value: &[u8]) -> Result<[u8; LENGTH], StorageFolderError> {
    value
        .try_into()
        .map_err(|_| StorageFolderError::CorruptMarker)
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{MeshId, TargetId};

    use super::TargetMarker;
    use crate::StorageFolderError;

    #[test]
    fn marker_round_trips_and_every_field_is_integrity_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let marker = TargetMarker::new(
            MeshId::from_bytes([1; 16])?,
            TargetId::from_bytes([2; 16])?,
            3,
            [4; 32],
        )?;
        let encoded = marker.encode();
        assert!(matches!(TargetMarker::decode(&encoded), Ok(value) if value == marker));
        for index in [0, 11, 20, 40, 50, 70, encoded.len() - 1] {
            let mut corrupt = encoded;
            corrupt[index] ^= 1;
            assert!(matches!(
                TargetMarker::decode(&corrupt),
                Err(StorageFolderError::CorruptMarker)
            ));
        }
        Ok(())
    }
}
