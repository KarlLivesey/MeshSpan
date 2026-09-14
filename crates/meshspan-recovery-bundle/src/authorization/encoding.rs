// SPDX-License-Identifier: GPL-2.0-only

//! Closed portable recovery authorisation container; no embedded trust anchor is accepted.

use meshspan_domain::{BackupId, MeshId, OperationId, PartitionId, Revision};

use super::{CLAIM_BYTES, FORMAT, RecoveryAuthorization, RecoveryAuthorizationClaims};
use crate::RecoveryBundleError;

impl RecoveryAuthorization {
    /// Encodes public claims followed by a one-byte length and bounded DER signature.
    /// This contains neither root private material nor a caller-selected trust anchor.
    /// # Errors
    /// Rejects malformed in-memory claims or signature lengths.
    pub fn encode(&self) -> Result<Vec<u8>, RecoveryBundleError> {
        let mut bytes = self.claims.canonical_bytes()?;
        let length =
            u8::try_from(self.signature.len()).map_err(|_| RecoveryBundleError::Corrupt)?;
        if length == 0 || length > 72 {
            return Err(RecoveryBundleError::Corrupt);
        }
        bytes.push(length);
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    /// Decodes a bounded portable container and verifies it against an independent root.
    /// Installation still requires matching its claims to independently verified source,
    /// inventory, replacement configuration and accepted recovery epoch.
    /// # Errors
    /// Rejects unknown formats, truncation, trailing data, malformed claims or bad signatures.
    pub fn decode(trusted_root: &[u8], encoded: &[u8]) -> Result<Self, RecoveryBundleError> {
        if !(CLAIM_BYTES + 2..=CLAIM_BYTES + 1 + 72).contains(&encoded.len()) {
            return Err(RecoveryBundleError::Corrupt);
        }
        let claims = RecoveryAuthorizationClaims::decode(&encoded[..CLAIM_BYTES])?;
        let length = usize::from(encoded[CLAIM_BYTES]);
        let signature = &encoded[CLAIM_BYTES + 1..];
        if length != signature.len() {
            return Err(RecoveryBundleError::Corrupt);
        }
        Self::verify(trusted_root, claims, signature)
    }
}

impl RecoveryAuthorizationClaims {
    fn decode(encoded: &[u8]) -> Result<Self, RecoveryBundleError> {
        if encoded.len() != CLAIM_BYTES || !encoded.starts_with(FORMAT) {
            return Err(RecoveryBundleError::Corrupt);
        }
        let mut fields = &encoded[FORMAT.len()..];
        let claims = Self {
            mesh_id: MeshId::from_bytes(take(&mut fields)?)
                .map_err(|_| RecoveryBundleError::Corrupt)?,
            partition_id: PartitionId::from_bytes(take(&mut fields)?)
                .map_err(|_| RecoveryBundleError::Corrupt)?,
            recovery_id: OperationId::from_bytes(take(&mut fields)?)
                .map_err(|_| RecoveryBundleError::Corrupt)?,
            backup_id: BackupId::from_bytes(take(&mut fields)?)
                .map_err(|_| RecoveryBundleError::Corrupt)?,
            backup_digest: take(&mut fields)?,
            source_log_index: u64::from_be_bytes(take(&mut fields)?),
            source_log_term: u64::from_be_bytes(take(&mut fields)?),
            source_revision: Revision::new(u64::from_be_bytes(take(&mut fields)?)),
            previous_epoch: u64::from_be_bytes(take(&mut fields)?),
            recovery_epoch: u64::from_be_bytes(take(&mut fields)?),
            replacement_manifest_digest: take(&mut fields)?,
            target_inventory_digest: take(&mut fields)?,
        };
        claims.canonical_bytes()?;
        Ok(claims)
    }
}

fn take<const N: usize>(remaining: &mut &[u8]) -> Result<[u8; N], RecoveryBundleError> {
    let (field, tail) = remaining
        .split_at_checked(N)
        .ok_or(RecoveryBundleError::Corrupt)?;
    *remaining = tail;
    field.try_into().map_err(|_| RecoveryBundleError::Corrupt)
}
