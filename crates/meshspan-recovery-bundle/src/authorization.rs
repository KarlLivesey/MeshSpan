// SPDX-License-Identifier: GPL-2.0-only

//! Exact offline recovery intent. Installation remains a separate, epoch-fenced transition.

use meshspan_certificates::verify_recovery_signature;
use meshspan_domain::{BackupId, MeshId, OperationId, PartitionId, Revision};

use crate::{RecoveredAuthority, RecoveryBundleError};

const FORMAT: &[u8] = b"MSRECOVERY\x01";
const CLAIM_BYTES: usize = 211;

mod encoding;

/// Public claims binding one source to one replacement and verified target inventory.
/// Digests describe independently validated canonical manifests, never filesystem paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryAuthorizationClaims {
    /// Owning swarm; recovery does not invent another swarm identity.
    pub mesh_id: MeshId,
    /// Exact restored metadata partition.
    pub partition_id: PartitionId,
    /// Stable identity for idempotent recovery admission.
    pub recovery_id: OperationId,
    /// Exact independently selected encrypted backup.
    pub backup_id: BackupId,
    /// SHA-256 of the entire encrypted backup, not merely its inner database.
    pub backup_digest: [u8; 32],
    /// Exact committed source log position.
    pub source_log_index: u64,
    /// Term at that committed source position.
    pub source_log_term: u64,
    /// Authoritative state revision captured by the backup.
    pub source_revision: Revision,
    /// Recovery generation represented by the selected source (zero before any recovery).
    pub previous_epoch: u64,
    /// Exact next generation; the installer must also check its currently accepted epoch.
    pub recovery_epoch: u64,
    /// SHA-256 binding replacement membership, keys, quorum and credential fencing plan.
    pub replacement_manifest_digest: [u8; 32],
    /// SHA-256 binding validated target identities and their exact inventory manifests.
    pub target_inventory_digest: [u8; 32],
}

impl RecoveryAuthorizationClaims {
    /// Encodes the closed fixed-width version-one signing payload.
    /// # Errors
    /// Rejects empty evidence, impossible source positions and non-successor/overflowed epochs.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RecoveryBundleError> {
        if self.backup_digest == [0; 32]
            || self.replacement_manifest_digest == [0; 32]
            || self.target_inventory_digest == [0; 32]
            || self.source_log_index == 0
            || self.source_log_term == 0
            || self.source_revision == Revision::ZERO
            || self.previous_epoch.checked_add(1) != Some(self.recovery_epoch)
            || self.recovery_epoch > i64::MAX.unsigned_abs()
        {
            return Err(RecoveryBundleError::Corrupt);
        }
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(FORMAT);
        for identity in [
            self.mesh_id.as_bytes(),
            self.partition_id.as_bytes(),
            self.recovery_id.as_bytes(),
            self.backup_id.as_bytes(),
        ] {
            bytes.extend_from_slice(&identity);
        }
        bytes.extend_from_slice(&self.backup_digest);
        for number in [
            self.source_log_index,
            self.source_log_term,
            self.source_revision.get(),
            self.previous_epoch,
            self.recovery_epoch,
        ] {
            bytes.extend_from_slice(&number.to_be_bytes());
        }
        bytes.extend_from_slice(&self.replacement_manifest_digest);
        bytes.extend_from_slice(&self.target_inventory_digest);
        Ok(bytes)
    }
}

/// Root-authenticated recovery proposal. It is not a receipt that service admission happened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryAuthorization {
    claims: RecoveryAuthorizationClaims,
    signature: Vec<u8>,
}

impl RecoveredAuthority {
    /// Signs exact recovery intent using the explicitly opened offline bundle.
    /// The caller must first verify the source, replacement and inventory manifests.
    /// # Errors
    /// Rejects another swarm, invalid claims or unavailable signing material.
    pub fn authorize_recovery(
        &self,
        claims: RecoveryAuthorizationClaims,
    ) -> Result<RecoveryAuthorization, RecoveryBundleError> {
        if claims.mesh_id != self.mesh_id {
            return Err(RecoveryBundleError::Corrupt);
        }
        let signature = self
            .root_authority
            .sign_recovery_manifest(&claims.canonical_bytes()?)
            .map_err(|_| RecoveryBundleError::Certificate)?;
        Ok(RecoveryAuthorization { claims, signature })
    }
}

impl RecoveryAuthorization {
    /// Validates externally supplied claims/signature against an independent trusted root.
    /// The trust anchor must be selected from verified mesh state, not from the supplied proposal.
    /// # Errors
    /// Rejects malformed claims and signatures or a different trusted root.
    pub fn verify(
        trusted_root: &[u8],
        claims: RecoveryAuthorizationClaims,
        signature: &[u8],
    ) -> Result<Self, RecoveryBundleError> {
        verify_recovery_signature(trusted_root, &claims.canonical_bytes()?, signature)
            .map_err(|_| RecoveryBundleError::Certificate)?;
        Ok(Self {
            claims,
            signature: signature.to_vec(),
        })
    }

    /// Borrows the exact signed claims; admission must compare all fields to its own evidence.
    #[must_use]
    pub const fn claims(&self) -> &RecoveryAuthorizationClaims {
        &self.claims
    }

    /// Borrows the canonical DER-encoded P-256 signature, safe to persist with its claims.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}
