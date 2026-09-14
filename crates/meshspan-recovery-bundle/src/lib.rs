// SPDX-License-Identifier: GPL-2.0-only

//! Bounded encrypted offline recovery authority for one exact `MeshSpan` mesh.
//!
//! The bundle is a portable opaque file. Its independently stored recovery code decrypts the
//! mesh root certificate-authority key and recovery X25519 key; only the root certificate and
//! public wrapping key are admitted to online authoritative metadata.

mod authorization;
mod bundle;
mod code;
mod consensus_admission;
mod error;
mod material;
mod secret_recovery;
mod state_transfer;
pub use secret_recovery::RecoveredSecret;
pub use state_transfer::{RecoveryStateTransfer, RecoveryStateTransferClaims};

pub use authorization::{RecoveryAuthorization, RecoveryAuthorizationClaims};
pub use bundle::{MAXIMUM_RECOVERY_BUNDLE_BYTES, RecoveryBundle, RecoveryBundleParts};
pub use code::{RecoveryBundleCode, RecoveryChallenge};
pub use consensus_admission::{RecoveryConsensusAdmission, RecoveryConsensusAdmissionClaims};
pub use error::RecoveryBundleError;
pub use material::{
    OfflineRecoveryIdentity, RecoveredAuthority, create_recovery_bundle,
    create_recovery_bundle_with_code,
};

#[cfg(test)]
mod tests;
