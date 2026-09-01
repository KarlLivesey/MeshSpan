// SPDX-License-Identifier: GPL-2.0-only

//! Recovery authority creation and authenticated restoration.

use meshspan_certificates::CertificateAuthority;
use meshspan_domain::{MeshId, RandomSource};
use meshspan_secret_envelope::{WrappingPrivateKey, WrappingPublicKey};

use crate::bundle::certificate_digest;
use crate::{RecoveryBundle, RecoveryBundleCode, RecoveryBundleError};

/// Public recovery identity safe for atomic commitment during first-mesh bootstrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineRecoveryIdentity {
    mesh_id: MeshId,
    public_wrapping_key: WrappingPublicKey,
    root_certificate_der: Vec<u8>,
    bundle_digest: [u8; 32],
}

impl OfflineRecoveryIdentity {
    /// Reconstructs public identity from an already validated encrypted bundle.
    ///
    /// # Errors
    ///
    /// Fails only if validated in-memory public-key evidence has been corrupted.
    pub fn from_bundle(bundle: &RecoveryBundle) -> Result<Self, RecoveryBundleError> {
        Ok(Self {
            mesh_id: bundle.mesh_id(),
            public_wrapping_key: bundle.recovery_public_key()?,
            root_certificate_der: bundle.root_certificate_der().to_vec(),
            bundle_digest: bundle.digest(),
        })
    }

    /// Returns the exact owning mesh.
    #[must_use]
    pub const fn mesh_id(&self) -> MeshId {
        self.mesh_id
    }

    /// Returns the offline public recipient for every recoverable secret generation.
    #[must_use]
    pub const fn public_wrapping_key(&self) -> WrappingPublicKey {
        self.public_wrapping_key
    }

    /// Borrows the immutable offline root certificate.
    #[must_use]
    pub fn root_certificate_der(&self) -> &[u8] {
        &self.root_certificate_der
    }

    /// Returns the digest binding the exact encrypted bundle delivered for this identity.
    #[must_use]
    pub const fn bundle_digest(&self) -> [u8; 32] {
        self.bundle_digest
    }
}

/// Decrypted offline authority available only inside an explicit recovery process.
///
/// This type implements neither `Clone`, `Debug` nor key export convenience methods.
pub struct RecoveredAuthority {
    recovery_key: WrappingPrivateKey,
    root_authority: CertificateAuthority,
}

impl RecoveredAuthority {
    /// Returns the recovery public key for exact comparison with committed identity.
    #[must_use]
    pub fn public_wrapping_key(&self) -> WrappingPublicKey {
        self.recovery_key.public_key()
    }

    /// Borrows the reconstructed root certificate for exact committed-identity comparison.
    #[must_use]
    pub fn root_certificate_der(&self) -> &[u8] {
        self.root_authority.certificate_der()
    }

    /// Borrows the private recovery key only for opening one exact committed recipient envelope.
    #[must_use]
    pub const fn wrapping_key(&self) -> &WrappingPrivateKey {
        &self.recovery_key
    }
}

/// Creates one offline root authority, encrypted bundle and independently stored random code.
///
/// # Errors
///
/// Fails without a partial result when entropy, certificate construction, encryption or bounded
/// canonical encoding is unavailable.
pub fn create_recovery_bundle(
    mesh_id: MeshId,
    random: &mut impl RandomSource,
) -> Result<(RecoveryBundle, RecoveryBundleCode, OfflineRecoveryIdentity), RecoveryBundleError> {
    let code = RecoveryBundleCode::generate(random)?;
    let (bundle, identity) = create_recovery_bundle_with_code(mesh_id, &code, random)?;
    Ok((bundle, code, identity))
}

/// Creates an offline authority using an independently derived high-entropy recovery code.
///
/// This is the restart-safe bootstrap path: the same claimed operation can reconstruct its code,
/// while the exact encrypted bundle is generated once and retained until save verification.
///
/// # Errors
///
/// Fails without a partial result when entropy, certificate construction, encryption or bounded
/// canonical encoding is unavailable.
pub fn create_recovery_bundle_with_code(
    mesh_id: MeshId,
    code: &RecoveryBundleCode,
    random: &mut impl RandomSource,
) -> Result<(RecoveryBundle, OfflineRecoveryIdentity), RecoveryBundleError> {
    let recovery_key =
        WrappingPrivateKey::generate(random).map_err(|_| RecoveryBundleError::Entropy)?;
    let root_authority =
        CertificateAuthority::new().map_err(|_| RecoveryBundleError::Certificate)?;
    let bundle = RecoveryBundle::encrypt(
        mesh_id,
        &recovery_key,
        root_authority.certificate_der(),
        root_authority.private_key_pkcs8(),
        code,
        random,
    )?;
    let identity = OfflineRecoveryIdentity {
        mesh_id,
        public_wrapping_key: recovery_key.public_key(),
        root_certificate_der: root_authority.certificate_der().to_vec(),
        bundle_digest: bundle.digest(),
    };
    Ok((bundle, identity))
}

impl RecoveryBundle {
    /// Decrypts and reconstructs this exact offline authority.
    ///
    /// # Errors
    ///
    /// Rejects an incorrect code, tampering, substituted keys or a root private key whose
    /// regenerated certificate differs from the authenticated public certificate.
    pub fn open(
        &self,
        code: &RecoveryBundleCode,
    ) -> Result<RecoveredAuthority, RecoveryBundleError> {
        let private = self.decrypt_private_payload(code)?;
        let recovery_key = WrappingPrivateKey::from_bytes(private.recovery_private_key)
            .map_err(|_| RecoveryBundleError::Corrupt)?;
        if recovery_key.public_key() != self.recovery_public_key()? {
            return Err(RecoveryBundleError::Corrupt);
        }
        if private.root_certificate_digest != certificate_digest(self.root_certificate_der()) {
            return Err(RecoveryBundleError::Corrupt);
        }
        let root_authority = CertificateAuthority::from_pkcs8(&private.root_private_key)
            .map_err(|_| RecoveryBundleError::Corrupt)?;
        if root_authority.certificate_der() != self.root_certificate_der() {
            return Err(RecoveryBundleError::Corrupt);
        }
        Ok(RecoveredAuthority {
            recovery_key,
            root_authority,
        })
    }
}
