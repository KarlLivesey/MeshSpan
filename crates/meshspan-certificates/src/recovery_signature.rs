// SPDX-License-Identifier: GPL-2.0-only

//! Offline-root authorisation signatures, separate from TLS, enrolment and software updates.

use p256::ecdsa::signature::Verifier as _;
use rcgen::SigningKey as _;
use x509_parser::prelude::{FromDer as _, X509Certificate};

use crate::{CertificateAuthority, CertificateError, RustCryptoKey};

const DOMAIN: &[u8] = b"MeshSpan recovery authorisation v1\0";
const MAXIMUM_MANIFEST_BYTES: usize = 16 * 1024;
const MAXIMUM_ROOT_BYTES: usize = 16 * 1024;

impl CertificateAuthority {
    /// Signs a bounded, canonical recovery manifest with the offline root.
    /// This does not itself authorise database installation or consensus reset.
    /// # Errors
    /// Rejects empty/oversized manifests, invalid key state or signing failure.
    pub fn sign_recovery_manifest(&self, manifest: &[u8]) -> Result<Vec<u8>, CertificateError> {
        RustCryptoKey::from_pkcs8(&self.private_key)?
            .sign(&payload(manifest)?)
            .map_err(CertificateError::from)
    }
}

/// Verifies exact recovery bytes against an independently trusted offline-root certificate.
/// The trust anchor must come from verified mesh state, not from the proposed recovery itself.
/// Signature validity is not admission, epoch freshness, or proof that old nodes are offline.
/// # Errors
/// Rejects malformed/non-CA anchors, non-canonical keys, invalid DER signatures,
/// excessive input, changed manifests and signatures from another operation domain.
pub fn verify_recovery_signature(
    trusted_root: &[u8],
    manifest: &[u8],
    signature: &[u8],
) -> Result<(), CertificateError> {
    if trusted_root.is_empty() || trusted_root.len() > MAXIMUM_ROOT_BYTES || signature.len() > 72 {
        return Err(CertificateError::InvalidIdentityProof);
    }
    let (tail, certificate) = X509Certificate::from_der(trusted_root)
        .map_err(|_| CertificateError::InvalidIdentityProof)?;
    if !tail.is_empty() || !certificate.is_ca() {
        return Err(CertificateError::InvalidIdentityProof);
    }
    let public = certificate.public_key().subject_public_key.data.as_ref();
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public)
        .map_err(|_| CertificateError::PublicKeyDecoding)?;
    if key.to_sec1_point(false).as_bytes() != public {
        return Err(CertificateError::PublicKeyDecoding);
    }
    let signature = p256::ecdsa::DerSignature::from_bytes(signature)
        .map_err(|_| CertificateError::InvalidIdentityProof)?;
    key.verify(&payload(manifest)?, &signature)
        .map_err(|_| CertificateError::InvalidIdentityProof)
}

fn payload(manifest: &[u8]) -> Result<Vec<u8>, CertificateError> {
    if manifest.is_empty() || manifest.len() > MAXIMUM_MANIFEST_BYTES {
        return Err(CertificateError::InvalidIdentityProof);
    }
    let mut bytes = Vec::with_capacity(DOMAIN.len() + manifest.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(manifest);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UPDATE_SIGNATURE_DOMAIN;

    #[test]
    fn recovery_signatures_reject_other_domains_and_non_ca_certificates()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = CertificateAuthority::new()?;
        let manifest = b"exact recovery intent";
        let signature = root.sign_recovery_manifest(manifest)?;
        verify_recovery_signature(root.certificate_der(), manifest, &signature)?;
        let key = RustCryptoKey::from_pkcs8(&root.private_key)?;
        for prefix in [b"".as_slice(), UPDATE_SIGNATURE_DOMAIN] {
            let mut wrong_domain = prefix.to_vec();
            wrong_domain.extend_from_slice(manifest);
            let wrong_signature = key.sign(&wrong_domain)?;
            assert!(
                verify_recovery_signature(root.certificate_der(), manifest, &wrong_signature)
                    .is_err()
            );
        }
        let leaf = root.issue_node("meshspan.internal")?;
        assert!(verify_recovery_signature(leaf.certificate_der(), manifest, &signature).is_err());
        for manifest in [Vec::new(), vec![0; MAXIMUM_MANIFEST_BYTES + 1]] {
            assert!(root.sign_recovery_manifest(&manifest).is_err());
            assert!(
                verify_recovery_signature(root.certificate_der(), &manifest, &signature).is_err()
            );
        }
        Ok(())
    }
}
