// SPDX-License-Identifier: GPL-2.0-only

//! Detached update signatures, deliberately separate from node and TLS identities.

use p256::ecdsa::signature::Verifier as _;

use crate::CertificateError;

/// Domain separating update manifests from every other use of an ECDSA key.
pub const UPDATE_SIGNATURE_DOMAIN: &[u8] = b"MeshSpan update manifest v1\0";

/// Verifies an exact bounded manifest using an independently trusted P-256 SEC1 key.
///
/// This verifies authenticity, not installation authority, compatibility or release acceptance.
/// The key must come from the caller's trusted configuration, never from the candidate itself.
/// No operating-system crypto service, command or network lookup is used.
///
/// # Errors
///
/// Rejects non-canonical public keys, malformed DER signatures, oversized manifests or any
/// signature that does not bind the domain and the exact supplied manifest bytes.
pub fn verify_update_signature(
    trusted_public_key: &[u8],
    manifest: &[u8],
    signature: &[u8],
) -> Result<(), CertificateError> {
    if manifest.is_empty() || manifest.len() > 16 * 1_024 || signature.len() > 72 {
        return Err(CertificateError::InvalidIdentityProof);
    }
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(trusted_public_key)
        .map_err(|_| CertificateError::PublicKeyDecoding)?;
    if key.to_sec1_point(false).as_bytes() != trusted_public_key {
        return Err(CertificateError::PublicKeyDecoding);
    }
    let signature = p256::ecdsa::DerSignature::from_bytes(signature)
        .map_err(|_| CertificateError::InvalidIdentityProof)?;
    let mut signed = Vec::with_capacity(UPDATE_SIGNATURE_DOMAIN.len() + manifest.len());
    signed.extend_from_slice(UPDATE_SIGNATURE_DOMAIN);
    signed.extend_from_slice(manifest);
    key.verify(&signed, &signature)
        .map_err(|_| CertificateError::InvalidIdentityProof)
}
