// SPDX-License-Identifier: GPL-2.0-only

//! Provider-neutral X.509 construction for `MeshSpan` identities and real transport tests.
//!
//! Current `rcgen` is used only for X.509 DER construction. Key generation and ECDSA signing use
//! current `RustCrypto` P-256, so enabling an `rcgen` crypto provider cannot silently change the
//! dependency graph or choose a different cryptographic backend.

use p256::ecdsa::signature::{SignatureEncoding as _, Signer as _};
use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod,
    KeyUsagePurpose, PublicKeyData, SerialNumber, SigningKey,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const KEY_BYTES: usize = 32;
const KEY_GENERATION_ATTEMPTS: usize = 16;
const KEY_IDENTIFIER_BYTES: usize = 20;

/// An ECDSA P-256 certificate authority and its provider-neutral signing key.
pub struct CertificateAuthority {
    certificate_der: Vec<u8>,
    issuer: Issuer<'static, RustCryptoKey>,
}

/// Locally generated node identity key which never leaves its owning daemon.
///
/// The type implements neither `Clone`, `Debug` nor `Display`, and clears its encoded private-key
/// bytes on drop. It may produce a temporary self-signed HTTPS identity before mesh enrolment; an
/// enrolled mesh CA later signs the same public key rather than replacing the private identity.
pub struct NodeIdentityKey {
    key: RustCryptoKey,
}

impl NodeIdentityKey {
    /// Generates a fresh ECDSA P-256 node identity using operating-system entropy.
    ///
    /// # Errors
    ///
    /// Fails when entropy or PKCS#8 encoding is unavailable.
    pub fn generate() -> Result<Self, CertificateError> {
        Ok(Self {
            key: RustCryptoKey::generate()?,
        })
    }

    /// Loads one exact PKCS#8 ECDSA P-256 identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed input and any key for another algorithm or curve.
    pub fn from_pkcs8(private_key: &[u8]) -> Result<Self, CertificateError> {
        Ok(Self {
            key: RustCryptoKey::from_pkcs8(private_key)?,
        })
    }

    /// Returns a SHA-256 fingerprint of the canonical subject public-key information.
    #[must_use]
    pub fn public_key_fingerprint(&self) -> [u8; 32] {
        Sha256::digest(self.key.subject_public_key_info()).into()
    }

    /// Borrows the PKCS#8 private key for immediate protected local persistence.
    #[must_use]
    pub fn private_key_pkcs8(&self) -> &[u8] {
        &self.key.private_key
    }

    /// Creates a temporary self-signed client/server certificate for first-start HTTPS.
    ///
    /// # Errors
    ///
    /// Rejects an invalid DNS name or X.509 construction failure.
    pub fn self_signed(&self, dns_name: &str) -> Result<Vec<u8>, CertificateError> {
        let parameters = node_parameters(&self.key, dns_name)?;
        Ok(parameters.self_signed(&self.key)?.der().to_vec())
    }
}

impl CertificateAuthority {
    /// Creates an independent certificate authority using operating-system entropy.
    ///
    /// # Errors
    ///
    /// Fails when entropy, key generation or X.509 construction fails.
    pub fn new() -> Result<Self, CertificateError> {
        let key = RustCryptoKey::generate()?;
        let mut parameters = CertificateParams::new(Vec::<String>::new())?;
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        parameters
            .key_usages
            .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
        parameters.serial_number = Some(key.serial_number());
        parameters.key_identifier_method = key.identifier();
        let certificate_der = parameters.self_signed(&key)?.der().to_vec();
        Ok(Self {
            certificate_der,
            issuer: Issuer::new(parameters, key),
        })
    }

    /// Returns the authority certificate trusted by issued peers.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Issues a dual client/server-authentication leaf for one DNS name.
    ///
    /// # Errors
    ///
    /// Fails when the name, entropy, key generation or X.509 construction is invalid.
    pub fn issue_node(&self, dns_name: &str) -> Result<IssuedCertificate, CertificateError> {
        let key = RustCryptoKey::generate()?;
        let parameters = node_parameters(&key, dns_name)?;
        let certificate_der = parameters.signed_by(&key, &self.issuer)?.der().to_vec();
        Ok(IssuedCertificate {
            certificate_der,
            private_key: key.private_key,
        })
    }
}

/// One issued leaf certificate and its PKCS#8 private key.
pub struct IssuedCertificate {
    certificate_der: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

impl IssuedCertificate {
    /// Borrows the issued DER certificate.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Borrows the plaintext PKCS#8 key for immediate secure configuration or protected output.
    #[must_use]
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }

    /// Separates the certificate and PKCS#8 key for a caller that owns both values.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.certificate_der, self.private_key.to_vec())
    }
}

/// Provider-neutral certificate construction failure.
#[derive(Debug, Error)]
pub enum CertificateError {
    /// The operating system could not provide entropy.
    #[error("operating-system entropy for a certificate key was unavailable")]
    Entropy,
    /// Random input did not produce a valid P-256 scalar within the fixed retry bound.
    #[error("P-256 certificate key generation exhausted its retry bound")]
    KeyGeneration,
    /// PKCS#8 encoding failed.
    #[error("P-256 certificate key encoding failed")]
    KeyEncoding,
    /// PKCS#8 input was malformed or used a different algorithm or curve.
    #[error("P-256 certificate private key is invalid")]
    KeyDecoding,
    /// X.509 parameter validation or DER construction failed.
    #[error("certificate construction failed")]
    Certificate(#[from] rcgen::Error),
}

struct RustCryptoKey {
    key: p256::ecdsa::SigningKey,
    public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

impl RustCryptoKey {
    fn generate() -> Result<Self, CertificateError> {
        for _ in 0..KEY_GENERATION_ATTEMPTS {
            let mut bytes = Zeroizing::new([0; KEY_BYTES]);
            getrandom::fill(bytes.as_mut()).map_err(|_| CertificateError::Entropy)?;
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(bytes.as_ref()) {
                let public_key = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
                let private_key = Zeroizing::new(
                    key.to_pkcs8_der()
                        .map_err(|_| CertificateError::KeyEncoding)?
                        .as_bytes()
                        .to_vec(),
                );
                return Ok(Self {
                    key,
                    public_key,
                    private_key,
                });
            }
        }
        Err(CertificateError::KeyGeneration)
    }

    fn from_pkcs8(private_key: &[u8]) -> Result<Self, CertificateError> {
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(private_key)
            .map_err(|_| CertificateError::KeyDecoding)?;
        let canonical = key
            .to_pkcs8_der()
            .map_err(|_| CertificateError::KeyEncoding)?;
        if canonical.as_bytes() != private_key {
            return Err(CertificateError::KeyDecoding);
        }
        let public_key = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Ok(Self {
            key,
            public_key,
            private_key: Zeroizing::new(canonical.as_bytes().to_vec()),
        })
    }

    fn identifier(&self) -> KeyIdMethod {
        let digest = Sha256::digest(self.subject_public_key_info());
        KeyIdMethod::PreSpecified(digest[..KEY_IDENTIFIER_BYTES].to_vec())
    }

    fn serial_number(&self) -> SerialNumber {
        let digest = Sha256::digest(self.subject_public_key_info());
        SerialNumber::from_slice(&digest[..KEY_IDENTIFIER_BYTES])
    }
}

fn node_parameters(
    key: &RustCryptoKey,
    dns_name: &str,
) -> Result<CertificateParams, CertificateError> {
    let mut parameters = CertificateParams::new(vec![dns_name.to_owned()])?;
    parameters
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    parameters.extended_key_usages.extend([
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ]);
    parameters.serial_number = Some(key.serial_number());
    parameters.key_identifier_method = key.identifier();
    Ok(parameters)
}

impl PublicKeyData for RustCryptoKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for RustCryptoKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature: p256::ecdsa::DerSignature = self
            .key
            .try_sign(message)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        Ok(signature.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::{CertificateAuthority, NodeIdentityKey};

    #[test]
    fn independently_issued_nodes_have_distinct_keys_and_certificates()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = CertificateAuthority::new()?;
        let first = authority.issue_node("meshspan.internal")?;
        let second = authority.issue_node("meshspan.internal")?;
        assert_ne!(first.certificate_der(), second.certificate_der());
        assert_ne!(first.private_key(), second.private_key());
        Ok(())
    }

    #[test]
    fn node_identity_reloads_with_the_same_key_and_self_signed_certificate()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = NodeIdentityKey::generate()?;
        let fingerprint = identity.public_key_fingerprint();
        let certificate = identity.self_signed("meshspan.internal")?;
        let reopened = NodeIdentityKey::from_pkcs8(identity.private_key_pkcs8())?;
        assert_eq!(reopened.public_key_fingerprint(), fingerprint);
        assert_eq!(
            reopened.self_signed("meshspan.internal")?,
            certificate,
            "the deterministic certificate parameters must reproduce the same leaf"
        );
        assert!(NodeIdentityKey::from_pkcs8(&[0; 32]).is_err());
        Ok(())
    }
}
