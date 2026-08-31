// SPDX-License-Identifier: GPL-2.0-only

//! Provider-neutral X.509 fixtures for real transport tests.
//!
//! Current `rcgen` is used only for X.509 DER construction. Key generation and
//! ECDSA signing use current `RustCrypto` P-256, so enabling an `rcgen` crypto
//! provider cannot silently change the workspace dependency graph.

use p256::ecdsa::signature::{SignatureEncoding as _, Signer as _};
use p256::pkcs8::EncodePrivateKey as _;
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

/// A test certificate authority and its provider-neutral signing key.
pub struct CertificateAuthority {
    certificate_der: Vec<u8>,
    issuer: Issuer<'static, RustCryptoKey>,
}

impl CertificateAuthority {
    /// Creates an independent ECDSA P-256 test authority using operating-system entropy.
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

    /// Returns the authority certificate trusted by both test peers.
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
    private_key: Vec<u8>,
}

impl IssuedCertificate {
    /// Borrows the issued DER certificate.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Borrows the plaintext PKCS#8 key for immediate test configuration or file output.
    #[must_use]
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }

    /// Separates the certificate and PKCS#8 key for fixtures that own both values.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.certificate_der, self.private_key)
    }
}

/// Provider-neutral fixture construction failure.
#[derive(Debug, Error)]
pub enum CertificateError {
    /// The operating system could not provide entropy.
    #[error("operating-system entropy for a test certificate key was unavailable")]
    Entropy,
    /// Random input did not produce a valid P-256 scalar within the fixed retry bound.
    #[error("P-256 test certificate key generation exhausted its retry bound")]
    KeyGeneration,
    /// PKCS#8 encoding failed.
    #[error("P-256 test certificate key encoding failed")]
    KeyEncoding,
    /// X.509 parameter validation or DER construction failed.
    #[error("test certificate construction failed")]
    Certificate(#[from] rcgen::Error),
}

struct RustCryptoKey {
    key: p256::ecdsa::SigningKey,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

impl RustCryptoKey {
    fn generate() -> Result<Self, CertificateError> {
        for _ in 0..KEY_GENERATION_ATTEMPTS {
            let mut bytes = Zeroizing::new([0; KEY_BYTES]);
            getrandom::fill(bytes.as_mut()).map_err(|_| CertificateError::Entropy)?;
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(bytes.as_ref()) {
                let public_key = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
                let private_key = key
                    .to_pkcs8_der()
                    .map_err(|_| CertificateError::KeyEncoding)?
                    .as_bytes()
                    .to_vec();
                return Ok(Self {
                    key,
                    public_key,
                    private_key,
                });
            }
        }
        Err(CertificateError::KeyGeneration)
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
    use super::CertificateAuthority;

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
}
