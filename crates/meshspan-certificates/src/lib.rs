// SPDX-License-Identifier: GPL-2.0-only

//! Provider-neutral X.509 construction for `MeshSpan` identities and real transport tests.
//!
//! Current `rcgen` is used only for X.509 DER construction. Key generation and ECDSA signing use
//! current `RustCrypto` P-256, so enabling an `rcgen` crypto provider cannot silently change the
//! dependency graph or choose a different cryptographic backend.

mod external_request;
mod public_bundle;

use p256::ecdsa::signature::{SignatureEncoding as _, Signer as _, Verifier as _};
use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyIdMethod, KeyUsagePurpose, PublicKeyData, SerialNumber, SigningKey,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub use external_request::ExternalCertificateRequestKey;
pub use public_bundle::{PublicCertificateBundle, PublicCertificateBundleError};

const KEY_BYTES: usize = 32;
const KEY_GENERATION_ATTEMPTS: usize = 16;
const KEY_IDENTIFIER_BYTES: usize = 20;

/// An ECDSA P-256 certificate authority and its provider-neutral signing key.
pub struct CertificateAuthority {
    certificate_der: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
    issuer: Issuer<'static, RustCryptoKey>,
}

/// Rotatable online node-certificate authority signed by the offline mesh root.
///
/// Its encrypted private key may be distributed to authorised voters. The offline root private
/// key remains only in the recovery bundle and is not required for routine node enrolment.
pub struct OnlineCertificateAuthority {
    certificate_der: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
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

/// Validated public half of one node-owned P-256 identity.
///
/// The joining node retains its private key and proves possession by signing the exact enrolment
/// transcript. The admitting swarm uses this value only after that proof has been verified.
pub struct NodePublicIdentity {
    key: p256::ecdsa::VerifyingKey,
    public_key: Vec<u8>,
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

    /// Borrows the canonical uncompressed SEC1 public identity for enrolment.
    #[must_use]
    pub fn public_key_sec1(&self) -> &[u8] {
        &self.key.public_key
    }

    /// Signs an exact caller-defined enrolment transcript with the node-owned private key.
    ///
    /// # Errors
    ///
    /// Fails closed if the cryptographic provider cannot produce a canonical DER signature.
    pub fn sign_enrolment_transcript(
        &self,
        transcript: &[u8],
    ) -> Result<Vec<u8>, CertificateError> {
        self.key
            .sign(transcript)
            .map_err(CertificateError::Certificate)
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

impl NodePublicIdentity {
    /// Parses one exact canonical uncompressed P-256 public identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed, compressed, off-curve and non-canonical values.
    pub fn from_sec1(public_key: &[u8]) -> Result<Self, CertificateError> {
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|_| CertificateError::PublicKeyDecoding)?;
        let canonical = key.to_sec1_point(false);
        if canonical.as_bytes() != public_key {
            return Err(CertificateError::PublicKeyDecoding);
        }
        Ok(Self {
            key,
            public_key: canonical.as_bytes().to_vec(),
        })
    }

    /// Returns a SHA-256 fingerprint of the canonical subject public-key information.
    #[must_use]
    pub fn public_key_fingerprint(&self) -> [u8; 32] {
        Sha256::digest(self.subject_public_key_info()).into()
    }

    /// Verifies the joining node's signature over the exact enrolment transcript.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical or invalid DER-encoded P-256 signatures.
    pub fn verify_enrolment_transcript(
        &self,
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<(), CertificateError> {
        let signature = p256::ecdsa::DerSignature::from_bytes(signature)
            .map_err(|_| CertificateError::InvalidIdentityProof)?;
        self.key
            .verify(transcript, &signature)
            .map_err(|_| CertificateError::InvalidIdentityProof)
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
        Self::from_key(key)
    }

    /// Loads one exact canonical PKCS#8 P-256 authority identity.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical or wrong-algorithm private key bytes.
    pub fn from_pkcs8(private_key: &[u8]) -> Result<Self, CertificateError> {
        Self::from_key(RustCryptoKey::from_pkcs8(private_key)?)
    }

    fn from_key(key: RustCryptoKey) -> Result<Self, CertificateError> {
        let parameters = authority_parameters(&key)?;
        let certificate_der = parameters.self_signed(&key)?.der().to_vec();
        let private_key = key.private_key.clone();
        Ok(Self {
            certificate_der,
            private_key,
            issuer: Issuer::new(parameters, key),
        })
    }

    /// Returns the authority certificate trusted by issued peers.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Borrows the canonical PKCS#8 authority key for immediate protected persistence.
    #[must_use]
    pub fn private_key_pkcs8(&self) -> &[u8] {
        &self.private_key
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

    /// Creates a rotatable online authority signed by this offline root.
    ///
    /// # Errors
    ///
    /// Fails when entropy, key generation or X.509 construction is unavailable.
    pub fn issue_online_authority(&self) -> Result<OnlineCertificateAuthority, CertificateError> {
        let key = RustCryptoKey::generate()?;
        self.issue_online_authority_for_key(key)
    }

    /// Deterministically recreates one exact online-authority generation for a restart-safe
    /// first-mesh transaction.
    ///
    /// # Errors
    ///
    /// Rejects a zero seed or a seed whose bounded derivation cannot produce a P-256 scalar.
    pub fn issue_online_authority_from_seed(
        &self,
        seed: [u8; KEY_BYTES],
    ) -> Result<OnlineCertificateAuthority, CertificateError> {
        self.issue_online_authority_for_key(RustCryptoKey::from_seed(seed)?)
    }

    fn issue_online_authority_for_key(
        &self,
        key: RustCryptoKey,
    ) -> Result<OnlineCertificateAuthority, CertificateError> {
        let parameters = online_authority_parameters(&key)?;
        let certificate_der = parameters.signed_by(&key, &self.issuer)?.der().to_vec();
        OnlineCertificateAuthority::from_parts(key, certificate_der)
    }

    /// Signs an existing node-owned public identity without moving its private key.
    ///
    /// # Errors
    ///
    /// Rejects an invalid DNS name or X.509 construction failure.
    pub fn sign_node_identity(
        &self,
        identity: &NodeIdentityKey,
        dns_name: &str,
    ) -> Result<Vec<u8>, CertificateError> {
        let parameters = node_parameters(&identity.key, dns_name)?;
        Ok(parameters
            .signed_by(&identity.key, &self.issuer)?
            .der()
            .to_vec())
    }

    /// Signs an already verified node-owned public identity without receiving its private key.
    ///
    /// # Errors
    ///
    /// Rejects an invalid DNS name or X.509 construction failure.
    pub fn sign_node_public_identity(
        &self,
        identity: &NodePublicIdentity,
        dns_name: &str,
    ) -> Result<Vec<u8>, CertificateError> {
        let parameters = node_parameters(identity, dns_name)?;
        Ok(parameters.signed_by(identity, &self.issuer)?.der().to_vec())
    }
}

impl OnlineCertificateAuthority {
    /// Reopens an encrypted-at-rest online authority generation.
    ///
    /// The exact certificate is carried separately from the private key because it was signed by
    /// the offline root. TLS composition subsequently proves their match before service starts.
    ///
    /// # Errors
    ///
    /// Rejects an empty certificate or malformed, non-canonical P-256 private key.
    pub fn from_pkcs8_and_certificate(
        private_key: &[u8],
        certificate_der: &[u8],
    ) -> Result<Self, CertificateError> {
        if certificate_der.is_empty() {
            return Err(CertificateError::CertificateMaterial);
        }
        Self::from_parts(
            RustCryptoKey::from_pkcs8(private_key)?,
            certificate_der.to_vec(),
        )
    }

    fn from_parts(key: RustCryptoKey, certificate_der: Vec<u8>) -> Result<Self, CertificateError> {
        let parameters = online_authority_parameters(&key)?;
        let private_key = key.private_key.clone();
        Ok(Self {
            certificate_der,
            private_key,
            issuer: Issuer::new(parameters, key),
        })
    }

    /// Borrows the root-signed online authority certificate.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Borrows the private key only for immediate envelope encryption or protected loading.
    #[must_use]
    pub fn private_key_pkcs8(&self) -> &[u8] {
        &self.private_key
    }

    /// Signs an already verified node-owned public identity.
    ///
    /// # Errors
    ///
    /// Rejects an invalid DNS name or X.509 construction failure.
    pub fn sign_node_public_identity(
        &self,
        identity: &NodePublicIdentity,
        dns_name: &str,
    ) -> Result<Vec<u8>, CertificateError> {
        let parameters = node_parameters(identity, dns_name)?;
        Ok(parameters.signed_by(identity, &self.issuer)?.der().to_vec())
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
    /// Public identity input was malformed or not canonical uncompressed P-256 SEC1.
    #[error("P-256 certificate public key is invalid")]
    PublicKeyDecoding,
    /// The node did not prove possession of the private key for its submitted public identity.
    #[error("node identity possession proof is invalid")]
    InvalidIdentityProof,
    /// A persisted certificate/key pair was absent or internally inconsistent.
    #[error("certificate authority material is invalid")]
    CertificateMaterial,
    /// The requested public-certificate name set or PKCS#10 request is invalid.
    #[error("external certificate request is invalid")]
    CertificateRequest,
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

    fn from_seed(seed: [u8; KEY_BYTES]) -> Result<Self, CertificateError> {
        if seed == [0; KEY_BYTES] {
            return Err(CertificateError::KeyGeneration);
        }
        let mut candidate = Zeroizing::new(seed);
        for attempt in 0..KEY_GENERATION_ATTEMPTS {
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(candidate.as_ref()) {
                return Self::from_signing_key(key);
            }
            let mut digest = Sha256::new();
            digest.update(b"meshspan.online-certificate-authority-key.v1");
            digest.update(seed);
            digest.update(
                u64::try_from(attempt)
                    .map_err(|_| CertificateError::KeyGeneration)?
                    .to_be_bytes(),
            );
            candidate.copy_from_slice(&digest.finalize());
        }
        Err(CertificateError::KeyGeneration)
    }

    fn from_signing_key(key: p256::ecdsa::SigningKey) -> Result<Self, CertificateError> {
        let public_key = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        let private_key = Zeroizing::new(
            key.to_pkcs8_der()
                .map_err(|_| CertificateError::KeyEncoding)?
                .as_bytes()
                .to_vec(),
        );
        Ok(Self {
            key,
            public_key,
            private_key,
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
    key: &impl PublicKeyData,
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
    parameters.serial_number = Some(serial_number(key));
    parameters.key_identifier_method = identifier(key);
    Ok(parameters)
}

fn identifier(key: &impl PublicKeyData) -> KeyIdMethod {
    let digest = Sha256::digest(key.subject_public_key_info());
    KeyIdMethod::PreSpecified(digest[..KEY_IDENTIFIER_BYTES].to_vec())
}

fn serial_number(key: &impl PublicKeyData) -> SerialNumber {
    let digest = Sha256::digest(key.subject_public_key_info());
    SerialNumber::from_slice(&digest[..KEY_IDENTIFIER_BYTES])
}

fn authority_parameters(key: &RustCryptoKey) -> Result<CertificateParams, CertificateError> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.distinguished_name = distinguished_name("MeshSpan Offline Root");
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters
        .key_usages
        .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
    parameters.serial_number = Some(key.serial_number());
    parameters.key_identifier_method = key.identifier();
    Ok(parameters)
}

fn online_authority_parameters(key: &RustCryptoKey) -> Result<CertificateParams, CertificateError> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    parameters.distinguished_name = distinguished_name("MeshSpan Online Node CA");
    parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    parameters
        .key_usages
        .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
    parameters.serial_number = Some(key.serial_number());
    parameters.key_identifier_method = key.identifier();
    Ok(parameters)
}

fn distinguished_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    name
}

impl PublicKeyData for RustCryptoKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl PublicKeyData for NodePublicIdentity {
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
    use super::{
        CertificateAuthority, NodeIdentityKey, NodePublicIdentity, OnlineCertificateAuthority,
    };

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

    #[test]
    fn authority_reloads_and_signs_the_same_node_owned_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = CertificateAuthority::new()?;
        let identity = NodeIdentityKey::generate()?;
        let authority_certificate = authority.certificate_der().to_vec();
        let node_certificate = authority.sign_node_identity(&identity, "meshspan.internal")?;
        let reopened = CertificateAuthority::from_pkcs8(authority.private_key_pkcs8())?;
        assert_eq!(reopened.certificate_der(), authority_certificate);
        assert_eq!(
            reopened.sign_node_identity(&identity, "meshspan.internal")?,
            node_certificate
        );
        assert_ne!(node_certificate, identity.self_signed("meshspan.internal")?);
        Ok(())
    }

    #[test]
    fn node_proves_its_public_identity_before_the_authority_signs_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = CertificateAuthority::new()?;
        let identity = NodeIdentityKey::generate()?;
        let public_identity = NodePublicIdentity::from_sec1(identity.public_key_sec1())?;
        let transcript = b"meshspan enrolment transcript";
        let signature = identity.sign_enrolment_transcript(transcript)?;

        public_identity.verify_enrolment_transcript(transcript, &signature)?;
        assert_eq!(
            public_identity.public_key_fingerprint(),
            identity.public_key_fingerprint()
        );
        assert_eq!(
            authority.sign_node_public_identity(&public_identity, "meshspan.internal")?,
            authority.sign_node_identity(&identity, "meshspan.internal")?
        );
        assert!(
            public_identity
                .verify_enrolment_transcript(b"substituted transcript", &signature)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn online_authority_reopens_without_the_offline_root() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = CertificateAuthority::new()?;
        let online = root.issue_online_authority()?;
        let online_certificate = online.certificate_der().to_vec();
        let online_key = online.private_key_pkcs8().to_vec();
        let node = NodeIdentityKey::generate()?;
        let public_node = NodePublicIdentity::from_sec1(node.public_key_sec1())?;
        let expected = online.sign_node_public_identity(&public_node, "meshspan.internal")?;

        let reopened = OnlineCertificateAuthority::from_pkcs8_and_certificate(
            &online_key,
            &online_certificate,
        )?;
        assert_eq!(reopened.certificate_der(), online_certificate);
        assert_eq!(
            reopened.sign_node_public_identity(&public_node, "meshspan.internal")?,
            expected
        );
        Ok(())
    }

    #[test]
    fn online_authority_seed_is_exact_retry_stable() -> Result<(), Box<dyn std::error::Error>> {
        let root = CertificateAuthority::new()?;
        let first = root.issue_online_authority_from_seed([41; 32])?;
        let replay = root.issue_online_authority_from_seed([41; 32])?;
        assert_eq!(first.certificate_der(), replay.certificate_der());
        assert_eq!(first.private_key_pkcs8(), replay.private_key_pkcs8());
        assert!(root.issue_online_authority_from_seed([0; 32]).is_err());
        Ok(())
    }
}
