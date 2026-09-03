// SPDX-License-Identifier: GPL-2.0-only

//! Bounded mesh-local HTTPS certificate authority and endpoint issuance.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyUsagePurpose,
};
use thiserror::Error;
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer as _;
use zeroize::Zeroizing;

use super::external_request::validate_dns_names;
use super::{ExternalCertificateRequestKey, RustCryptoKey};

const MAXIMUM_CA_LIFETIME_SECONDS: u64 = 20 * 366 * 24 * 60 * 60;
const MAXIMUM_LEAF_LIFETIME_SECONDS: u64 = 398 * 24 * 60 * 60;

/// A self-contained, reloadable authority used only for locally trusted HTTPS identities.
///
/// The private key is neither cloneable nor printable and is exposed only for immediate envelope
/// encryption. Persisted callers must keep the key in an encrypted secret generation. The public
/// certificate is the trust bundle installed by clients which opt into mesh-local trust.
pub struct MeshLocalCertificateAuthority {
    certificate_der: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
    issuer: Issuer<'static, RustCryptoKey>,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
}

impl MeshLocalCertificateAuthority {
    /// Generates one self-signed authority with an exact bounded validity interval.
    ///
    /// # Errors
    ///
    /// Rejects an empty, unrepresentable or excessive lifetime and fails when operating-system
    /// entropy, key construction or certificate encoding is unavailable.
    pub fn generate(
        not_before_unix_seconds: u64,
        not_after_unix_seconds: u64,
    ) -> Result<Self, MeshLocalCertificateAuthorityError> {
        validate_lifetime(
            not_before_unix_seconds,
            not_after_unix_seconds,
            MAXIMUM_CA_LIFETIME_SECONDS,
        )?;
        let key = RustCryptoKey::generate()?;
        let parameters =
            authority_parameters(&key, not_before_unix_seconds, not_after_unix_seconds)?;
        let certificate_der = parameters.self_signed(&key)?.der().to_vec();
        let private_key = key.private_key.clone();
        Ok(Self {
            certificate_der,
            private_key,
            issuer: Issuer::new(parameters, key),
            not_before_unix_seconds,
            not_after_unix_seconds,
        })
    }

    /// Reloads and proves one exact persisted authority certificate/private-key pair.
    ///
    /// # Errors
    ///
    /// Rejects malformed DER, a non-CA certificate, missing signing use, a mismatched key,
    /// unsupported lifetime, trailing bytes or an authority not valid at `now_unix_seconds`.
    pub fn from_parts(
        certificate_der: &[u8],
        private_key_pkcs8: &[u8],
        now_unix_seconds: u64,
    ) -> Result<Self, MeshLocalCertificateAuthorityError> {
        let key = RustCryptoKey::from_pkcs8(private_key_pkcs8)?;
        let (remainder, certificate) = X509Certificate::from_der(certificate_der)
            .map_err(|_| MeshLocalCertificateAuthorityError::InvalidMaterial)?;
        if !remainder.is_empty() {
            return Err(MeshLocalCertificateAuthorityError::InvalidMaterial);
        }
        let not_before_unix_seconds = u64::try_from(certificate.validity().not_before.timestamp())
            .map_err(|_| MeshLocalCertificateAuthorityError::InvalidLifetime)?;
        let not_after_unix_seconds = u64::try_from(certificate.validity().not_after.timestamp())
            .map_err(|_| MeshLocalCertificateAuthorityError::InvalidLifetime)?;
        validate_lifetime(
            not_before_unix_seconds,
            not_after_unix_seconds,
            MAXIMUM_CA_LIFETIME_SECONDS,
        )?;
        if now_unix_seconds < not_before_unix_seconds || now_unix_seconds >= not_after_unix_seconds
        {
            return Err(MeshLocalCertificateAuthorityError::InvalidMaterial);
        }
        let parameters =
            authority_parameters(&key, not_before_unix_seconds, not_after_unix_seconds)?;
        let expected_certificate = parameters.self_signed(&key)?.der().to_vec();
        if expected_certificate != certificate_der {
            return Err(MeshLocalCertificateAuthorityError::InvalidMaterial);
        }
        let issuer = Issuer::new(parameters, key);
        Ok(Self {
            certificate_der: certificate_der.to_vec(),
            private_key: Zeroizing::new(private_key_pkcs8.to_vec()),
            issuer,
            not_before_unix_seconds,
            not_after_unix_seconds,
        })
    }

    /// Borrows the self-signed public trust anchor in DER form.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Borrows the authority key only for immediate protected persistence.
    #[must_use]
    pub fn private_key_pkcs8(&self) -> &[u8] {
        &self.private_key
    }

    /// Returns the inclusive authority validity start in Unix seconds.
    #[must_use]
    pub const fn not_before_unix_seconds(&self) -> u64 {
        self.not_before_unix_seconds
    }

    /// Returns the exclusive authority validity end in Unix seconds.
    #[must_use]
    pub const fn not_after_unix_seconds(&self) -> u64 {
        self.not_after_unix_seconds
    }

    /// Issues one server-only endpoint certificate for an existing generation-owned key.
    ///
    /// The leaf validity must be non-empty, no longer than 398 days and wholly contained by the
    /// authority lifetime. DNS names must be lower-case, sorted and unique.
    ///
    /// # Errors
    ///
    /// Rejects invalid names or lifetime and fails closed on certificate construction failure.
    pub fn issue_endpoint(
        &self,
        dns_names: &[String],
        request_key: &ExternalCertificateRequestKey,
        not_before_unix_seconds: u64,
        not_after_unix_seconds: u64,
    ) -> Result<Vec<u8>, MeshLocalCertificateAuthorityError> {
        validate_dns_names(dns_names)
            .map_err(|_| MeshLocalCertificateAuthorityError::InvalidNames)?;
        validate_lifetime(
            not_before_unix_seconds,
            not_after_unix_seconds,
            MAXIMUM_LEAF_LIFETIME_SECONDS,
        )?;
        if not_before_unix_seconds < self.not_before_unix_seconds
            || not_after_unix_seconds > self.not_after_unix_seconds
        {
            return Err(MeshLocalCertificateAuthorityError::InvalidLifetime);
        }
        let key = request_key.signing_key();
        let mut parameters = CertificateParams::new(dns_names.to_vec())?;
        parameters.distinguished_name = DistinguishedName::new();
        parameters.not_before = timestamp(not_before_unix_seconds)?;
        parameters.not_after = timestamp(not_after_unix_seconds)?;
        parameters
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        parameters
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        parameters.serial_number = Some(key.serial_number());
        parameters.key_identifier_method = key.identifier();
        parameters.use_authority_key_identifier_extension = true;
        Ok(parameters.signed_by(key, &self.issuer)?.der().to_vec())
    }
}

fn authority_parameters(
    key: &RustCryptoKey,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
) -> Result<CertificateParams, MeshLocalCertificateAuthorityError> {
    let mut parameters = CertificateParams::new(Vec::<String>::new())?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "MeshSpan Local HTTPS CA");
    parameters.distinguished_name = name;
    parameters.not_before = timestamp(not_before_unix_seconds)?;
    parameters.not_after = timestamp(not_after_unix_seconds)?;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    parameters
        .key_usages
        .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
    parameters.serial_number = Some(key.serial_number());
    parameters.key_identifier_method = key.identifier();
    parameters.use_authority_key_identifier_extension = true;
    Ok(parameters)
}

fn timestamp(seconds: u64) -> Result<OffsetDateTime, MeshLocalCertificateAuthorityError> {
    let seconds =
        i64::try_from(seconds).map_err(|_| MeshLocalCertificateAuthorityError::InvalidLifetime)?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| MeshLocalCertificateAuthorityError::InvalidLifetime)
}

fn validate_lifetime(
    not_before: u64,
    not_after: u64,
    maximum: u64,
) -> Result<(), MeshLocalCertificateAuthorityError> {
    if not_after <= not_before || not_after - not_before > maximum {
        Err(MeshLocalCertificateAuthorityError::InvalidLifetime)
    } else {
        timestamp(not_before)?;
        timestamp(not_after)?;
        Ok(())
    }
}

/// Closed mesh-local authority construction or loading failure.
#[derive(Debug, Error)]
pub enum MeshLocalCertificateAuthorityError {
    /// The requested DNS names are not canonical or safely bounded.
    #[error("mesh-local certificate names are invalid")]
    InvalidNames,
    /// The requested or persisted validity interval is invalid or excessive.
    #[error("mesh-local certificate lifetime is invalid")]
    InvalidLifetime,
    /// Persisted authority material is malformed, mismatched or not a signing CA.
    #[error("mesh-local certificate authority material is invalid")]
    InvalidMaterial,
    /// Certificate key construction failed.
    #[error("mesh-local certificate key construction failed")]
    Certificate(#[from] super::CertificateError),
    /// X.509 construction failed.
    #[error("mesh-local X.509 construction failed")]
    X509(#[from] rcgen::Error),
}

#[cfg(test)]
mod tests {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer as _;

    use super::{MeshLocalCertificateAuthority, MeshLocalCertificateAuthorityError};
    use crate::ExternalCertificateRequestKey;

    const START: u64 = 1_800_000_000;
    const CA_END: u64 = START + 5 * 365 * 24 * 60 * 60;

    #[test]
    fn authority_reloads_and_issues_exact_server_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let authority = MeshLocalCertificateAuthority::generate(START, CA_END)?;
        let reloaded = MeshLocalCertificateAuthority::from_parts(
            authority.certificate_der(),
            authority.private_key_pkcs8(),
            START,
        )?;
        let key = ExternalCertificateRequestKey::generate()?;
        let names = vec![
            "files.mesh.test".to_owned(),
            "node.files.mesh.test".to_owned(),
        ];
        let leaf_end = START + 90 * 24 * 60 * 60;
        let leaf = reloaded.issue_endpoint(&names, &key, START, leaf_end)?;
        let (remainder, certificate) = X509Certificate::from_der(&leaf)?;

        assert!(remainder.is_empty());
        assert_eq!(
            certificate.validity().not_before.timestamp(),
            i64::try_from(START)?
        );
        assert_eq!(
            certificate.validity().not_after.timestamp(),
            i64::try_from(leaf_end)?
        );
        assert_eq!(
            certificate
                .extended_key_usage()?
                .map(|usage| usage.value.server_auth),
            Some(true)
        );
        Ok(())
    }

    #[test]
    fn authority_rejects_wrong_key_expiry_and_excessive_leaf_lifetime()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = MeshLocalCertificateAuthority::generate(START, CA_END)?;
        let wrong_key = MeshLocalCertificateAuthority::generate(START, CA_END)?;
        assert!(matches!(
            MeshLocalCertificateAuthority::from_parts(
                authority.certificate_der(),
                wrong_key.private_key_pkcs8(),
                START,
            ),
            Err(MeshLocalCertificateAuthorityError::InvalidMaterial)
        ));
        assert!(matches!(
            MeshLocalCertificateAuthority::from_parts(
                authority.certificate_der(),
                authority.private_key_pkcs8(),
                CA_END,
            ),
            Err(MeshLocalCertificateAuthorityError::InvalidMaterial)
        ));
        let leaf_key = ExternalCertificateRequestKey::generate()?;
        assert!(matches!(
            authority.issue_endpoint(
                &["files.mesh.test".to_owned()],
                &leaf_key,
                START,
                START + 399 * 24 * 60 * 60,
            ),
            Err(MeshLocalCertificateAuthorityError::InvalidLifetime)
        ));
        Ok(())
    }
}
