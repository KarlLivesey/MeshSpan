// SPDX-License-Identifier: GPL-2.0-only

//! Online-authority key binding and offline-root authentication.

use rcgen::PublicKeyData as _;
use x509_parser::prelude::{FromDer as _, X509Certificate};

use crate::{CertificateError, NodePublicIdentity, RustCryptoKey};

/// Verifies an online CA's exact issuer, signing capability and signature against a trusted root.
/// Trust must come from independently verified mesh metadata. This checks the certificate's
/// validity interval against its issuer, not against an implicit host clock or service epoch.
/// # Errors
/// Rejects malformed certificates, non-CA usage, wrong issuer/signature, unsupported signature
/// algorithms or a validity interval outside the trusted root's interval.
pub fn validate_online_authority_certificate(
    certificate_der: &[u8],
    trusted_root_der: &[u8],
) -> Result<(), CertificateError> {
    let certificate = parse_ca(certificate_der)?;
    let root = parse_ca(trusted_root_der)?;
    require_online_constraint(&certificate)?;
    if certificate.issuer() != root.subject()
        || certificate.validity().not_before < root.validity().not_before
        || certificate.validity().not_after > root.validity().not_after
        || certificate.signature_algorithm.algorithm.to_id_string() != "1.2.840.10045.4.3.2"
        || certificate.signature_algorithm != certificate.tbs_certificate.signature
    {
        return Err(CertificateError::CertificateMaterial);
    }
    NodePublicIdentity::from_certificate(trusted_root_der)?.verify_enrolment_transcript(
        certificate.tbs_certificate.as_ref(),
        certificate.signature_value.data.as_ref(),
    )
}

pub(super) fn validate_key_match(
    key: &RustCryptoKey,
    certificate_der: &[u8],
) -> Result<(), CertificateError> {
    let certificate = parse_ca(certificate_der)?;
    require_online_constraint(&certificate)?;
    if certificate.public_key().raw != key.subject_public_key_info() {
        return Err(CertificateError::CertificateMaterial);
    }
    Ok(())
}

fn require_online_constraint(certificate: &X509Certificate<'_>) -> Result<(), CertificateError> {
    let constraints = certificate
        .basic_constraints()
        .map_err(|_| CertificateError::CertificateMaterial)?
        .ok_or(CertificateError::CertificateMaterial)?;
    if constraints.value.path_len_constraint == Some(0) {
        Ok(())
    } else {
        Err(CertificateError::CertificateMaterial)
    }
}

fn parse_ca(der: &[u8]) -> Result<X509Certificate<'_>, CertificateError> {
    if der.is_empty() || der.len() > 8192 {
        return Err(CertificateError::CertificateMaterial);
    }
    let (tail, certificate) =
        X509Certificate::from_der(der).map_err(|_| CertificateError::CertificateMaterial)?;
    let usage = certificate
        .key_usage()
        .map_err(|_| CertificateError::CertificateMaterial)?
        .ok_or(CertificateError::CertificateMaterial)?;
    if !tail.is_empty()
        || !certificate.is_ca()
        || !usage.value.key_cert_sign()
        || certificate.validity().not_before >= certificate.validity().not_after
    {
        return Err(CertificateError::CertificateMaterial);
    }
    Ok(certificate)
}
