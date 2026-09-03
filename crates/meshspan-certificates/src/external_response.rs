// SPDX-License-Identifier: GPL-2.0-only

//! Bounded semantic validation of a certificate chain returned by an external authority.

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::FromDer as _;

use super::external_request::validate_dns_names;
use super::{ExternalCertificateRequestKey, PublicCertificateBundle};

const MAXIMUM_PEM_RESPONSE_BYTES: usize = 96 * 1_024;
const MAXIMUM_CERTIFICATES: usize = 8;
const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
const PEM_END: &[u8] = b"-----END CERTIFICATE-----";

/// A semantically valid leaf-first chain and its exact certificate lifetime.
///
/// Trust-anchor and signature-path validation remains the caller's responsibility because the
/// accepted trust roots belong to the configured external authority, not to this parser.
pub struct ValidatedExternalCertificateResponse {
    bundle: PublicCertificateBundle,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
}

impl ValidatedExternalCertificateResponse {
    /// Borrows the bounded certificate/private-key bundle ready for protected publication.
    #[must_use]
    pub const fn bundle(&self) -> &PublicCertificateBundle {
        &self.bundle
    }

    /// Consumes the response and returns its protected-publication bundle.
    #[must_use]
    pub fn into_bundle(self) -> PublicCertificateBundle {
        self.bundle
    }

    /// Returns the inclusive leaf validity start as seconds since the Unix epoch.
    #[must_use]
    pub const fn not_before_unix_seconds(&self) -> u64 {
        self.not_before_unix_seconds
    }

    /// Returns the exclusive leaf validity end as seconds since the Unix epoch.
    #[must_use]
    pub const fn not_after_unix_seconds(&self) -> u64 {
        self.not_after_unix_seconds
    }
}

/// Parses and semantically validates one ACME-style PEM certificate response.
///
/// The returned chain is canonical leaf-first DER. The leaf must contain exactly the requested
/// DNS SAN set, match the protected request key and be valid at `now_unix_seconds`. Chain trust and
/// signatures must be validated against the authority's configured roots before publication.
///
/// # Errors
///
/// Rejects malformed, empty or excessive PEM; an invalid requested-name set; missing, duplicate,
/// unexpected or non-DNS SANs; a different public key; or a leaf outside its validity interval.
pub fn validate_external_certificate_response(
    pem_response: &[u8],
    requested_dns_names: &[String],
    request_key: &ExternalCertificateRequestKey,
    now_unix_seconds: u64,
) -> Result<ValidatedExternalCertificateResponse, ExternalCertificateResponseError> {
    validate_dns_names(requested_dns_names)
        .map_err(|_| ExternalCertificateResponseError::InvalidNames)?;
    if pem_response.is_empty() || pem_response.len() > MAXIMUM_PEM_RESPONSE_BYTES {
        return Err(ExternalCertificateResponseError::InvalidEncoding);
    }
    let chain = parse_certificate_chain(pem_response)?;
    let leaf_der = chain
        .first()
        .ok_or(ExternalCertificateResponseError::InvalidEncoding)?;
    let (remainder, leaf) = X509Certificate::from_der(leaf_der)
        .map_err(|_| ExternalCertificateResponseError::InvalidEncoding)?;
    if !remainder.is_empty() {
        return Err(ExternalCertificateResponseError::InvalidEncoding);
    }
    validate_names(&leaf, requested_dns_names)?;
    validate_public_key(&leaf, request_key)?;
    let validity = leaf.validity();
    let not_before_unix_seconds = u64::try_from(validity.not_before.timestamp())
        .map_err(|_| ExternalCertificateResponseError::InvalidLifetime)?;
    let not_after_unix_seconds = u64::try_from(validity.not_after.timestamp())
        .map_err(|_| ExternalCertificateResponseError::InvalidLifetime)?;
    if not_after_unix_seconds <= not_before_unix_seconds
        || now_unix_seconds < not_before_unix_seconds
        || now_unix_seconds >= not_after_unix_seconds
    {
        return Err(ExternalCertificateResponseError::InvalidLifetime);
    }
    let bundle = PublicCertificateBundle::new(chain, request_key.private_key_pkcs8().to_vec())
        .map_err(|_| ExternalCertificateResponseError::InvalidEncoding)?;
    Ok(ValidatedExternalCertificateResponse {
        bundle,
        not_before_unix_seconds,
        not_after_unix_seconds,
    })
}

fn parse_certificate_chain(
    pem_response: &[u8],
) -> Result<Vec<Vec<u8>>, ExternalCertificateResponseError> {
    let mut remaining = trim_ascii_whitespace(pem_response);
    let mut chain = Vec::new();
    while !remaining.is_empty() {
        if chain.len() == MAXIMUM_CERTIFICATES || !remaining.starts_with(PEM_BEGIN) {
            return Err(ExternalCertificateResponseError::InvalidEncoding);
        }
        let end = find_bytes(remaining, PEM_END)
            .and_then(|offset| offset.checked_add(PEM_END.len()))
            .ok_or(ExternalCertificateResponseError::InvalidEncoding)?;
        let (remainder, pem) = parse_x509_pem(&remaining[..end])
            .map_err(|_| ExternalCertificateResponseError::InvalidEncoding)?;
        if !remainder.is_empty() || pem.label != "CERTIFICATE" {
            return Err(ExternalCertificateResponseError::InvalidEncoding);
        }
        let (der_remainder, _) = X509Certificate::from_der(&pem.contents)
            .map_err(|_| ExternalCertificateResponseError::InvalidEncoding)?;
        if !der_remainder.is_empty() {
            return Err(ExternalCertificateResponseError::InvalidEncoding);
        }
        chain.push(pem.contents);
        remaining = trim_ascii_whitespace(&remaining[end..]);
    }
    if chain.is_empty() {
        Err(ExternalCertificateResponseError::InvalidEncoding)
    } else {
        Ok(chain)
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn validate_names(
    leaf: &X509Certificate<'_>,
    requested_dns_names: &[String],
) -> Result<(), ExternalCertificateResponseError> {
    let subject_alternative_name = leaf
        .subject_alternative_name()
        .map_err(|_| ExternalCertificateResponseError::InvalidNames)?
        .ok_or(ExternalCertificateResponseError::InvalidNames)?;
    let mut certificate_names = subject_alternative_name
        .value
        .general_names
        .iter()
        .map(|name| match name {
            GeneralName::DNSName(value) => Ok((*value).to_owned()),
            _ => Err(ExternalCertificateResponseError::InvalidNames),
        })
        .collect::<Result<Vec<_>, _>>()?;
    certificate_names.sort_unstable();
    if certificate_names.windows(2).any(|pair| pair[0] == pair[1])
        || certificate_names != requested_dns_names
    {
        return Err(ExternalCertificateResponseError::InvalidNames);
    }
    Ok(())
}

fn validate_public_key(
    leaf: &X509Certificate<'_>,
    request_key: &ExternalCertificateRequestKey,
) -> Result<(), ExternalCertificateResponseError> {
    let fingerprint: [u8; 32] = Sha256::digest(leaf.public_key().raw).into();
    if fingerprint != request_key.public_key_fingerprint() {
        return Err(ExternalCertificateResponseError::InvalidPublicKey);
    }
    Ok(())
}

/// Closed external-certificate semantic validation failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ExternalCertificateResponseError {
    /// The PEM chain is absent, malformed, excessive or cannot form a bounded publication bundle.
    #[error("external certificate response encoding is invalid")]
    InvalidEncoding,
    /// The requested or returned subject-alternative-name set is invalid.
    #[error("external certificate response names are invalid")]
    InvalidNames,
    /// The returned leaf does not contain the request key's public identity.
    #[error("external certificate response key does not match the request")]
    InvalidPublicKey,
    /// The returned leaf has an empty lifetime or is not currently valid.
    #[error("external certificate response lifetime is invalid")]
    InvalidLifetime,
}

#[cfg(test)]
mod tests {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::prelude::FromDer as _;

    use super::{ExternalCertificateResponseError, validate_external_certificate_response};
    use crate::{CertificateAuthority, ExternalCertificateRequestKey};

    const NAMES: [&str; 2] = ["*.files.example.test", "files.example.test"];

    #[test]
    fn validates_exact_names_key_lifetime_and_leaf_first_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = CertificateAuthority::new()?;
        let request_key = ExternalCertificateRequestKey::generate()?;
        let response = issued_response(&authority, &request_key, &NAMES)?;
        let names = requested_names();
        let provisional =
            validate_external_certificate_response(&response, &names, &request_key, 0);
        assert_eq!(
            provisional.err(),
            Some(ExternalCertificateResponseError::InvalidLifetime)
        );

        let parsed_chain = super::parse_certificate_chain(&response)?;
        let (_, parsed_leaf) = X509Certificate::from_der(&parsed_chain[0])?;
        let now = u64::try_from(parsed_leaf.validity().not_before.timestamp())?;
        let validated =
            validate_external_certificate_response(&response, &names, &request_key, now)?;

        assert_eq!(validated.bundle().certificate_chain().len(), 2);
        assert_eq!(
            validated.bundle().private_key_pkcs8(),
            request_key.private_key_pkcs8()
        );
        assert!(validated.not_after_unix_seconds() > validated.not_before_unix_seconds());
        Ok(())
    }

    #[test]
    fn rejects_wrong_name_key_expiry_and_unbounded_input() -> Result<(), Box<dyn std::error::Error>>
    {
        let authority = CertificateAuthority::new()?;
        let request_key = ExternalCertificateRequestKey::generate()?;
        let response = issued_response(&authority, &request_key, &NAMES)?;
        let parsed_chain = super::parse_certificate_chain(&response)?;
        let (_, leaf) = X509Certificate::from_der(&parsed_chain[0])?;
        let validity = leaf.validity();
        let now = u64::try_from(validity.not_before.timestamp())?;
        let expires = u64::try_from(validity.not_after.timestamp())?;

        assert_eq!(
            validate_external_certificate_response(
                &response,
                &["other.example.test".to_owned()],
                &request_key,
                now,
            )
            .err(),
            Some(ExternalCertificateResponseError::InvalidNames)
        );
        let other_key = ExternalCertificateRequestKey::generate()?;
        assert_eq!(
            validate_external_certificate_response(&response, &requested_names(), &other_key, now)
                .err(),
            Some(ExternalCertificateResponseError::InvalidPublicKey)
        );
        assert_eq!(
            validate_external_certificate_response(
                &response,
                &requested_names(),
                &request_key,
                expires,
            )
            .err(),
            Some(ExternalCertificateResponseError::InvalidLifetime)
        );
        assert_eq!(
            validate_external_certificate_response(
                &vec![b'x'; super::MAXIMUM_PEM_RESPONSE_BYTES + 1],
                &requested_names(),
                &request_key,
                now,
            )
            .err(),
            Some(ExternalCertificateResponseError::InvalidEncoding)
        );
        Ok(())
    }

    fn requested_names() -> Vec<String> {
        NAMES.iter().map(ToString::to_string).collect()
    }

    fn issued_response(
        authority: &CertificateAuthority,
        request_key: &ExternalCertificateRequestKey,
        names: &[&str],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let dns_names = names.iter().map(ToString::to_string).collect::<Vec<_>>();
        let leaf = authority.issue_public_endpoint(&dns_names, request_key)?;
        let mut response = pem_certificate(&leaf);
        response.extend_from_slice(&pem_certificate(authority.certificate_der()));
        Ok(response)
    }

    fn pem_certificate(der: &[u8]) -> Vec<u8> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut base64 = Vec::with_capacity(der.len().div_ceil(3) * 4);
        for chunk in der.chunks(3) {
            let value = u32::from(chunk[0]) << 16
                | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
                | u32::from(*chunk.get(2).unwrap_or(&0));
            base64.push(ALPHABET[((value >> 18) & 63) as usize]);
            base64.push(ALPHABET[((value >> 12) & 63) as usize]);
            base64.push(if chunk.len() > 1 {
                ALPHABET[((value >> 6) & 63) as usize]
            } else {
                b'='
            });
            base64.push(if chunk.len() > 2 {
                ALPHABET[(value & 63) as usize]
            } else {
                b'='
            });
        }
        let mut pem = b"-----BEGIN CERTIFICATE-----\n".to_vec();
        for line in base64.chunks(64) {
            pem.extend_from_slice(line);
            pem.push(b'\n');
        }
        pem.extend_from_slice(b"-----END CERTIFICATE-----\n");
        pem
    }
}
