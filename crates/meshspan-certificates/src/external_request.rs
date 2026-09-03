// SPDX-License-Identifier: GPL-2.0-only

//! Key ownership and PKCS#10 construction for certificates issued by an external authority.

use rcgen::{
    CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, KeyUsagePurpose, PublicKeyData,
};
use sha2::{Digest as _, Sha256};

use super::{CertificateError, RustCryptoKey};

const MAXIMUM_DNS_NAMES: usize = 256;
const MAXIMUM_DNS_NAME_BYTES: usize = 253;

/// Private key for one externally issued public-certificate generation.
///
/// The key is generated inside `MeshSpan` and is intentionally neither cloneable nor printable. Its
/// encoded form is exposed only so the authority layer can immediately envelope-encrypt it and
/// restore the same pending generation after a worker restart.
pub struct ExternalCertificateRequestKey {
    key: RustCryptoKey,
}

impl ExternalCertificateRequestKey {
    /// Generates a fresh P-256 key using operating-system entropy.
    ///
    /// # Errors
    ///
    /// Fails when entropy or canonical PKCS#8 encoding is unavailable.
    pub fn generate() -> Result<Self, CertificateError> {
        Ok(Self {
            key: RustCryptoKey::generate()?,
        })
    }

    /// Reopens the exact canonical P-256 key belonging to a pending certificate generation.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical or wrong-algorithm private-key bytes.
    pub fn from_pkcs8(private_key: &[u8]) -> Result<Self, CertificateError> {
        Ok(Self {
            key: RustCryptoKey::from_pkcs8(private_key)?,
        })
    }

    /// Borrows the PKCS#8 key for immediate envelope encryption or protected persistence.
    #[must_use]
    pub fn private_key_pkcs8(&self) -> &[u8] {
        &self.key.private_key
    }

    /// Returns a stable SHA-256 fingerprint of the canonical subject public-key information.
    #[must_use]
    pub fn public_key_fingerprint(&self) -> [u8; 32] {
        Sha256::digest(self.key.subject_public_key_info()).into()
    }

    /// Creates a signed PKCS#10 request for one exact canonical DNS-name set.
    ///
    /// Names must be lower-case, strictly sorted and unique. Wildcards are accepted only as the
    /// complete left-most label. The request asks only for TLS server authentication.
    ///
    /// # Errors
    ///
    /// Rejects an empty, excessive, unordered, duplicate or invalid DNS-name set and any CSR
    /// construction failure.
    pub fn certificate_signing_request(
        &self,
        dns_names: &[String],
    ) -> Result<Vec<u8>, CertificateError> {
        validate_dns_names(dns_names)?;
        let mut parameters = CertificateParams::new(dns_names.to_vec())?;
        parameters.distinguished_name = DistinguishedName::new();
        parameters
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        parameters
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        Ok(parameters.serialize_request(&self.key)?.der().to_vec())
    }
}

fn validate_dns_names(dns_names: &[String]) -> Result<(), CertificateError> {
    if dns_names.is_empty() || dns_names.len() > MAXIMUM_DNS_NAMES {
        return Err(CertificateError::CertificateRequest);
    }
    let mut previous: Option<&str> = None;
    for dns_name in dns_names {
        if !valid_dns_name(dns_name) || previous.is_some_and(|value| value >= dns_name.as_str()) {
            return Err(CertificateError::CertificateRequest);
        }
        previous = Some(dns_name);
    }
    Ok(())
}

fn valid_dns_name(value: &str) -> bool {
    let name = value.strip_prefix("*.").unwrap_or(value);
    !name.is_empty()
        && value.len() <= MAXIMUM_DNS_NAME_BYTES
        && name.contains('.')
        && name.split('.').all(valid_dns_label)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'*')
        })
}

fn valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::ExternalCertificateRequestKey;
    use crate::CertificateError;

    #[test]
    fn key_reload_reproduces_exact_signed_multi_name_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = ExternalCertificateRequestKey::generate()?;
        let names = vec![
            "*.files.example.test".to_owned(),
            "files.example.test".to_owned(),
        ];
        let request = key.certificate_signing_request(&names)?;
        let reopened = ExternalCertificateRequestKey::from_pkcs8(key.private_key_pkcs8())?;

        assert_eq!(
            reopened.public_key_fingerprint(),
            key.public_key_fingerprint()
        );
        assert_eq!(reopened.certificate_signing_request(&names)?, request);
        assert_eq!(request.first(), Some(&0x30));
        assert!(contains_bytes(&request, names[0].as_bytes()));
        assert!(contains_bytes(&request, names[1].as_bytes()));
        Ok(())
    }

    #[test]
    fn request_rejects_ambiguous_or_noncanonical_name_sets()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = ExternalCertificateRequestKey::generate()?;
        for names in [
            Vec::new(),
            vec![
                "files.example.test".to_owned(),
                "files.example.test".to_owned(),
            ],
            vec!["z.example.test".to_owned(), "a.example.test".to_owned()],
            vec!["Files.example.test".to_owned()],
            vec!["*.*.example.test".to_owned()],
            vec!["localhost".to_owned()],
        ] {
            assert!(matches!(
                key.certificate_signing_request(&names),
                Err(CertificateError::CertificateRequest)
            ));
        }
        Ok(())
    }

    #[test]
    fn request_rejects_more_than_the_bounded_identifier_count()
    -> Result<(), Box<dyn std::error::Error>> {
        let key = ExternalCertificateRequestKey::generate()?;
        let names = (0..257)
            .map(|index| format!("host-{index:03}.example.test"))
            .collect::<Vec<_>>();
        assert!(matches!(
            key.certificate_signing_request(&names),
            Err(CertificateError::CertificateRequest)
        ));
        Ok(())
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|candidate| candidate == needle)
    }
}
