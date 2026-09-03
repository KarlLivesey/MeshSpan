// SPDX-License-Identifier: GPL-2.0-only

//! Canonical bounded transport for one public TLS certificate chain and its private key.

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"MSCB";
const FORMAT_VERSION: u8 = 1;
const HEADER_BYTES: usize = 8;
const LENGTH_BYTES: usize = 4;
const MAXIMUM_CERTIFICATES: usize = 8;
const MAXIMUM_CERTIFICATE_BYTES: usize = 16 * 1_024;
const MAXIMUM_PRIVATE_KEY_BYTES: usize = 8 * 1_024;
const MAXIMUM_BUNDLE_BYTES: usize = 63 * 1_024;

/// One canonical public TLS certificate chain and matching PKCS#8 private-key candidate.
///
/// This type validates framing and resource bounds. The TLS provider must additionally parse the
/// DER, validate the private-key algorithm and prove that the leaf certificate matches the key.
pub struct PublicCertificateBundle {
    certificate_chain: Vec<Vec<u8>>,
    private_key: Zeroizing<Vec<u8>>,
}

impl PublicCertificateBundle {
    /// Validates one non-empty, bounded DER chain and PKCS#8 private key.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized or obviously non-DER values before any cryptographic work.
    pub fn new(
        certificate_chain: Vec<Vec<u8>>,
        private_key: Vec<u8>,
    ) -> Result<Self, PublicCertificateBundleError> {
        if certificate_chain.is_empty()
            || certificate_chain.len() > MAXIMUM_CERTIFICATES
            || certificate_chain.iter().any(|certificate| {
                certificate.is_empty()
                    || certificate.len() > MAXIMUM_CERTIFICATE_BYTES
                    || certificate.first() != Some(&0x30)
            })
            || private_key.is_empty()
            || private_key.len() > MAXIMUM_PRIVATE_KEY_BYTES
            || private_key.first() != Some(&0x30)
        {
            return Err(PublicCertificateBundleError::Invalid);
        }
        let bundle = Self {
            certificate_chain,
            private_key: Zeroizing::new(private_key),
        };
        if bundle.encoded_length()? > MAXIMUM_BUNDLE_BYTES {
            return Err(PublicCertificateBundleError::Invalid);
        }
        Ok(bundle)
    }

    /// Borrows the leaf-first DER certificate chain.
    #[must_use]
    pub fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.certificate_chain
    }

    /// Borrows the plaintext PKCS#8 bytes only for immediate protected TLS composition.
    #[must_use]
    pub fn private_key_pkcs8(&self) -> &[u8] {
        &self.private_key
    }

    /// Returns a domain-separated digest of the canonical public/private bundle.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"meshspan.public-certificate-bundle.v1\0");
        digest.update([FORMAT_VERSION]);
        digest.update(self.private_key.len().to_be_bytes());
        digest.update(self.private_key.as_slice());
        digest.update(self.certificate_chain.len().to_be_bytes());
        for certificate in &self.certificate_chain {
            digest.update(certificate.len().to_be_bytes());
            digest.update(certificate);
        }
        digest.finalize().into()
    }

    /// Encodes the bundle into its unique bounded binary representation.
    ///
    /// # Errors
    ///
    /// Returns an error if a checked length cannot be represented.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, PublicCertificateBundleError> {
        let expected_length = self.encoded_length()?;
        let certificate_count = u8::try_from(self.certificate_chain.len())
            .map_err(|_| PublicCertificateBundleError::Invalid)?;
        let mut encoded = Vec::with_capacity(expected_length);
        encoded.extend_from_slice(MAGIC);
        encoded.push(FORMAT_VERSION);
        encoded.push(certificate_count);
        encoded.extend_from_slice(&[0, 0]);
        append_field(&mut encoded, &self.private_key)?;
        for certificate in &self.certificate_chain {
            append_field(&mut encoded, certificate)?;
        }
        if encoded.len() != expected_length || encoded.len() > MAXIMUM_BUNDLE_BYTES {
            return Err(PublicCertificateBundleError::Invalid);
        }
        Ok(Zeroizing::new(encoded))
    }

    /// Decodes and revalidates hostile bundle bytes.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, malformed lengths, trailing bytes and values outside bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, PublicCertificateBundleError> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > MAXIMUM_BUNDLE_BYTES
            || bytes.get(..4) != Some(MAGIC)
            || bytes[4] != FORMAT_VERSION
            || bytes[6..HEADER_BYTES] != [0, 0]
        {
            return Err(PublicCertificateBundleError::Invalid);
        }
        let certificate_count = usize::from(bytes[5]);
        if certificate_count == 0 || certificate_count > MAXIMUM_CERTIFICATES {
            return Err(PublicCertificateBundleError::Invalid);
        }
        let mut cursor = HEADER_BYTES;
        let private_key = read_field(bytes, &mut cursor, MAXIMUM_PRIVATE_KEY_BYTES)?.to_vec();
        let mut certificate_chain = Vec::with_capacity(certificate_count);
        for _ in 0..certificate_count {
            certificate_chain
                .push(read_field(bytes, &mut cursor, MAXIMUM_CERTIFICATE_BYTES)?.to_vec());
        }
        if cursor != bytes.len() {
            return Err(PublicCertificateBundleError::Invalid);
        }
        Self::new(certificate_chain, private_key)
    }

    fn encoded_length(&self) -> Result<usize, PublicCertificateBundleError> {
        self.certificate_chain.iter().try_fold(
            HEADER_BYTES
                .checked_add(LENGTH_BYTES)
                .and_then(|length| length.checked_add(self.private_key.len()))
                .ok_or(PublicCertificateBundleError::Invalid)?,
            |length, certificate| {
                length
                    .checked_add(LENGTH_BYTES)
                    .and_then(|value| value.checked_add(certificate.len()))
                    .ok_or(PublicCertificateBundleError::Invalid)
            },
        )
    }
}

fn append_field(
    destination: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), PublicCertificateBundleError> {
    let length = u32::try_from(value.len()).map_err(|_| PublicCertificateBundleError::Invalid)?;
    destination.extend_from_slice(&length.to_be_bytes());
    destination.extend_from_slice(value);
    Ok(())
}

fn read_field<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    maximum: usize,
) -> Result<&'a [u8], PublicCertificateBundleError> {
    let length_end = cursor
        .checked_add(LENGTH_BYTES)
        .ok_or(PublicCertificateBundleError::Invalid)?;
    let length = u32::from_be_bytes(
        bytes
            .get(*cursor..length_end)
            .ok_or(PublicCertificateBundleError::Invalid)?
            .try_into()
            .map_err(|_| PublicCertificateBundleError::Invalid)?,
    );
    let length = usize::try_from(length).map_err(|_| PublicCertificateBundleError::Invalid)?;
    if length == 0 || length > maximum {
        return Err(PublicCertificateBundleError::Invalid);
    }
    let end = length_end
        .checked_add(length)
        .ok_or(PublicCertificateBundleError::Invalid)?;
    let field = bytes
        .get(length_end..end)
        .ok_or(PublicCertificateBundleError::Invalid)?;
    *cursor = end;
    Ok(field)
}

/// Closed public-certificate bundle validation failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PublicCertificateBundleError {
    /// The bundle is malformed, ambiguous or outside its resource bounds.
    #[error("public certificate bundle is invalid")]
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::{PublicCertificateBundle, PublicCertificateBundleError};
    use crate::CertificateAuthority;

    #[test]
    fn canonical_bundle_round_trips_and_rejects_trailing_or_substituted_framing()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = CertificateAuthority::new()?;
        let issued = authority.issue_node("files.example.test")?;
        let bundle = PublicCertificateBundle::new(
            vec![issued.certificate_der().to_vec()],
            issued.private_key().to_vec(),
        )?;
        let encoded = bundle.encode()?;
        let decoded = PublicCertificateBundle::decode(&encoded)?;
        assert_eq!(decoded.certificate_chain(), bundle.certificate_chain());
        assert_eq!(decoded.private_key_pkcs8(), bundle.private_key_pkcs8());
        assert_eq!(decoded.digest(), bundle.digest());

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            PublicCertificateBundle::decode(&trailing).err(),
            Some(PublicCertificateBundleError::Invalid)
        );
        let mut substituted = encoded.to_vec();
        substituted[4] = 2;
        assert_eq!(
            PublicCertificateBundle::decode(&substituted).err(),
            Some(PublicCertificateBundleError::Invalid)
        );
        Ok(())
    }
}
