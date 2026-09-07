// SPDX-License-Identifier: GPL-2.0-only

//! Explicit, replayable node-certificate generations for the renewal owner.

use rcgen::{PublicKeyData as _, SerialNumber};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer as _, GeneralName, X509Certificate};

use crate::{CertificateError, NodePublicIdentity, OnlineCertificateAuthority, node_parameters};

/// Public inputs bound into one immutable node-certificate generation.
///
/// The caller establishes the node's membership and authority to renew. This record
/// contains no private key. Times are exact Unix seconds, not an implicit CA default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeCertificateRequest<'a> {
    /// Exact node DNS identity already authorised by the mesh.
    pub dns_name: &'a str,
    /// Positive, monotonically increasing generation enforced by metadata.
    pub generation: u64,
    /// Inclusive validity start in Unix seconds.
    pub not_before: i64,
    /// Exclusive validity end in Unix seconds, at most 30 days after the start.
    pub not_after: i64,
}

impl NodePublicIdentity {
    /// Extracts a canonical P-256 identity from one bounded, exact DER certificate.
    ///
    /// This parses public identity only; it does not establish certificate trust or validity.
    ///
    /// # Errors
    ///
    /// Rejects malformed/trailing DER, oversized certificates and non-canonical P-256 SPKI.
    pub fn from_certificate(certificate_der: &[u8]) -> Result<Self, CertificateError> {
        let certificate = parse_node_certificate(certificate_der)?;
        let identity = Self::from_sec1(certificate.public_key().subject_public_key.data.as_ref())?;
        if identity.subject_public_key_info() != certificate.public_key().raw {
            return Err(CertificateError::PublicKeyDecoding);
        }
        Ok(identity)
    }
}

/// Validates a renewal against the previously admitted key and exact authorised issuer.
///
/// The caller obtains both certificates from authoritative metadata, not request-supplied
/// trust. Validation is deterministic at the request's explicit interval, with no local clock.
///
/// # Errors
///
/// Rejects substituted identities/issuers, invalid signatures, names, usages, intervals or
/// generation serials. It does not grant membership or acknowledge installation.
pub fn validate_node_certificate_renewal(
    certificate_der: &[u8],
    previous_certificate_der: &[u8],
    issuer_certificate_der: &[u8],
    request: NodeCertificateRequest<'_>,
) -> Result<(), CertificateError> {
    let identity = NodePublicIdentity::from_certificate(previous_certificate_der)?;
    let certificate = parse_node_certificate(certificate_der)?;
    let issuer = parse_node_certificate(issuer_certificate_der)?;
    let signing_identity = NodePublicIdentity::from_certificate(issuer_certificate_der)?;
    let names = certificate
        .subject_alternative_name()
        .map_err(|_| CertificateError::CertificateMaterial)?
        .ok_or(CertificateError::CertificateMaterial)?;
    let usage = certificate
        .extended_key_usage()
        .map_err(|_| CertificateError::CertificateMaterial)?
        .ok_or(CertificateError::CertificateMaterial)?;
    let serial = renewal_serial(&identity, issuer_certificate_der, request).to_bytes();
    if request.generation == 0
        || request.dns_name.contains('*')
        || request.not_before < 0
        || !request
            .not_after
            .checked_sub(request.not_before)
            .is_some_and(|seconds| (1..=30 * 86_400).contains(&seconds))
        || certificate.public_key().raw != identity.subject_public_key_info()
        || names.value.general_names != [GeneralName::DNSName(request.dns_name)]
        || !usage.value.server_auth
        || !usage.value.client_auth
        || certificate.is_ca()
        || certificate.validity().not_before.timestamp() != request.not_before
        || certificate.validity().not_after.timestamp() != request.not_after
        || request.not_before < issuer.validity().not_before.timestamp()
        || request.not_after > issuer.validity().not_after.timestamp()
        || certificate.issuer() != issuer.subject()
        || certificate.signature_algorithm.algorithm.to_id_string() != "1.2.840.10045.4.3.2"
        || certificate.signature_algorithm != certificate.tbs_certificate.signature
        || certificate
            .raw_serial()
            .iter()
            .copied()
            .skip_while(|byte| *byte == 0)
            .ne(serial.iter().copied().skip_while(|byte| *byte == 0))
    {
        return Err(CertificateError::CertificateMaterial);
    }
    signing_identity.verify_enrolment_transcript(
        certificate.tbs_certificate.as_ref(),
        certificate.signature_value.data.as_ref(),
    )
}

fn parse_node_certificate(der: &[u8]) -> Result<X509Certificate<'_>, CertificateError> {
    if der.is_empty() || der.len() > 65_536 {
        return Err(CertificateError::CertificateMaterial);
    }
    let (remaining, certificate) =
        X509Certificate::from_der(der).map_err(|_| CertificateError::CertificateMaterial)?;
    if !remaining.is_empty() {
        return Err(CertificateError::CertificateMaterial);
    }
    Ok(certificate)
}

impl OnlineCertificateAuthority {
    /// Signs an explicit renewable generation of the same node-owned public key.
    ///
    /// Exact replay produces identical DER. The serial binds issuer, key, DNS name,
    /// generation and validity interval; renewing does not reuse an old serial.
    ///
    /// # Errors
    ///
    /// Rejects zero generations, invalid names, unrepresentable or non-positive
    /// intervals, lifetimes over 30 days and intervals outside the issuer's lifetime.
    /// This does not authorise, persist, distribute or activate the generation.
    pub fn renew_node_certificate(
        &self,
        identity: &NodePublicIdentity,
        request: NodeCertificateRequest<'_>,
    ) -> Result<Vec<u8>, CertificateError> {
        let lifetime = request.not_after.checked_sub(request.not_before);
        if request.generation == 0
            || request.dns_name.contains('*')
            || request.not_before < 0
            || !lifetime.is_some_and(|seconds| (1..=30 * 86_400).contains(&seconds))
        {
            return Err(CertificateError::CertificateRequest);
        }
        crate::external_request::validate_dns_names(&[request.dns_name.to_owned()])?;
        let (remaining, issuer) = X509Certificate::from_der(&self.certificate_der)
            .map_err(|_| CertificateError::CertificateMaterial)?;
        if !remaining.is_empty()
            || request.not_before < issuer.validity().not_before.timestamp()
            || request.not_after > issuer.validity().not_after.timestamp()
        {
            return Err(CertificateError::CertificateMaterial);
        }
        let mut parameters = node_parameters(identity, request.dns_name)?;
        parameters.not_before = OffsetDateTime::from_unix_timestamp(request.not_before)
            .map_err(|_| CertificateError::CertificateRequest)?;
        parameters.not_after = OffsetDateTime::from_unix_timestamp(request.not_after)
            .map_err(|_| CertificateError::CertificateRequest)?;
        parameters.serial_number = Some(renewal_serial(identity, &self.certificate_der, request));
        Ok(parameters.signed_by(identity, &self.issuer)?.der().to_vec())
    }
}

fn renewal_serial(
    identity: &NodePublicIdentity,
    issuer_der: &[u8],
    request: NodeCertificateRequest<'_>,
) -> SerialNumber {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.node-certificate.generation.v1\0");
    digest.update(Sha256::digest(issuer_der));
    digest.update(Sha256::digest(identity.subject_public_key_info()));
    digest.update(request.generation.to_be_bytes());
    digest.update(request.not_before.to_be_bytes());
    digest.update(request.not_after.to_be_bytes());
    digest.update(request.dns_name.as_bytes());
    let hash = digest.finalize();
    // Nineteen bytes keep the serial positive and below the X.509 20-octet ceiling.
    SerialNumber::from_slice(&hash[..19])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CertificateAuthority, NodeIdentityKey};
    use x509_parser::prelude::GeneralName;

    #[test]
    fn renewable_generation_binds_exact_identity_window_and_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = CertificateAuthority::new()?;
        let authority = root.issue_online_authority()?;
        let identity = NodeIdentityKey::generate()?;
        let public = NodePublicIdentity::from_sec1(identity.public_key_sec1())?;
        let request = NodeCertificateRequest {
            dns_name: "node.meshspan.internal",
            generation: 2,
            not_before: 1_800_000_000,
            not_after: 1_802_592_000,
        };
        let der = authority.renew_node_certificate(&public, request)?;
        assert_eq!(der, authority.renew_node_certificate(&public, request)?);
        let previous = identity.self_signed(request.dns_name)?;
        validate_node_certificate_renewal(&der, &previous, authority.certificate_der(), request)?;
        let (remaining, leaf) = X509Certificate::from_der(&der)?;
        assert!(remaining.is_empty());
        assert_eq!(leaf.validity().not_before.timestamp(), 1_800_000_000);
        assert_eq!(leaf.validity().not_after.timestamp(), 1_802_592_000);
        assert_eq!(
            leaf.public_key().subject_public_key.data.as_ref(),
            identity.public_key_sec1()
        );
        let usage = leaf.extended_key_usage()?.ok_or("missing EKU")?.value;
        assert!(usage.server_auth && usage.client_auth);
        assert_eq!(
            leaf.subject_alternative_name()?
                .ok_or("missing SAN")?
                .value
                .general_names,
            vec![GeneralName::DNSName("node.meshspan.internal")]
        );
        for changed in [
            NodeCertificateRequest {
                generation: 3,
                ..request
            },
            NodeCertificateRequest {
                not_before: 1_800_000_001,
                ..request
            },
            NodeCertificateRequest {
                not_after: 1_802_591_999,
                ..request
            },
            NodeCertificateRequest {
                dns_name: "other.meshspan.internal",
                ..request
            },
        ] {
            let renewed = authority.renew_node_certificate(&public, changed)?;
            assert!(
                validate_node_certificate_renewal(
                    &renewed,
                    &previous,
                    authority.certificate_der(),
                    request,
                )
                .is_err()
            );
            let (_, renewed) = X509Certificate::from_der(&renewed)?;
            assert_ne!(leaf.raw_serial(), renewed.raw_serial());
        }
        Ok(())
    }

    #[test]
    fn renewable_generation_rejects_invalid_windows_and_names()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = CertificateAuthority::new()?.issue_online_authority()?;
        let identity = NodeIdentityKey::generate()?;
        let public = NodePublicIdentity::from_sec1(identity.public_key_sec1())?;
        let valid = NodeCertificateRequest {
            dns_name: "node.meshspan.internal",
            generation: 1,
            not_before: 1_800_000_000,
            not_after: 1_802_592_000,
        };
        for request in [
            NodeCertificateRequest {
                generation: 0,
                ..valid
            },
            NodeCertificateRequest {
                not_after: valid.not_before,
                ..valid
            },
            NodeCertificateRequest {
                not_after: valid.not_before - 1,
                ..valid
            },
            NodeCertificateRequest {
                not_after: valid.not_after + 1,
                ..valid
            },
            NodeCertificateRequest {
                not_before: -1,
                not_after: 1,
                ..valid
            },
            NodeCertificateRequest {
                not_before: i64::MAX - 1,
                not_after: i64::MAX,
                ..valid
            },
            NodeCertificateRequest {
                dns_name: "",
                ..valid
            },
            NodeCertificateRequest {
                dns_name: "*.meshspan.internal",
                ..valid
            },
        ] {
            assert!(
                authority.renew_node_certificate(&public, request).is_err(),
                "{request:?}"
            );
        }
        Ok(())
    }
}
