// SPDX-License-Identifier: GPL-2.0-only

//! Exact public certificate material carried inside the authenticated recovery transfer.

use std::io::{Read, Write};

use meshspan_certificates::{
    NodeCertificateRequest, NodePublicIdentity, validate_node_certificate,
};
use meshspan_domain::NodeId;

use crate::RecoveryKeyBundleError;
use crate::recovery_key_bundle::{read_frame, write_frame};

/// Validated replacement leaf and its prepared online issuer. No private key is carried.
/// Possession of this public record does not grant membership or permission to start services.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryNodeCertificate {
    pub(crate) node_id: NodeId,
    pub(crate) generation: u64,
    pub(crate) not_before: i64,
    pub(crate) not_after: i64,
    pub(crate) certificate_der: Vec<u8>,
    pub(crate) issuer_der: Vec<u8>,
}

impl RecoveryNodeCertificate {
    /// Exact leaf generation; activation must persist it before normal renewal starts.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Inclusive certificate validity start, in Unix seconds.
    #[must_use]
    pub const fn not_before(&self) -> i64 {
        self.not_before
    }

    /// Exclusive certificate validity end, in Unix seconds.
    #[must_use]
    pub const fn not_after(&self) -> i64 {
        self.not_after
    }

    /// The selected node's public leaf DER, verified against its existing private identity.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Root-signed successor online issuer DER from the signed key-inventory commitment.
    #[must_use]
    pub fn issuer_der(&self) -> &[u8] {
        &self.issuer_der
    }

    /// Canonical private transport DNS name, derived from the selected node ID.
    #[must_use]
    pub fn dns_name(&self) -> String {
        certificate_name(self.node_id)
    }

    pub(crate) fn write(&self, output: &mut impl Write) -> Result<(), RecoveryKeyBundleError> {
        output.write_all(&self.generation.to_be_bytes())?;
        output.write_all(&self.not_before.to_be_bytes())?;
        output.write_all(&self.not_after.to_be_bytes())?;
        write_frame(output, &self.certificate_der)
    }

    pub(crate) fn read(
        input: &mut impl Read,
        node_id: NodeId,
        identity: &[u8; 65],
        issuer_der: Vec<u8>,
    ) -> Result<Self, RecoveryKeyBundleError> {
        let mut generation = [0_u8; 8];
        let mut not_before = [0_u8; 8];
        let mut not_after = [0_u8; 8];
        input.read_exact(&mut generation)?;
        input.read_exact(&mut not_before)?;
        input.read_exact(&mut not_after)?;
        let certificate = Self {
            node_id,
            generation: u64::from_be_bytes(generation),
            not_before: i64::from_be_bytes(not_before),
            not_after: i64::from_be_bytes(not_after),
            certificate_der: read_frame(input, 8192)?,
            issuer_der,
        };
        certificate.validate(identity)?;
        Ok(certificate)
    }

    pub(crate) fn validate(&self, identity: &[u8; 65]) -> Result<(), RecoveryKeyBundleError> {
        if self.generation > i64::MAX.unsigned_abs() {
            return Err(RecoveryKeyBundleError::Invalid);
        }
        let identity = NodePublicIdentity::from_sec1(identity)
            .map_err(|_| RecoveryKeyBundleError::Authority)?;
        validate_node_certificate(
            &self.certificate_der,
            &identity,
            &self.issuer_der,
            NodeCertificateRequest {
                dns_name: &self.dns_name(),
                generation: self.generation,
                not_before: self.not_before,
                not_after: self.not_after,
            },
        )
        .map_err(|_| RecoveryKeyBundleError::Authority)
    }
}

pub(crate) fn certificate_name(node_id: NodeId) -> String {
    format!(
        "node-{}.meshspan.internal",
        node_id.to_string().replace('-', "")
    )
}
