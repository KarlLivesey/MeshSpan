// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic leaf issuance for the root-selected replacement identities.

use meshspan_certificates::{
    NodeCertificateRequest, NodePublicIdentity, OnlineCertificateAuthority,
};
use meshspan_domain::UnixMicros;
use meshspan_recovery_bundle::RecoveredAuthority;

use super::key_journal::open_secret;
use crate::recovery_node_certificate::certificate_name;
use crate::{
    AuthoritativeRepository, RecoveryControlKeys, RecoveryKeyBundleError, RecoveryNodeCertificate,
    RecoveryReplacementNode, RepositoryError,
};

impl AuthoritativeRepository {
    // Called only after selection, complete keys and the credential fence validate in the
    // caller's transaction. Replaying the fixed source/fence produces exactly the same leaf.
    pub(super) fn issue_recovery_node_certificate(
        &self,
        recovery: &RecoveredAuthority,
        control: &RecoveryControlKeys,
        node: &RecoveryReplacementNode,
        fenced_at: UnixMicros,
    ) -> Result<RecoveryNodeCertificate, RecoveryKeyBundleError> {
        let previous: i64 = self
            .database
            .connection()
            .query_row(
                "SELECT COALESCE(MAX(generation), 0) FROM node_certificates WHERE node_id = ?1",
                [node.node_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(RepositoryError::from)?;
        let generation = previous
            .checked_add(1)
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or(RecoveryKeyBundleError::Invalid)?;
        let not_before = fenced_at.get().div_euclid(1_000_000);
        let not_after = not_before
            .checked_add(30 * 86_400)
            .ok_or(RecoveryKeyBundleError::Invalid)?;
        let identity = NodePublicIdentity::from_sec1(&node.identity_public_key)
            .map_err(|_| RecoveryKeyBundleError::Authority)?;
        let private = open_secret(recovery, &control.online_authority_key)?;
        let issuer = OnlineCertificateAuthority::from_pkcs8_and_certificate(
            private.expose(),
            &control.online_certificate_der,
        )
        .map_err(|_| RecoveryKeyBundleError::Authority)?;
        let certificate = RecoveryNodeCertificate {
            node_id: node.node_id,
            generation,
            not_before,
            not_after,
            certificate_der: issuer
                .renew_node_certificate(
                    &identity,
                    NodeCertificateRequest {
                        dns_name: &certificate_name(node.node_id),
                        generation,
                        not_before,
                        not_after,
                    },
                )
                .map_err(|_| RecoveryKeyBundleError::Authority)?,
            issuer_der: control.online_certificate_der.clone(),
        };
        certificate.validate(&node.identity_public_key)?;
        Ok(certificate)
    }
}
