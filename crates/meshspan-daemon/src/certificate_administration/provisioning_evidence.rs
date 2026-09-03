// SPDX-License-Identifier: GPL-2.0-only

//! Validation and public projection of committed certificate-provisioning evidence.

use meshspan_api_contract::{OperationId as ApiOperationId, ProvisionCertificateResponse};

use super::provisioning_request::ProvisioningIdentity;
use super::{CertificateProvisioningCommit, CertificateProvisioningError};

pub(super) fn validate_commit(
    commit: &CertificateProvisioningCommit,
    identity: ProvisioningIdentity,
    expected_request_digest: Option<[u8; 32]>,
) -> Result<(), CertificateProvisioningError> {
    if expected_request_digest.is_some_and(|digest| commit.request_digest != digest)
        || commit.request_digest == [0; 32]
        || commit.result_digest == [0; 32]
        || commit.configuration.config_id != identity.configuration_id
        || commit.configuration.provisioning_intent_digest != Some(identity.intent_digest)
        || commit.order.order_id != identity.order_id
        || commit.order.config_id != identity.configuration_id
        || commit.configuration.revision != commit.committed_revision
        || commit.order.revision < commit.committed_revision
    {
        Err(CertificateProvisioningError::Conflict)
    } else {
        Ok(())
    }
}

pub(super) fn provisioning_response(
    operation_id: ApiOperationId,
    commit: CertificateProvisioningCommit,
) -> Result<ProvisionCertificateResponse, CertificateProvisioningError> {
    Ok(ProvisionCertificateResponse {
        operation_id,
        configuration_id: meshspan_api_contract::AcmeConfigurationId::from_uuid_bytes(
            commit.configuration.config_id.as_bytes(),
        )
        .ok_or(CertificateProvisioningError::Failed)?,
        order_id: meshspan_api_contract::CertificateOrderId::from_uuid_bytes(
            commit.order.order_id.as_bytes(),
        )
        .ok_or(CertificateProvisioningError::Failed)?,
        certificate_names: commit.configuration.certificate_names,
        revision: commit.committed_revision.get(),
    })
}
