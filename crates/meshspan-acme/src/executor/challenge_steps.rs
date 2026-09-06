// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{
    BoundedBytes, CertificateChallengeCleanup, CertificateChallengeKind,
    CertificateChallengeReceipt, CertificateChallengeRequest,
};
use sha2::{Digest as _, Sha256};

use super::{
    AcmeChallengeExecution, AcmeJwsSigner, AcmeStepExecutor, AcmeStepOutcome, AcmeTransport,
    AcmeWorkerError, CertificateChallenge,
};
use crate::{
    AcmeChallengePublication, AcmeChallengeRecord, AcmeMachineAction, AcmeMachineEvent,
    Dns01Payload, Http01Payload,
};

impl<T, S, C> AcmeStepExecutor<T, S, C>
where
    T: AcmeTransport,
    S: AcmeJwsSigner,
    C: CertificateChallenge,
{
    /// Derives exact public material locally, before the caller checkpoints it and permits IO.
    ///
    /// # Errors
    ///
    /// Rejects non-publication actions, signer/input errors and changed retained material.
    pub fn prepare_publication(
        &self,
        action: &AcmeMachineAction,
        execution: AcmeChallengeExecution<'_>,
    ) -> Result<AcmeChallengePublication, AcmeWorkerError> {
        let AcmeMachineAction::PublishChallenge {
            dns_name,
            wildcard,
            challenge,
            order_epoch,
        } = action
        else {
            return Err(AcmeWorkerError::InvalidInput);
        };
        Ok(AcmeChallengePublication::capture(&challenge_request(
            &self.signer,
            dns_name,
            *wildcard,
            challenge,
            *order_epoch,
            execution,
        )?)?)
    }

    /// Checks retained receipt identity locally; this does not publish or prove visibility.
    ///
    /// # Errors
    ///
    /// Rejects changed provider configuration, material or receipt identity.
    pub fn verify_publication_receipt(
        &self,
        publication: &AcmeChallengePublication,
        context: meshspan_contracts::RequestContext,
        digest: [u8; 32],
    ) -> Result<(), AcmeWorkerError> {
        if self
            .expected_publication_receipt(publication, context)?
            .publication_digest
            != digest
        {
            return Err(AcmeWorkerError::InvalidInput);
        }
        Ok(())
    }

    /// Derives provider-bound cleanup identity without publishing or asserting visibility.
    ///
    /// # Errors
    ///
    /// Rejects incompatible material, configuration, fence or an empty receipt digest.
    pub fn expected_publication_receipt(
        &self,
        publication: &AcmeChallengePublication,
        context: meshspan_contracts::RequestContext,
    ) -> Result<CertificateChallengeReceipt, AcmeWorkerError> {
        let request = publication.request(context)?;
        let expected = self.challenge.expected_receipt(&request)?;
        if expected.configuration_revision
            != context
                .expected_revision
                .ok_or(AcmeWorkerError::InvalidInput)?
            || expected.order_epoch != publication.order_epoch()
            || expected.publication_digest == [0; 32]
        {
            return Err(AcmeWorkerError::InvalidInput);
        }
        Ok(expected)
    }

    pub(super) async fn publish_challenge(
        &mut self,
        dns_name: &str,
        wildcard: bool,
        challenge: &AcmeChallengeRecord,
        order_epoch: u64,
        execution: AcmeChallengeExecution<'_>,
    ) -> Result<AcmeStepOutcome, AcmeWorkerError> {
        let request = challenge_request(
            &self.signer,
            dns_name,
            wildcard,
            challenge,
            order_epoch,
            execution,
        )?;
        if request.expires_at <= request.context.deadline {
            return Err(AcmeWorkerError::InvalidInput);
        }
        let expected = self.challenge.expected_receipt(&request)?;
        let receipt = self.challenge.publish(&request).await?;
        if receipt != expected {
            return Err(AcmeWorkerError::InvalidInput);
        }
        if self.challenge.is_visible(&request, receipt).await? {
            Ok(AcmeStepOutcome::Advanced(
                AcmeMachineEvent::ChallengePublished {
                    publication_digest: receipt.publication_digest,
                },
            ))
        } else {
            Ok(AcmeStepOutcome::Pending)
        }
    }

    pub(super) async fn cleanup_challenge(
        &mut self,
        dns_name: &str,
        wildcard: bool,
        challenge: &AcmeChallengeRecord,
        publication_digest: [u8; 32],
        order_epoch: u64,
        execution: AcmeChallengeExecution<'_>,
    ) -> Result<AcmeStepOutcome, AcmeWorkerError> {
        let request = challenge_request(
            &self.signer,
            dns_name,
            wildcard,
            challenge,
            order_epoch,
            execution,
        )?;
        let receipt = CertificateChallengeReceipt {
            configuration_revision: execution
                .context
                .expected_revision
                .ok_or(AcmeWorkerError::InvalidInput)?,
            order_epoch,
            publication_digest,
        };
        match self.challenge.cleanup(&request, receipt).await? {
            CertificateChallengeCleanup::Pending => Ok(AcmeStepOutcome::Pending),
            CertificateChallengeCleanup::Complete => Ok(AcmeStepOutcome::Advanced(
                AcmeMachineEvent::ChallengeCleaned,
            )),
        }
    }
}

fn challenge_request(
    signer: &impl AcmeJwsSigner,
    dns_name: &str,
    wildcard: bool,
    challenge: &AcmeChallengeRecord,
    order_epoch: u64,
    execution: AcmeChallengeExecution<'_>,
) -> Result<CertificateChallengeRequest, AcmeWorkerError> {
    let expires_at = execution.publication.map_or(
        execution.challenge_expires_at,
        AcmeChallengePublication::expires_at,
    );
    if order_epoch == 0
        || execution.context.expected_revision.is_none()
        || expires_at.get() <= 0
        || execution.context.deadline.get() <= 0
    {
        return Err(AcmeWorkerError::InvalidInput);
    }
    let identifier = if wildcard {
        format!("*.{dns_name}")
    } else {
        dns_name.to_owned()
    };
    let key_authorization = key_authorization(signer, &challenge.token)?;
    let (kind, payload) = match challenge.kind.as_str() {
        "http-01" if !wildcard => (
            CertificateChallengeKind::Http01,
            Http01Payload::new(&challenge.token, key_authorization.as_bytes())?.encode()?,
        ),
        "dns-01" => {
            let record_name = format!("_acme-challenge.{dns_name}");
            let record_value = crate::wire::encode_base64url(&Sha256::digest(&key_authorization));
            (
                CertificateChallengeKind::Dns01,
                Dns01Payload::new(&record_name, record_value.as_bytes())?.encode()?,
            )
        }
        _ => return Err(AcmeWorkerError::InvalidInput),
    };
    let request = CertificateChallengeRequest {
        context: execution.context,
        kind,
        identifier: BoundedBytes::copy_from(identifier.as_bytes(), 253)
            .map_err(|_| AcmeWorkerError::InvalidInput)?,
        challenge: payload,
        expires_at,
        order_epoch,
    };
    if let Some(retained) = execution.publication
        && retained.request(execution.context)? != request
    {
        return Err(AcmeWorkerError::InvalidInput);
    }
    Ok(request)
}

fn key_authorization(signer: &impl AcmeJwsSigner, token: &str) -> Result<String, AcmeWorkerError> {
    if token.is_empty() {
        return Err(AcmeWorkerError::InvalidInput);
    }
    Ok(format!("{token}.{}", signer.public_jwk()?.thumbprint()))
}

impl From<crate::PayloadError> for AcmeWorkerError {
    fn from(_: crate::PayloadError) -> Self {
        Self::InvalidInput
    }
}
