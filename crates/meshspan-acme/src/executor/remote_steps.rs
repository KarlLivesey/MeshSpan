// SPDX-License-Identifier: GPL-2.0-only

use super::{
    AcmeAccountBinding, AcmeMachineEvent, AcmeStepExecutor, AcmeStepOutcome, AcmeTransport,
    AcmeWire, AcmeWorkerError, CertificateChallenge,
};
use crate::AcmeJwsSigner;

impl<T, S, C> AcmeStepExecutor<T, S, C>
where
    T: AcmeTransport,
    S: AcmeJwsSigner,
    C: CertificateChallenge,
{
    pub(super) async fn fetch_authorization(
        &mut self,
        url: &str,
        nonce: &str,
        account_url: &str,
        poll: bool,
    ) -> Result<AcmeStepOutcome, AcmeWorkerError> {
        let binding = AcmeAccountBinding::ExistingAccount(account_url.to_owned());
        let response = self
            .post_signed(nonce, |fresh_nonce, signer| {
                AcmeWire::post_as_get(url, fresh_nonce, &binding, signer)
            })
            .await?;
        progress_with_retry(&response, |response| {
            let authorization = AcmeWire::authorization(response)?;
            let replay_nonce = AcmeWire::replay_nonce(response)?;
            Ok(if poll {
                AcmeMachineEvent::AuthorizationPolled {
                    authorization,
                    replay_nonce,
                }
            } else {
                AcmeMachineEvent::AuthorizationFetched {
                    authorization,
                    replay_nonce,
                }
            })
        })
    }

    pub(super) async fn notify_challenge(
        &mut self,
        url: &str,
        nonce: &str,
        account_url: &str,
    ) -> Result<AcmeStepOutcome, AcmeWorkerError> {
        let binding = AcmeAccountBinding::ExistingAccount(account_url.to_owned());
        let response = self
            .post_signed(nonce, |fresh_nonce, signer| {
                AcmeWire::challenge_ready(url, fresh_nonce, &binding, signer)
            })
            .await?;
        progress_with_retry(&response, |response| {
            Ok(AcmeMachineEvent::ChallengeNotified {
                replay_nonce: AcmeWire::challenge_acknowledgement(response)?,
            })
        })
    }

    pub(super) async fn finalize(
        &mut self,
        url: &str,
        nonce: &str,
        account_url: &str,
        csr_der: &[u8],
    ) -> Result<AcmeStepOutcome, AcmeWorkerError> {
        let binding = AcmeAccountBinding::ExistingAccount(account_url.to_owned());
        let response = self
            .post_signed(nonce, |fresh_nonce, signer| {
                AcmeWire::finalize(url, fresh_nonce, &binding, csr_der, signer)
            })
            .await?;
        progress_with_retry(&response, |response| {
            Ok(AcmeMachineEvent::OrderFinalized {
                order: AcmeWire::order(response)?,
                replay_nonce: AcmeWire::replay_nonce(response)?,
            })
        })
    }

    pub(super) async fn poll_order(
        &mut self,
        url: &str,
        nonce: &str,
        account_url: &str,
    ) -> Result<AcmeStepOutcome, AcmeWorkerError> {
        let binding = AcmeAccountBinding::ExistingAccount(account_url.to_owned());
        let response = self
            .post_signed(nonce, |fresh_nonce, signer| {
                AcmeWire::post_as_get(url, fresh_nonce, &binding, signer)
            })
            .await?;
        progress_with_retry(&response, |response| {
            Ok(AcmeMachineEvent::OrderPolled {
                order: AcmeWire::order(response)?,
                replay_nonce: AcmeWire::replay_nonce(response)?,
            })
        })
    }

    pub(super) async fn download_certificate(
        &mut self,
        url: &str,
        nonce: &str,
        account_url: &str,
    ) -> Result<AcmeStepOutcome, AcmeWorkerError> {
        let binding = AcmeAccountBinding::ExistingAccount(account_url.to_owned());
        let response = self
            .post_signed(nonce, |fresh_nonce, signer| {
                AcmeWire::post_as_get(url, fresh_nonce, &binding, signer)
            })
            .await?;
        progress_with_retry(&response, |response| {
            Ok(AcmeMachineEvent::CertificateDownloaded(
                AcmeWire::certificate(response)?,
            ))
        })
    }
}

pub(super) fn progress_with_retry(
    response: &crate::AcmeHttpResponse,
    parse: impl FnOnce(&crate::AcmeHttpResponse) -> Result<AcmeMachineEvent, crate::AcmeProtocolError>,
) -> Result<AcmeStepOutcome, AcmeWorkerError> {
    // Guidance is independent of payload validity. A malformed or ambiguous header still
    // fails closed, but a valid deadline survives all subsequent response-field validation.
    let retry_after = response.headers.retry_after()?;
    let event = parse(response).map_err(|_| match retry_after {
        Some(_) => AcmeWorkerError::RemoteRetry { retry_after },
        None => AcmeWorkerError::Protocol,
    })?;
    Ok(match retry_after {
        Some(retry_after) => AcmeStepOutcome::AdvancedWithRetry { event, retry_after },
        None => AcmeStepOutcome::Advanced(event),
    })
}
