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
        let authorization = AcmeWire::authorization(&response)?;
        let replay_nonce = AcmeWire::replay_nonce(&response)?;
        let event = if poll {
            AcmeMachineEvent::AuthorizationPolled {
                authorization,
                replay_nonce,
            }
        } else {
            AcmeMachineEvent::AuthorizationFetched {
                authorization,
                replay_nonce,
            }
        };
        Ok(AcmeStepOutcome::Advanced(event))
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
        Ok(AcmeStepOutcome::Advanced(
            AcmeMachineEvent::ChallengeNotified {
                replay_nonce: AcmeWire::challenge_acknowledgement(&response)?,
            },
        ))
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
        Ok(AcmeStepOutcome::Advanced(
            AcmeMachineEvent::OrderFinalized {
                order: AcmeWire::order(&response)?,
                replay_nonce: AcmeWire::replay_nonce(&response)?,
            },
        ))
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
        Ok(AcmeStepOutcome::Advanced(AcmeMachineEvent::OrderPolled {
            order: AcmeWire::order(&response)?,
            replay_nonce: AcmeWire::replay_nonce(&response)?,
        }))
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
        Ok(AcmeStepOutcome::Advanced(
            AcmeMachineEvent::CertificateDownloaded(AcmeWire::certificate(&response)?),
        ))
    }
}
