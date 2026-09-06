// SPDX-License-Identifier: GPL-2.0-only

use super::{
    AcmeAuthorization, AcmeChallengeRecord, AcmeDirectory, AcmeMachineAction, AcmeMachineError,
    AcmeOrder, AcmeOrderMachine, Phase,
};

impl AcmeOrderMachine {
    pub(super) fn action_for_phase(&self) -> Result<AcmeMachineAction, AcmeMachineError> {
        match self.phase {
            Phase::DiscoverDirectory => Ok(AcmeMachineAction::DiscoverDirectory {
                url: self.directory_url.clone(),
            }),
            Phase::AcquireNonce => Ok(AcmeMachineAction::AcquireNonce {
                url: self.directory()?.new_nonce.clone(),
            }),
            Phase::CreateAccount => Ok(AcmeMachineAction::CreateAccount {
                url: self.directory()?.new_account.clone(),
                nonce: self.nonce()?,
            }),
            Phase::CreateOrder => Ok(AcmeMachineAction::CreateOrder {
                url: self.directory()?.new_order.clone(),
                nonce: self.nonce()?,
                account_url: self.account_url()?,
                request: self.request.clone(),
            }),
            Phase::FetchAuthorization => Ok(AcmeMachineAction::FetchAuthorization {
                url: self.authorization_url()?,
                nonce: self.nonce()?,
                account_url: self.account_url()?,
            }),
            Phase::PublishChallenge => {
                let authorization = self.authorization()?;
                Ok(AcmeMachineAction::PublishChallenge {
                    dns_name: authorization.dns_name.clone(),
                    wildcard: authorization.wildcard,
                    challenge: self.challenge()?,
                    order_epoch: self.publication_epoch().unwrap_or(self.order_epoch),
                })
            }
            Phase::NotifyChallenge => Ok(AcmeMachineAction::NotifyChallenge {
                url: self.challenge()?.url,
                nonce: self.nonce()?,
                account_url: self.account_url()?,
            }),
            Phase::PollAuthorization => Ok(AcmeMachineAction::PollAuthorization {
                url: self.authorization_url()?,
                nonce: self.nonce()?,
                account_url: self.account_url()?,
            }),
            Phase::CleanupChallenge => {
                let authorization = self.authorization()?;
                Ok(AcmeMachineAction::CleanupChallenge {
                    dns_name: authorization.dns_name.clone(),
                    wildcard: authorization.wildcard,
                    challenge: self.challenge()?,
                    publication_digest: self
                        .publication_digest
                        .ok_or(AcmeMachineError::CorruptState)?,
                    order_epoch: self.publication_epoch().unwrap_or(self.order_epoch),
                })
            }
            Phase::FinalizeOrder => Ok(AcmeMachineAction::FinalizeOrder {
                url: self.order()?.finalize.clone(),
                nonce: self.nonce()?,
                account_url: self.account_url()?,
            }),
            Phase::PollOrder => Ok(AcmeMachineAction::PollOrder {
                url: self.order_url()?,
                nonce: self.nonce()?,
                account_url: self.account_url()?,
            }),
            Phase::DownloadCertificate => Ok(AcmeMachineAction::DownloadCertificate {
                url: self
                    .order()?
                    .certificate
                    .clone()
                    .ok_or(AcmeMachineError::CorruptState)?,
                nonce: self.nonce()?,
                account_url: self.account_url()?,
            }),
            Phase::Complete => Ok(AcmeMachineAction::Complete {
                certificate: self
                    .certificate
                    .clone()
                    .ok_or(AcmeMachineError::CorruptState)?,
            }),
        }
    }

    fn directory(&self) -> Result<&AcmeDirectory, AcmeMachineError> {
        self.directory
            .as_ref()
            .ok_or(AcmeMachineError::CorruptState)
    }

    fn nonce(&self) -> Result<String, AcmeMachineError> {
        self.nonce.clone().ok_or(AcmeMachineError::CorruptState)
    }

    fn account_url(&self) -> Result<String, AcmeMachineError> {
        self.account_url
            .clone()
            .ok_or(AcmeMachineError::CorruptState)
    }

    fn order_url(&self) -> Result<String, AcmeMachineError> {
        self.order_url.clone().ok_or(AcmeMachineError::CorruptState)
    }

    fn order(&self) -> Result<&AcmeOrder, AcmeMachineError> {
        self.order.as_ref().ok_or(AcmeMachineError::CorruptState)
    }

    fn authorization(&self) -> Result<&AcmeAuthorization, AcmeMachineError> {
        self.authorization
            .as_ref()
            .ok_or(AcmeMachineError::CorruptState)
    }

    fn authorization_url(&self) -> Result<String, AcmeMachineError> {
        self.order()?
            .authorizations
            .get(self.authorization_index)
            .cloned()
            .ok_or(AcmeMachineError::CorruptState)
    }

    fn challenge(&self) -> Result<AcmeChallengeRecord, AcmeMachineError> {
        self.challenge.clone().ok_or(AcmeMachineError::CorruptState)
    }
}
