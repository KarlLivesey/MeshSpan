// SPDX-License-Identifier: GPL-2.0-only

//! Pure resumable ACME order transitions, separate from transport and durable authority I/O.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AcmeAuthorization, AcmeChallengeRecord, AcmeDirectory, AcmeOrder, AcmeOrderRequest,
    AcmeProtocolError, AcmeResourceStatus,
};

mod action;
mod checkpoint;

/// Configured challenge family for one immutable order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcmeChallengePreference {
    /// Publish an HTTP token on every eligible gateway.
    Http01,
    /// Publish and independently observe an authoritative DNS TXT value.
    Dns01,
}

/// One exact side effect requested by the pure order state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcmeMachineAction {
    /// Fetch the configured ACME directory.
    DiscoverDirectory {
        /// Configured directory URL.
        url: String,
    },
    /// Acquire a fresh replay nonce.
    AcquireNonce {
        /// Directory-advertised nonce URL.
        url: String,
    },
    /// Create or resolve the account belonging to the configured signer.
    CreateAccount {
        /// Directory-advertised account URL.
        url: String,
        /// Fresh nonce bound into the request.
        nonce: String,
    },
    /// Create an order for the immutable requested DNS-name set.
    CreateOrder {
        /// Directory-advertised order URL.
        url: String,
        /// Fresh nonce bound into the request.
        nonce: String,
        /// Existing account identity used as the JWS key ID.
        account_url: String,
        /// Immutable requested DNS-name set.
        request: AcmeOrderRequest,
    },
    /// Read one authorization resource.
    FetchAuthorization {
        /// Order-advertised authorization URL.
        url: String,
        /// Fresh nonce bound into the request.
        nonce: String,
        /// Existing account identity used as the JWS key ID.
        account_url: String,
    },
    /// Publish and independently prove one selected challenge.
    PublishChallenge {
        /// Authorization DNS name without a wildcard prefix.
        dns_name: String,
        /// Whether the authorization covers the wildcard form of the name.
        wildcard: bool,
        /// Exact server-offered challenge selected by policy.
        challenge: AcmeChallengeRecord,
        /// Fencing epoch carried by publication and cleanup.
        order_epoch: u64,
    },
    /// Tell the ACME server that a proven challenge is ready.
    NotifyChallenge {
        /// Selected challenge URL.
        url: String,
        /// Fresh nonce bound into the request.
        nonce: String,
        /// Existing account identity used as the JWS key ID.
        account_url: String,
    },
    /// Poll one authorization after challenge notification.
    PollAuthorization {
        /// Current authorization URL.
        url: String,
        /// Fresh nonce bound into the request.
        nonce: String,
        /// Existing account identity used as the JWS key ID.
        account_url: String,
    },
    /// Remove only the exact challenge publication proved by the receipt digest.
    CleanupChallenge {
        /// Authorization DNS name without a wildcard prefix.
        dns_name: String,
        /// Whether the authorization covers the wildcard form of the name.
        wildcard: bool,
        /// Exact published challenge.
        challenge: AcmeChallengeRecord,
        /// Exact publication receipt digest.
        publication_digest: [u8; 32],
        /// Fencing epoch carried by publication and cleanup.
        order_epoch: u64,
    },
    /// Finalize an order with a generated certificate signing request.
    FinalizeOrder {
        /// Order-advertised finalization URL.
        url: String,
        /// Fresh nonce bound into the request.
        nonce: String,
        /// Existing account identity used as the JWS key ID.
        account_url: String,
    },
    /// Poll the canonical order resource.
    PollOrder {
        /// Canonical order URL.
        url: String,
        /// Fresh nonce bound into the request.
        nonce: String,
        /// Existing account identity used as the JWS key ID.
        account_url: String,
    },
    /// Download the issued certificate chain.
    DownloadCertificate {
        /// Order-advertised issued-certificate URL.
        url: String,
        /// Fresh nonce bound into the request.
        nonce: String,
        /// Existing account identity used as the JWS key ID.
        account_url: String,
    },
    /// The certificate bytes are ready for cryptographic validation and encrypted publication.
    Complete {
        /// Bounded certificate response awaiting cryptographic validation.
        certificate: Vec<u8>,
    },
}

/// One proven result fed back after completing the current machine action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcmeMachineEvent {
    /// Successfully parsed directory.
    DirectoryDiscovered(AcmeDirectory),
    /// Fresh validated replay nonce.
    NonceAcquired(String),
    /// Account URL and next replay nonce from account creation or lookup.
    AccountCreated {
        /// Canonical account resource URL.
        account_url: String,
        /// Fresh replay nonce returned with the response.
        replay_nonce: String,
    },
    /// Canonical order URL, parsed order and next replay nonce.
    OrderCreated {
        /// Canonical order resource URL.
        order_url: String,
        /// Parsed order resource.
        order: AcmeOrder,
        /// Fresh replay nonce returned with the response.
        replay_nonce: String,
    },
    /// Parsed authorization and next replay nonce.
    AuthorizationFetched {
        /// Parsed authorization resource.
        authorization: AcmeAuthorization,
        /// Fresh replay nonce returned with the response.
        replay_nonce: String,
    },
    /// Exact nonzero receipt digest from challenge publication and visibility proof.
    ChallengePublished {
        /// Exact nonzero publication receipt digest.
        publication_digest: [u8; 32],
    },
    /// Challenge-ready request accepted with a next replay nonce.
    ChallengeNotified {
        /// Fresh replay nonce returned with the response.
        replay_nonce: String,
    },
    /// Parsed authorization poll and next replay nonce.
    AuthorizationPolled {
        /// Parsed authorization resource.
        authorization: AcmeAuthorization,
        /// Fresh replay nonce returned with the response.
        replay_nonce: String,
    },
    /// Exact challenge publication was removed or proved already absent.
    ChallengeCleaned,
    /// Parsed order returned by finalization and its next replay nonce.
    OrderFinalized {
        /// Parsed order resource returned after finalization.
        order: AcmeOrder,
        /// Fresh replay nonce returned with the response.
        replay_nonce: String,
    },
    /// Parsed order poll and next replay nonce.
    OrderPolled {
        /// Parsed current order resource.
        order: AcmeOrder,
        /// Fresh replay nonce returned with the response.
        replay_nonce: String,
    },
    /// Bounded nonempty certificate response body.
    CertificateDownloaded(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    DiscoverDirectory,
    AcquireNonce,
    CreateAccount,
    CreateOrder,
    FetchAuthorization,
    PublishChallenge,
    NotifyChallenge,
    PollAuthorization,
    CleanupChallenge,
    FinalizeOrder,
    PollOrder,
    DownloadCertificate,
    Complete,
}

/// Validated, cloneable ACME checkpoint. The complete value is the resumable machine state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcmeOrderMachine {
    directory_url: String,
    request: AcmeOrderRequest,
    preference: AcmeChallengePreference,
    order_epoch: u64,
    phase: Phase,
    directory: Option<AcmeDirectory>,
    nonce: Option<String>,
    account_url: Option<String>,
    order_url: Option<String>,
    order: Option<AcmeOrder>,
    authorization_index: usize,
    authorized_names: Vec<String>,
    authorization: Option<AcmeAuthorization>,
    challenge: Option<AcmeChallengeRecord>,
    publication_digest: Option<[u8; 32]>,
    certificate: Option<Vec<u8>>,
}

impl AcmeOrderMachine {
    /// Starts one immutable order from a validated request and positive fencing epoch.
    ///
    /// # Errors
    ///
    /// Rejects an invalid directory URL or zero fencing epoch.
    pub fn new(
        directory_url: String,
        request: AcmeOrderRequest,
        preference: AcmeChallengePreference,
        order_epoch: u64,
    ) -> Result<Self, AcmeMachineError> {
        crate::wire::bounded_url(&directory_url)?;
        if order_epoch == 0 {
            return Err(AcmeMachineError::InvalidInput);
        }
        Ok(Self {
            directory_url,
            request,
            preference,
            order_epoch,
            phase: Phase::DiscoverDirectory,
            directory: None,
            nonce: None,
            account_url: None,
            order_url: None,
            order: None,
            authorization_index: 0,
            authorized_names: Vec::new(),
            authorization: None,
            challenge: None,
            publication_digest: None,
            certificate: None,
        })
    }

    /// Returns the sole side effect currently allowed by this checkpoint.
    ///
    /// # Errors
    ///
    /// Fails closed if an incomplete or contradictory checkpoint is observed.
    pub fn action(&self) -> Result<AcmeMachineAction, AcmeMachineError> {
        self.action_for_phase()
    }

    /// Encodes the complete validated state needed to resume this exact order.
    ///
    /// # Errors
    ///
    /// Fails closed if the in-memory state is contradictory or exceeds the checkpoint bound.
    pub fn encode_checkpoint(&self) -> Result<Vec<u8>, AcmeMachineError> {
        self.encode_validated_checkpoint()
    }

    /// Restores one complete versioned order checkpoint from hostile bytes.
    ///
    /// # Errors
    ///
    /// Rejects malformed, excessive, unknown-version or internally contradictory state.
    pub fn decode_checkpoint(bytes: &[u8]) -> Result<Self, AcmeMachineError> {
        Self::decode_validated_checkpoint(bytes)
    }

    /// Applies one exact result only when it matches the current action.
    ///
    /// # Errors
    ///
    /// Rejects out-of-order, contradictory, invalid or name-changing results.
    pub fn advance(&mut self, event: AcmeMachineEvent) -> Result<(), AcmeMachineError> {
        match (self.phase, event) {
            (Phase::DiscoverDirectory, AcmeMachineEvent::DirectoryDiscovered(directory)) => {
                self.directory = Some(directory);
                self.phase = Phase::AcquireNonce;
            }
            (Phase::AcquireNonce, AcmeMachineEvent::NonceAcquired(nonce)) => {
                validate_nonce(&nonce)?;
                self.nonce = Some(nonce);
                self.phase = Phase::CreateAccount;
            }
            (
                Phase::CreateAccount,
                AcmeMachineEvent::AccountCreated {
                    account_url,
                    replay_nonce,
                },
            ) => {
                validate_remote_identity(&account_url, &replay_nonce)?;
                self.account_url = Some(account_url);
                self.nonce = Some(replay_nonce);
                self.phase = Phase::CreateOrder;
            }
            (
                Phase::CreateOrder,
                AcmeMachineEvent::OrderCreated {
                    order_url,
                    order,
                    replay_nonce,
                },
            ) => {
                validate_remote_identity(&order_url, &replay_nonce)?;
                self.accept_order(order_url, order, replay_nonce)?;
            }
            (
                Phase::FetchAuthorization,
                AcmeMachineEvent::AuthorizationFetched {
                    authorization,
                    replay_nonce,
                },
            ) => self.accept_authorization(authorization, replay_nonce, false)?,
            (
                Phase::PublishChallenge,
                AcmeMachineEvent::ChallengePublished { publication_digest },
            ) => {
                if publication_digest == [0; 32] {
                    return Err(AcmeMachineError::InvalidInput);
                }
                self.publication_digest = Some(publication_digest);
                self.phase = Phase::NotifyChallenge;
            }
            (Phase::NotifyChallenge, AcmeMachineEvent::ChallengeNotified { replay_nonce }) => {
                validate_nonce(&replay_nonce)?;
                self.nonce = Some(replay_nonce);
                self.phase = Phase::PollAuthorization;
            }
            (
                Phase::PollAuthorization,
                AcmeMachineEvent::AuthorizationPolled {
                    authorization,
                    replay_nonce,
                },
            ) => self.accept_authorization(authorization, replay_nonce, true)?,
            (Phase::CleanupChallenge, AcmeMachineEvent::ChallengeCleaned) => {
                self.advance_authorization()?;
                self.clear_challenge();
            }
            (
                Phase::FinalizeOrder,
                AcmeMachineEvent::OrderFinalized {
                    order,
                    replay_nonce,
                },
            )
            | (
                Phase::PollOrder,
                AcmeMachineEvent::OrderPolled {
                    order,
                    replay_nonce,
                },
            ) => self.accept_order_update(order, replay_nonce)?,
            (Phase::DownloadCertificate, AcmeMachineEvent::CertificateDownloaded(certificate)) => {
                if certificate.is_empty() {
                    return Err(AcmeMachineError::InvalidInput);
                }
                self.certificate = Some(certificate);
                self.phase = Phase::Complete;
            }
            _ => return Err(AcmeMachineError::InvalidTransition),
        }
        Ok(())
    }

    fn accept_order(
        &mut self,
        order_url: String,
        order: AcmeOrder,
        replay_nonce: String,
    ) -> Result<(), AcmeMachineError> {
        self.validate_order(&order)?;
        self.order_url = Some(order_url);
        self.nonce = Some(replay_nonce);
        self.order = Some(order);
        self.select_order_phase()
    }

    fn accept_order_update(
        &mut self,
        order: AcmeOrder,
        replay_nonce: String,
    ) -> Result<(), AcmeMachineError> {
        validate_nonce(&replay_nonce)?;
        self.validate_order(&order)?;
        self.nonce = Some(replay_nonce);
        self.order = Some(order);
        self.select_order_phase()
    }

    fn select_order_phase(&mut self) -> Result<(), AcmeMachineError> {
        let order = self.order.as_ref().ok_or(AcmeMachineError::CorruptState)?;
        self.phase = match order.status {
            AcmeResourceStatus::Pending
                if self.authorization_index < order.authorizations.len() =>
            {
                Phase::FetchAuthorization
            }
            AcmeResourceStatus::Pending | AcmeResourceStatus::Processing => Phase::PollOrder,
            AcmeResourceStatus::Ready => Phase::FinalizeOrder,
            AcmeResourceStatus::Valid if order.certificate.is_some() => Phase::DownloadCertificate,
            AcmeResourceStatus::Invalid => return Err(AcmeMachineError::RemoteRejected),
            _ => return Err(AcmeMachineError::InvalidRemoteState),
        };
        Ok(())
    }

    fn accept_authorization(
        &mut self,
        authorization: AcmeAuthorization,
        replay_nonce: String,
        was_poll: bool,
    ) -> Result<(), AcmeMachineError> {
        validate_nonce(&replay_nonce)?;
        self.validate_current_authorization(&authorization)?;
        self.nonce = Some(replay_nonce);
        match authorization.status {
            AcmeResourceStatus::Valid if self.publication_digest.is_some() => {
                self.authorization = Some(authorization);
                self.phase = Phase::CleanupChallenge;
            }
            AcmeResourceStatus::Valid => {
                self.authorization = Some(authorization);
                self.advance_authorization()?;
            }
            AcmeResourceStatus::Pending if was_poll => {
                self.authorization = Some(authorization);
                self.phase = Phase::PollAuthorization;
            }
            AcmeResourceStatus::Pending => {
                let challenge = select_challenge(&authorization, self.preference)?;
                self.authorization = Some(authorization);
                self.challenge = Some(challenge);
                self.phase = Phase::PublishChallenge;
            }
            AcmeResourceStatus::Invalid
            | AcmeResourceStatus::Deactivated
            | AcmeResourceStatus::Expired
            | AcmeResourceStatus::Revoked => return Err(AcmeMachineError::RemoteRejected),
            _ => return Err(AcmeMachineError::InvalidRemoteState),
        }
        Ok(())
    }

    fn validate_order(&self, order: &AcmeOrder) -> Result<(), AcmeMachineError> {
        if order.dns_names == self.request.dns_names()
            && order.authorizations.len() == order.dns_names.len()
        {
            if self.order.as_ref().is_some_and(|existing| {
                existing.authorizations != order.authorizations
                    || existing.finalize != order.finalize
            }) {
                Err(AcmeMachineError::InvalidRemoteState)
            } else {
                Ok(())
            }
        } else {
            Err(AcmeMachineError::NameMismatch)
        }
    }

    fn validate_current_authorization(
        &self,
        authorization: &AcmeAuthorization,
    ) -> Result<(), AcmeMachineError> {
        let returned = if authorization.wildcard {
            format!("*.{}", authorization.dns_name)
        } else {
            authorization.dns_name.clone()
        };
        if self.request.dns_names().contains(&returned)
            && !self.authorized_names.contains(&returned)
        {
            Ok(())
        } else {
            Err(AcmeMachineError::NameMismatch)
        }
    }

    fn advance_authorization(&mut self) -> Result<(), AcmeMachineError> {
        let authorization = self
            .authorization
            .as_ref()
            .ok_or(AcmeMachineError::CorruptState)?;
        let name = if authorization.wildcard {
            format!("*.{}", authorization.dns_name)
        } else {
            authorization.dns_name.clone()
        };
        if !self.request.dns_names().contains(&name) || self.authorized_names.contains(&name) {
            return Err(AcmeMachineError::CorruptState);
        }
        self.authorized_names.push(name);
        self.authorization_index += 1;
        self.authorization = None;
        self.phase = if self
            .order
            .as_ref()
            .is_some_and(|order| self.authorization_index < order.authorizations.len())
        {
            Phase::FetchAuthorization
        } else if self.authorized_names.len() == self.request.dns_names().len() {
            Phase::PollOrder
        } else {
            return Err(AcmeMachineError::InvalidRemoteState);
        };
        Ok(())
    }

    fn clear_challenge(&mut self) {
        self.authorization = None;
        self.challenge = None;
        self.publication_digest = None;
    }
}

fn select_challenge(
    authorization: &AcmeAuthorization,
    preference: AcmeChallengePreference,
) -> Result<AcmeChallengeRecord, AcmeMachineError> {
    let kind = match preference {
        AcmeChallengePreference::Http01 if authorization.wildcard => {
            return Err(AcmeMachineError::UnsupportedChallenge);
        }
        AcmeChallengePreference::Http01 => "http-01",
        AcmeChallengePreference::Dns01 => "dns-01",
    };
    authorization
        .challenges
        .iter()
        .find(|challenge| challenge.kind == kind)
        .cloned()
        .ok_or(AcmeMachineError::UnsupportedChallenge)
}

fn validate_remote_identity(url: &str, nonce: &str) -> Result<(), AcmeMachineError> {
    crate::wire::bounded_url(url)?;
    validate_nonce(nonce)
}

fn validate_nonce(value: &str) -> Result<(), AcmeMachineError> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Err(AcmeMachineError::InvalidInput)
    } else {
        Ok(())
    }
}

/// Closed state-machine failure without CA diagnostic or secret content.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcmeMachineError {
    /// Configured or event input is invalid.
    #[error("ACME machine input is invalid")]
    InvalidInput,
    /// An event does not belong to the current phase.
    #[error("ACME machine event is out of order")]
    InvalidTransition,
    /// A typed remote resource is not valid in the current transition.
    #[error("ACME remote state is invalid")]
    InvalidRemoteState,
    /// Returned identifiers differ from the immutable requested names.
    #[error("ACME returned a different identifier set")]
    NameMismatch,
    /// The CA did not offer the configured challenge family.
    #[error("ACME configured challenge is unavailable")]
    UnsupportedChallenge,
    /// The CA rejected the authorization or order.
    #[error("ACME remote resource was rejected")]
    RemoteRejected,
    /// A checkpoint is incomplete or internally contradictory.
    #[error("ACME checkpoint failed closed")]
    CorruptState,
    /// Wire value failed validation.
    #[error("ACME wire value failed validation")]
    Protocol,
}

impl From<AcmeProtocolError> for AcmeMachineError {
    fn from(_: AcmeProtocolError) -> Self {
        Self::Protocol
    }
}
