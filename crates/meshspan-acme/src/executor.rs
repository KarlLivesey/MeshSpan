// SPDX-License-Identifier: GPL-2.0-only

//! One-step ACME executor over replaceable in-process HTTP and challenge boundaries.

use std::future::Future;

use meshspan_contracts::{CertificateChallenge, ContractError, RequestContext};
use meshspan_domain::UnixMicros;
use thiserror::Error;

use crate::{
    AcmeAccountBinding, AcmeBadNonceRetry, AcmeJwsSigner, AcmeMachineAction, AcmeMachineEvent,
    AcmeProtocolError, AcmeSignedRequest, AcmeWire,
};

mod challenge_steps;
mod remote_steps;

/// HTTP methods required by RFC 8555.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeHttpMethod {
    /// Unsigned directory retrieval.
    Get,
    /// Fresh-nonce request without a response body.
    Head,
    /// Signed JWS request.
    Post,
}

/// Complete bounded request supplied to an in-process ACME transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcmeTransportRequest {
    /// HTTP method.
    pub method: AcmeHttpMethod,
    /// Exact validated HTTPS URL.
    pub url: String,
    /// JWS body for POST, empty for GET and HEAD.
    pub body: Vec<u8>,
    /// Media type when a body is present.
    pub content_type: Option<&'static str>,
}

/// Replaceable HTTP client boundary; implementations remain in process and return bounded responses.
pub trait AcmeTransport {
    /// Sends one already validated request without following redirects implicitly.
    ///
    /// # Errors
    ///
    /// Reports availability or closed transport failures without leaking credentials or bodies.
    fn send(
        &mut self,
        request: &AcmeTransportRequest,
    ) -> impl Future<Output = Result<crate::AcmeHttpResponse, AcmeTransportError>> + Send;
}

/// Authority-bound inputs required for challenge publication and CSR finalization.
#[derive(Clone, Copy, Debug)]
pub struct AcmeChallengeExecution<'a> {
    /// Operation, contract version, deadline and exact provider-configuration revision.
    pub context: RequestContext,
    /// Exclusive expiry for a challenge publication.
    pub challenge_expires_at: UnixMicros,
    /// DER-encoded CSR generated for this exact immutable name set.
    pub csr_der: &'a [u8],
}

/// Result of one side effect. Pending means the same action is safe to retry later.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcmeStepOutcome {
    /// Feed this proven event into the state machine.
    Advanced(AcmeMachineEvent),
    /// Publication visibility or requested removal is not yet proven.
    Pending,
    /// No side effect remains; certificate bytes are ready for validation and completion.
    Complete(Vec<u8>),
}

/// Executes exactly one machine action and never advances state itself.
pub struct AcmeStepExecutor<T, S, C> {
    transport: T,
    signer: S,
    challenge: C,
}

impl<T, S, C> AcmeStepExecutor<T, S, C> {
    /// Binds one HTTP transport, protected account signer and challenge publisher.
    #[must_use]
    pub const fn new(transport: T, signer: S, challenge: C) -> Self {
        Self {
            transport,
            signer,
            challenge,
        }
    }

    /// Returns the composed implementations after a worker step sequence.
    #[must_use]
    pub fn into_parts(self) -> (T, S, C) {
        (self.transport, self.signer, self.challenge)
    }
}

impl<T, S, C> AcmeStepExecutor<T, S, C>
where
    T: AcmeTransport,
    S: AcmeJwsSigner,
    C: CertificateChallenge,
{
    /// Performs only the requested action and returns its validated event.
    ///
    /// # Errors
    ///
    /// Fails closed on transport, wire, signer, challenge, context or transition input errors.
    pub async fn execute(
        &mut self,
        action: &AcmeMachineAction,
        execution: AcmeChallengeExecution<'_>,
    ) -> Result<AcmeStepOutcome, AcmeWorkerError> {
        match action {
            AcmeMachineAction::DiscoverDirectory { url } => self.discover(url).await,
            AcmeMachineAction::AcquireNonce { url } => self.acquire_nonce(url).await,
            AcmeMachineAction::CreateAccount { url, nonce } => {
                self.create_account(url, nonce).await
            }
            AcmeMachineAction::CreateOrder {
                url,
                nonce,
                account_url,
                request,
            } => self.create_order(url, nonce, account_url, request).await,
            AcmeMachineAction::FetchAuthorization {
                url,
                nonce,
                account_url,
            } => {
                self.fetch_authorization(url, nonce, account_url, false)
                    .await
            }
            AcmeMachineAction::PublishChallenge {
                dns_name,
                wildcard,
                challenge,
                order_epoch,
            } => {
                self.publish_challenge(dns_name, *wildcard, challenge, *order_epoch, execution)
                    .await
            }
            AcmeMachineAction::NotifyChallenge {
                url,
                nonce,
                account_url,
            } => self.notify_challenge(url, nonce, account_url).await,
            AcmeMachineAction::PollAuthorization {
                url,
                nonce,
                account_url,
            } => {
                self.fetch_authorization(url, nonce, account_url, true)
                    .await
            }
            AcmeMachineAction::CleanupChallenge {
                dns_name,
                wildcard,
                challenge,
                publication_digest,
                order_epoch,
            } => {
                self.cleanup_challenge(
                    dns_name,
                    *wildcard,
                    challenge,
                    *publication_digest,
                    *order_epoch,
                    execution,
                )
                .await
            }
            AcmeMachineAction::FinalizeOrder {
                url,
                nonce,
                account_url,
            } => {
                self.finalize(url, nonce, account_url, execution.csr_der)
                    .await
            }
            AcmeMachineAction::PollOrder {
                url,
                nonce,
                account_url,
            } => self.poll_order(url, nonce, account_url).await,
            AcmeMachineAction::DownloadCertificate {
                url,
                nonce,
                account_url,
            } => self.download_certificate(url, nonce, account_url).await,
            AcmeMachineAction::Complete { certificate } => {
                Ok(AcmeStepOutcome::Complete(certificate.clone()))
            }
        }
    }

    async fn discover(&mut self, url: &str) -> Result<AcmeStepOutcome, AcmeWorkerError> {
        let response = self
            .send_remote(&request(AcmeHttpMethod::Get, url, Vec::new())?)
            .await?;
        Ok(AcmeStepOutcome::Advanced(
            AcmeMachineEvent::DirectoryDiscovered(AcmeWire::directory(&response)?),
        ))
    }

    async fn acquire_nonce(&mut self, url: &str) -> Result<AcmeStepOutcome, AcmeWorkerError> {
        let response = self
            .send_remote(&request(AcmeHttpMethod::Head, url, Vec::new())?)
            .await?;
        Ok(AcmeStepOutcome::Advanced(AcmeMachineEvent::NonceAcquired(
            AcmeWire::nonce_response(&response)?,
        )))
    }

    async fn create_account(
        &mut self,
        url: &str,
        nonce: &str,
    ) -> Result<AcmeStepOutcome, AcmeWorkerError> {
        let response = self
            .post_signed(nonce, |fresh_nonce, signer| {
                AcmeWire::new_account(url, fresh_nonce, signer)
            })
            .await?;
        Ok(AcmeStepOutcome::Advanced(
            AcmeMachineEvent::AccountCreated {
                account_url: AcmeWire::account_location(&response)?,
                replay_nonce: AcmeWire::replay_nonce(&response)?,
            },
        ))
    }

    async fn create_order(
        &mut self,
        url: &str,
        nonce: &str,
        account_url: &str,
        order: &crate::AcmeOrderRequest,
    ) -> Result<AcmeStepOutcome, AcmeWorkerError> {
        let binding = AcmeAccountBinding::ExistingAccount(account_url.to_owned());
        let response = self
            .post_signed(nonce, |fresh_nonce, signer| {
                AcmeWire::new_order(url, fresh_nonce, &binding, order, signer)
            })
            .await?;
        Ok(AcmeStepOutcome::Advanced(AcmeMachineEvent::OrderCreated {
            order_url: AcmeWire::resource_location(&response)?,
            order: AcmeWire::order(&response)?,
            replay_nonce: AcmeWire::replay_nonce(&response)?,
        }))
    }

    async fn post_signed<F>(
        &mut self,
        nonce: &str,
        build: F,
    ) -> Result<crate::AcmeHttpResponse, AcmeWorkerError>
    where
        F: Fn(&str, &S) -> Result<AcmeSignedRequest, AcmeProtocolError>,
    {
        let first = build(nonce, &self.signer)?;
        let response = self.send_remote(&signed_request(first)).await?;
        if (200..300).contains(&response.status) {
            return Ok(response);
        }
        let problem = AcmeWire::problem(&response)?;
        let mut retry = AcmeBadNonceRetry::default();
        let Some(fresh_nonce) = retry.consume(&problem, &response)? else {
            return Ok(response);
        };
        let second = build(&fresh_nonce, &self.signer)?;
        let response = self.send_remote(&signed_request(second)).await?;
        if !(200..300).contains(&response.status) {
            let second_problem = AcmeWire::problem(&response)?;
            let _ = retry.consume(&second_problem, &response)?;
        }
        Ok(response)
    }

    async fn send_remote(
        &mut self,
        request: &AcmeTransportRequest,
    ) -> Result<crate::AcmeHttpResponse, AcmeWorkerError> {
        let response = self.transport.send(request).await?;
        if !(200..300).contains(&response.status) {
            let retry_after = response.headers.retry_after()?;
            if retry_after.is_some() || matches!(response.status, 429 | 503) {
                return Err(AcmeWorkerError::RemoteRetry { retry_after });
            }
        }
        Ok(response)
    }
}

fn request(
    method: AcmeHttpMethod,
    url: &str,
    body: Vec<u8>,
) -> Result<AcmeTransportRequest, AcmeWorkerError> {
    crate::wire::bounded_url(url)?;
    if method != AcmeHttpMethod::Post && !body.is_empty() {
        return Err(AcmeWorkerError::InvalidInput);
    }
    Ok(AcmeTransportRequest {
        method,
        url: url.to_owned(),
        content_type: (method == AcmeHttpMethod::Post).then_some("application/jose+json"),
        body,
    })
}

fn signed_request(value: crate::AcmeSignedRequest) -> AcmeTransportRequest {
    AcmeTransportRequest {
        method: AcmeHttpMethod::Post,
        url: value.url,
        body: value.body,
        content_type: Some("application/jose+json"),
    }
}

/// Closed in-process transport failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcmeTransportError {
    /// Network, resolver or peer is temporarily unavailable.
    #[error("ACME transport is unavailable")]
    Unavailable,
    /// TLS, redirect or response framing violated the transport policy.
    #[error("ACME transport rejected the exchange")]
    Rejected,
}

/// Closed worker failure without secret, nonce, token, body or CA diagnostic content.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcmeWorkerError {
    /// Local execution input is incomplete or invalid.
    #[error("ACME worker input is invalid")]
    InvalidInput,
    /// HTTP transport failed.
    #[error("ACME worker transport failed")]
    Transport,
    /// ACME wire validation failed.
    #[error("ACME worker protocol failed")]
    Protocol,
    /// The CA requests a later attempt; no remote text or secret material is retained.
    #[error("ACME authority requested a later attempt")]
    RemoteRetry {
        /// Validated server guidance; absence leaves the scheduler's local backoff in effect.
        retry_after: Option<crate::AcmeRetryAfter>,
    },
    /// Challenge provider rejected or could not complete the action.
    #[error("ACME worker challenge failed")]
    Challenge,
}

impl From<AcmeTransportError> for AcmeWorkerError {
    fn from(_: AcmeTransportError) -> Self {
        Self::Transport
    }
}

impl From<AcmeProtocolError> for AcmeWorkerError {
    fn from(_: AcmeProtocolError) -> Self {
        Self::Protocol
    }
}

impl From<ContractError> for AcmeWorkerError {
    fn from(_: ContractError) -> Self {
        Self::Challenge
    }
}
