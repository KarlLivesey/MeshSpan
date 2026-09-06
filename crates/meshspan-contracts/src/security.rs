// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable authentication-handler and certificate-challenge contracts.

use std::future::Future;

use meshspan_domain::{AssuranceLevel, PrincipalId, Revision, UnixMicros};

use crate::{BoundedBytes, ComponentLifecycle, ContractError, RequestContext, VersionedPayload};

/// One bounded authentication message bound to a transport session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationAttempt {
    /// Operation identity, deadline and selected handler contract.
    pub context: RequestContext,
    /// Optional claimed principal; it is never treated as authenticated input.
    pub principal_hint: Option<PrincipalId>,
    /// Digest binding the attempt to its transport and anti-CSRF/session state.
    pub session_binding_digest: [u8; 32],
    /// Handler-owned, independently versioned credential message.
    pub credential: VersionedPayload,
}

/// Bounded next step or terminal result of one authentication exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationOutcome {
    /// No authenticated identity was established.
    Rejected,
    /// Another bounded factor or ceremony response is required.
    Continue(VersionedPayload),
    /// A principal and assurance were established against an exact identity revision.
    Authenticated {
        /// Authenticated user or service principal.
        principal_id: PrincipalId,
        /// Assurance established by the complete exchange.
        assurance: AssuranceLevel,
        /// Authoritative identity/configuration revision used by the decision.
        identity_revision: Revision,
        /// Digest binding the resulting session to the complete exchange.
        authentication_digest: [u8; 32],
    },
}

/// Authentication method implementation without permission or namespace authority.
pub trait AuthenticationHandler: ComponentLifecycle {
    /// Evaluates one hostile bounded credential message.
    ///
    /// # Errors
    ///
    /// Returns stable malformed, stale, unavailable and resource failures; invalid credentials
    /// use [`AuthenticationOutcome::Rejected`] without leaking which check failed.
    fn authenticate(
        &mut self,
        attempt: &AuthenticationAttempt,
    ) -> Result<AuthenticationOutcome, ContractError>;
}

/// ACME challenge transport selected for one order authorisation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateChallengeKind {
    /// Publish an exact token at the HTTP-01 well-known path.
    Http01,
    /// Publish an exact TXT value through a configured DNS provider.
    Dns01,
}

/// Fenced bounded ACME challenge publication request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateChallengeRequest {
    /// Operation identity, deadline and contract version.
    pub context: RequestContext,
    /// Selected challenge transport.
    pub kind: CertificateChallengeKind,
    /// Canonical ASCII identifier validated by the ACME coordinator.
    pub identifier: BoundedBytes,
    /// Provider-owned token/name/value representation.
    pub challenge: VersionedPayload,
    /// Exclusive expiry after which publication must not be trusted.
    pub expires_at: UnixMicros,
    /// Leader/order epoch fencing stale publishers.
    pub order_epoch: u64,
}

/// Durable evidence of one exact challenge publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateChallengeReceipt {
    /// Revision of the challenge provider configuration.
    pub configuration_revision: Revision,
    /// Leader/order epoch that performed publication.
    pub order_epoch: u64,
    /// Digest binding the exact published name/path and value.
    pub publication_digest: [u8; 32],
}

/// Whether exact challenge removal has finished, rather than merely been requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateChallengeCleanup {
    /// Removal is durably requested but not yet confirmed; retry the same receipt later.
    Pending,
    /// The exact publication was removed or its absence was proved.
    Complete,
}

/// HTTP-01 or DNS-01 publication without certificate private-key access.
pub trait CertificateChallenge: ComponentLifecycle {
    /// Publishes one exact fenced challenge idempotently.
    ///
    /// # Errors
    ///
    /// Rejects stale epochs, unsupported kinds, invalid identifiers and provider failures.
    fn publish(
        &mut self,
        request: &CertificateChallengeRequest,
    ) -> impl Future<Output = Result<CertificateChallengeReceipt, ContractError>> + Send;

    /// Observes whether the exact publication is externally visible.
    ///
    /// # Errors
    ///
    /// Rejects stale receipts and returns unavailable for inconclusive provider observations.
    fn is_visible(
        &self,
        request: &CertificateChallengeRequest,
        receipt: CertificateChallengeReceipt,
    ) -> impl Future<Output = Result<bool, ContractError>> + Send;

    /// Removes only the exact fenced publication represented by the receipt.
    /// The request retains the original publication expiry even when it is in the past;
    /// its current operation deadline is independent. Exact absence permits an idempotent
    /// completion, never deletion of a replacement publication. A durable removal task
    /// without confirmed removal returns `Pending`, not `Complete`.
    ///
    /// # Errors
    ///
    /// Rejects stale or mismatched cleanup rather than deleting unrelated provider state.
    fn cleanup(
        &mut self,
        request: &CertificateChallengeRequest,
        receipt: CertificateChallengeReceipt,
    ) -> impl Future<Output = Result<CertificateChallengeCleanup, ContractError>> + Send;
}
