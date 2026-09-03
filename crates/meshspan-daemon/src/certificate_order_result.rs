// SPDX-License-Identifier: GPL-2.0-only

//! Trust validation and atomic publication of a terminal ACME order result.

use std::sync::Arc;
use std::time::Duration;

use meshspan_domain::{PrincipalId, UnixMicros};
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier as _;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use thiserror::Error;

use crate::{
    CertificateOrderCompletionAuthority, CertificateOrderCompletionCommit,
    CertificateOrderCompletionError, CertificateOrderCompletionService, CertificateOrderExecution,
    CertificateOrderIssuance,
};

const MICROS_PER_SECOND: u64 = 1_000_000;
const WILDCARD_VALIDATION_LABEL: &str = "meshspan-validation";

/// Configured trust-path validator for downloaded ACME certificate chains.
pub struct CertificateOrderResultService {
    verifier: Arc<WebPkiServerVerifier>,
}

impl CertificateOrderResultService {
    /// Builds a verifier from the trust roots configured for the selected certificate authority.
    ///
    /// # Errors
    ///
    /// Rejects an empty or otherwise unusable trust-anchor set.
    pub fn new(trust_roots: RootCertStore) -> Result<Self, CertificateOrderResultError> {
        let provider = Arc::new(meshspan_rustls_provider::provider());
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(trust_roots), provider)
            .build()
            .map_err(|_| CertificateOrderResultError::InvalidTrust)?;
        Ok(Self { verifier })
    }

    /// Validates a terminal response and commits the same key and chain to every gateway envelope.
    ///
    /// The execution object binds the response to its claimed order, exact configuration revision,
    /// requested names and protected order-specific leaf key.
    ///
    /// # Errors
    ///
    /// Rejects malformed or semantically invalid certificate bytes, an untrusted signature path,
    /// invalid time conversion, a stale claim and any failed fenced completion transaction.
    pub fn complete<A, R, T, C>(
        &self,
        completion_service: &mut CertificateOrderCompletionService<A, R>,
        actor_principal_id: PrincipalId,
        now: UnixMicros,
        execution: &CertificateOrderExecution<T, C>,
        certificate_response: &[u8],
    ) -> Result<CertificateOrderCompletionCommit, CertificateOrderResultError>
    where
        A: CertificateOrderCompletionAuthority,
        R: meshspan_domain::RandomSource,
    {
        let assignment = execution.assignment();
        let claim = assignment
            .order
            .claim
            .ok_or(CertificateOrderResultError::InvalidInput)?;
        let now_seconds = unix_seconds(now)?;
        let validated = meshspan_certificates::validate_external_certificate_response(
            certificate_response,
            &assignment.configuration.certificate_names,
            execution.certificate_key(),
            now_seconds,
        )?;
        self.verify_trust(
            validated.bundle().certificate_chain(),
            &assignment.configuration.certificate_names,
            now_seconds,
        )?;
        let issuance = CertificateOrderIssuance {
            order_id: assignment.order.order_id,
            claim,
            not_before: unix_micros(validated.not_before_unix_seconds())?,
            not_after: unix_micros(validated.not_after_unix_seconds())?,
            bundle: validated.into_bundle(),
        };
        completion_service
            .complete(actor_principal_id, now, &issuance)
            .map_err(Into::into)
    }

    fn verify_trust(
        &self,
        certificate_chain: &[Vec<u8>],
        dns_names: &[String],
        now_seconds: u64,
    ) -> Result<(), CertificateOrderResultError> {
        let (leaf, intermediates) = certificate_chain
            .split_first()
            .ok_or(CertificateOrderResultError::InvalidCertificate)?;
        let leaf = CertificateDer::from(leaf.as_slice());
        let intermediates = intermediates
            .iter()
            .map(|certificate| CertificateDer::from(certificate.as_slice()))
            .collect::<Vec<_>>();
        let now = UnixTime::since_unix_epoch(Duration::from_secs(now_seconds));
        for name in dns_names {
            let validation_name = wildcard_validation_name(name);
            let server_name = ServerName::try_from(validation_name)
                .map_err(|_| CertificateOrderResultError::InvalidCertificate)?;
            self.verifier
                .verify_server_cert(&leaf, &intermediates, &server_name, &[], now)
                .map_err(|_| CertificateOrderResultError::InvalidTrust)?;
        }
        Ok(())
    }
}

fn wildcard_validation_name(name: &str) -> String {
    name.strip_prefix("*.").map_or_else(
        || name.to_owned(),
        |suffix| format!("{WILDCARD_VALIDATION_LABEL}.{suffix}"),
    )
}

fn unix_seconds(now: UnixMicros) -> Result<u64, CertificateOrderResultError> {
    let micros = u64::try_from(now.get()).map_err(|_| CertificateOrderResultError::InvalidInput)?;
    Ok(micros / MICROS_PER_SECOND)
}

fn unix_micros(seconds: u64) -> Result<UnixMicros, CertificateOrderResultError> {
    let micros = seconds
        .checked_mul(MICROS_PER_SECOND)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(CertificateOrderResultError::InvalidCertificate)?;
    Ok(UnixMicros::new(micros))
}

/// Closed failure while accepting one terminal external-certificate result.
#[derive(Debug, Error)]
pub enum CertificateOrderResultError {
    /// The order claim or authoritative time is invalid.
    #[error("certificate order result input is invalid")]
    InvalidInput,
    /// The configured external-certificate trust anchors are unusable.
    #[error("certificate order result trust configuration is invalid")]
    InvalidTrust,
    /// The downloaded certificate violates its exact semantic contract.
    #[error("certificate order result is invalid")]
    InvalidCertificate,
    /// Certificate response parsing or semantic validation failed.
    #[error("certificate order result validation failed")]
    Validation(#[from] meshspan_certificates::ExternalCertificateResponseError),
    /// The fenced encrypted completion transaction failed.
    #[error("certificate order result could not be committed")]
    Completion(#[from] CertificateOrderCompletionError),
}
