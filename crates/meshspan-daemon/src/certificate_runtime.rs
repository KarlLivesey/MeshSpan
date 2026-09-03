// SPDX-License-Identifier: GPL-2.0-only

//! Lifecycle composition for automatic certificate issuance and shared HTTP-01 state.

use std::{future::Future, sync::Arc, time::Duration};

use meshspan_acme::{Http01Challenge, Rfc2136ProviderPolicy};
use meshspan_dns::AuthoritativeTxtResolver;
use meshspan_domain::{Clock, DurationMicros, NodeId};
use rustls::{ClientConfig, RootCertStore};
use thiserror::Error;

use crate::{
    CertificateAutomationComponents, CertificateAutomationError, CertificateAutomationOutcome,
    CertificateAutomationPolicy, CertificateAutomationService, CertificateExecutionFactoryError,
    CertificateOrderDrivePolicy, CertificateOrderDriverError, CertificateOrderPreparationService,
    CertificateOrderResultError, CertificateOrderResultService, ConsensusAuthenticationAuthority,
    InProcessCertificateExecutionFactory, InProcessCertificateRuntimeComponents,
    InProcessCertificateRuntimePolicy, LocalWrappingKey, OperatingSystemClock,
    OperatingSystemRandom, PublicCertificateInstallationWorker,
    PublicCertificateInstallationWorkerComponents, PublicCertificateInstallationWorkerError,
    PublicCertificateInstallationWorkerOutcome, RotatingHttpsIdentity,
    SharedManualDnsTaskAuthority, SystemAuthoritativeTxtObserver,
};

const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(5);
const ACTIVE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const CLAIM_LEASE_MICROS: u64 = 5 * 60 * 1_000_000;
const RENEWAL_LEAD_MICROS: u64 = 30 * 24 * 60 * 60 * 1_000_000;
const ADMISSION_PAGE_ITEMS: usize = 32;
const DRIVE_REQUEST_TIMEOUT_MICROS: u64 = 2 * 60 * 1_000_000;
const DRIVE_MAXIMUM_STEPS: usize = 16;
const EXTERNAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const EXTERNAL_REQUEST_TIMEOUT: Duration = Duration::from_mins(2);
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TTL_SECONDS: u32 = 60;
const RFC2136_TSIG_FUDGE_SECONDS: u16 = 30;

type CertificateService = CertificateAutomationService<
    ConsensusAuthenticationAuthority,
    CertificateOrderPreparationService<
        ConsensusAuthenticationAuthority,
        LocalWrappingKey,
        OperatingSystemRandom,
    >,
    InProcessCertificateExecutionFactory<
        SharedManualDnsTaskAuthority,
        SystemAuthoritativeTxtObserver,
        OperatingSystemRandom,
        OperatingSystemClock,
    >,
    OperatingSystemRandom,
    OperatingSystemClock,
>;

type CertificateInstallation = PublicCertificateInstallationWorker<
    ConsensusAuthenticationAuthority,
    ConsensusAuthenticationAuthority,
    ConsensusAuthenticationAuthority,
    LocalWrappingKey,
>;

/// Independently owned consensus readers required by one certificate runtime.
pub(crate) struct CertificateAuthoritySet {
    pub scheduler: ConsensusAuthenticationAuthority,
    pub checkpoint: ConsensusAuthenticationAuthority,
    pub completion: ConsensusAuthenticationAuthority,
    pub retry: ConsensusAuthenticationAuthority,
    pub preparation: ConsensusAuthenticationAuthority,
    pub manual_dns: ConsensusAuthenticationAuthority,
    pub installation_selection: ConsensusAuthenticationAuthority,
    pub installation_generation: ConsensusAuthenticationAuthority,
    pub installation_acknowledgement: ConsensusAuthenticationAuthority,
}

/// One restart-scoped certificate worker and its shared HTTP-01 challenge catalogue.
pub(crate) struct CertificateRuntime {
    service: CertificateService,
    installation: CertificateInstallation,
    http01: Http01Challenge,
}

impl CertificateRuntime {
    /// Composes every in-process certificate capability without starting network activity.
    ///
    /// # Errors
    ///
    /// Rejects unavailable platform trust, invalid resolver configuration or invalid bounds.
    pub fn new(
        authorities: CertificateAuthoritySet,
        wrapping_key: LocalWrappingKey,
        installation_wrapping_key: LocalWrappingKey,
        https_identity: RotatingHttpsIdentity,
        node_id: NodeId,
        worker_incarnation: u64,
    ) -> Result<Self, CertificateRuntimeError> {
        let trust_roots = native_trust_roots()?;
        let tls = acme_client_config(trust_roots.clone())?;
        let observer = SystemAuthoritativeTxtObserver::new(AuthoritativeTxtResolver::from_system(
            DNS_TIMEOUT,
        )?);
        let http01 = Http01Challenge::new();
        let rfc2136 =
            Rfc2136ProviderPolicy::new(DNS_TIMEOUT, DNS_TTL_SECONDS, RFC2136_TSIG_FUDGE_SECONDS)?;
        let runtime_policy = InProcessCertificateRuntimePolicy::new(
            EXTERNAL_CONNECT_TIMEOUT,
            EXTERNAL_REQUEST_TIMEOUT,
            DNS_TTL_SECONDS,
            rfc2136,
        )?;
        let drive = CertificateOrderDrivePolicy::new(
            DurationMicros::new(DRIVE_REQUEST_TIMEOUT_MICROS),
            DRIVE_MAXIMUM_STEPS,
        )?;
        let policy = CertificateAutomationPolicy::new(
            DurationMicros::new(CLAIM_LEASE_MICROS),
            DurationMicros::new(RENEWAL_LEAD_MICROS),
            ADMISSION_PAGE_ITEMS,
            drive,
        )?;
        let preparation = CertificateOrderPreparationService::new(
            authorities.preparation,
            wrapping_key,
            OperatingSystemRandom,
        );
        let execution_factory =
            InProcessCertificateExecutionFactory::new(InProcessCertificateRuntimeComponents {
                authority: SharedManualDnsTaskAuthority::new(authorities.manual_dns),
                observer,
                random: OperatingSystemRandom,
                clock: OperatingSystemClock,
                tls,
                http01: http01.clone(),
                policy: runtime_policy,
            });
        let service = CertificateAutomationService::new(CertificateAutomationComponents {
            authority: authorities.scheduler,
            checkpoint_authority: authorities.checkpoint,
            completion_authority: authorities.completion,
            retry_authority: authorities.retry,
            preparation,
            execution_factory,
            random: OperatingSystemRandom,
            clock: OperatingSystemClock,
            worker_node_id: node_id,
            worker_incarnation,
            policy,
            result: CertificateOrderResultService::new(trust_roots)?,
        });
        let installation = PublicCertificateInstallationWorker::new(
            PublicCertificateInstallationWorkerComponents {
                selection: authorities.installation_selection,
                generation: authorities.installation_generation,
                decryptor: installation_wrapping_key,
                acknowledgement: authorities.installation_acknowledgement,
                identity: https_identity,
                gateway_node_id: node_id,
                gateway_incarnation: worker_incarnation,
            },
        )?;
        Ok(Self {
            service,
            installation,
            http01,
        })
    }

    /// Returns the catalogue served by the isolated plain-HTTP listener.
    #[must_use]
    pub fn http01(&self) -> Http01Challenge {
        self.http01.clone()
    }

    /// Runs one serial certificate worker until shutdown or a closed internal failure.
    ///
    /// # Errors
    ///
    /// Fails when a blocking worker stops unexpectedly or certificate authority evidence cannot
    /// be processed safely. Typed external ACME and DNS failures are durably retried by the
    /// service and do not terminate this loop.
    pub async fn run_until<F>(mut self, shutdown: F) -> Result<(), CertificateRuntimeError>
    where
        F: Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        loop {
            let mut service = self.service;
            let mut installation = self.installation;
            let runtime = tokio::runtime::Handle::current();
            let (returned_service, returned_installation, outcome) =
                tokio::task::spawn_blocking(move || {
                    let automation = runtime.block_on(service.run_once());
                    let outcome =
                        automation
                            .map_err(CertificateRuntimeError::from)
                            .and_then(|automation| {
                                installation
                                    .run_once(OperatingSystemClock.now())
                                    .map(|installed| (automation, installed))
                                    .map_err(CertificateRuntimeError::from)
                            });
                    (service, installation, outcome)
                })
                .await
                .map_err(|_| CertificateRuntimeError::WorkerStopped)?;
            self.service = returned_service;
            self.installation = returned_installation;
            let (automation, installation) = outcome?;
            let interval = match (automation, installation) {
                (CertificateAutomationOutcome::Order { .. }, _)
                | (_, PublicCertificateInstallationWorkerOutcome::Installed(_)) => {
                    ACTIVE_POLL_INTERVAL
                }
                _ => IDLE_POLL_INTERVAL,
            };
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                () = tokio::time::sleep(interval) => {}
            }
        }
    }
}

fn native_trust_roots() -> Result<RootCertStore, CertificateRuntimeError> {
    let loaded = rustls_native_certs::load_native_certs();
    if !loaded.errors.is_empty() || loaded.certs.is_empty() {
        return Err(CertificateRuntimeError::NativeTrust);
    }
    let mut roots = RootCertStore::empty();
    for certificate in loaded.certs {
        roots
            .add(certificate)
            .map_err(|_| CertificateRuntimeError::NativeTrust)?;
    }
    Ok(roots)
}

fn acme_client_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, CertificateRuntimeError> {
    let provider = Arc::new(meshspan_rustls_provider::provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| CertificateRuntimeError::NativeTrust)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Closed certificate lifecycle construction and execution failure.
#[derive(Debug, Error)]
pub(crate) enum CertificateRuntimeError {
    /// The platform root store could not be loaded completely into the supported TLS profile.
    #[error("native certificate trust is unavailable")]
    NativeTrust,
    /// System DNS discovery configuration is unavailable or invalid.
    #[error("system DNS authority discovery is unavailable")]
    Resolver(#[from] meshspan_dns::AuthoritativeResolverError),
    /// A challenge-provider lifecycle policy is invalid.
    #[error("certificate provider policy is invalid")]
    ProviderPolicy(#[from] meshspan_contracts::ContractError),
    /// In-process transport and provider bounds are invalid.
    #[error("certificate execution policy is invalid")]
    ExecutionPolicy(#[from] CertificateExecutionFactoryError),
    /// Bounded order-driving policy is invalid.
    #[error("certificate drive policy is invalid")]
    DrivePolicy(#[from] CertificateOrderDriverError),
    /// Certificate worker scheduling or execution failed closed.
    #[error("certificate automation failed")]
    Automation(#[from] CertificateAutomationError),
    /// Certificate result trust validation could not be constructed.
    #[error("certificate result validation is unavailable")]
    Result(#[from] CertificateOrderResultError),
    /// Gateway certificate selection, decryption or acknowledgement failed closed.
    #[error("public certificate installation failed")]
    Installation(#[from] PublicCertificateInstallationWorkerError),
    /// The blocking certificate task stopped without returning its service state.
    #[error("certificate worker stopped unexpectedly")]
    WorkerStopped,
}
