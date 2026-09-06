// SPDX-License-Identifier: GPL-2.0-only

//! Concrete selection of every built-in ACME transport and challenge implementation.

use std::{sync::Arc, time::Duration};

use meshspan_acme::{
    AuthoritativeTxtObserver, CloudflareDnsProvider, CloudflareV4Api, Dns01Challenge,
    DnsProviderSettings, Http01Challenge, ManualDns01Challenge, Rfc2136DnsProvider,
    Rfc2136ProviderPolicy, RustlsAcmeTransport, RustlsCloudflareHttpTransport,
    RustlsWebhookHttpTransport, WebhookDnsProvider, WebhookV1Api,
};
use meshspan_contracts::{
    CertificateChallenge, CertificateChallengeCleanup, CertificateChallengeReceipt,
    CertificateChallengeRequest, ComponentConfiguration, ComponentLifecycle, ComponentObservation,
    ComponentTransition, ContractError, ImplementationDescriptor,
};
use meshspan_domain::{Clock, RandomSource, Revision, UnixMicros};
use meshspan_metadata::AcmeChallengeKind;
use rustls::ClientConfig;

use crate::{
    CertificateExecutionFactory, CertificateExecutionFactoryError, CertificateOrderExecution,
    ConsensusManualDnsTaskAuthority, ManualDnsTaskCommitAuthority, PreparedCertificateOrder,
};

type Rfc2136Challenge<R, C> = Dns01Challenge<Rfc2136DnsProvider<R, C>>;
type CloudflareChallenge<O> =
    Dns01Challenge<CloudflareDnsProvider<CloudflareV4Api<RustlsCloudflareHttpTransport>, O>>;
type WebhookChallenge<O> =
    Dns01Challenge<WebhookDnsProvider<WebhookV1Api<RustlsWebhookHttpTransport>, O>>;
type ManualChallenge<A, O, C> = ManualDns01Challenge<ConsensusManualDnsTaskAuthority<A, C>, O>;

/// Which built-in challenge implementation one prepared order selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InProcessChallengeKind {
    /// Shared in-memory HTTP-01 catalogue served by every eligible gateway.
    Http01,
    /// Authenticated RFC 2136 update with TSIG.
    Rfc2136,
    /// Scoped Cloudflare v4 DNS API.
    Cloudflare,
    /// Authenticated version-one HTTPS webhook.
    Webhook,
    /// Durable operator task plus automatic authoritative observation.
    ManualDns,
}

/// Closed runtime enum allowing one automation loop to drive every built-in challenge.
pub enum InProcessCertificateChallenge<A, O, R, C> {
    /// HTTP-01.
    Http01(Http01Challenge),
    /// RFC 2136 DNS-01.
    Rfc2136(Rfc2136Challenge<R, C>),
    /// Cloudflare DNS-01.
    Cloudflare(CloudflareChallenge<O>),
    /// Authenticated webhook DNS-01.
    Webhook(WebhookChallenge<O>),
    /// Manual DNS-01.
    ManualDns(ManualChallenge<A, O, C>),
}

impl<A, O, R, C> InProcessCertificateChallenge<A, O, R, C> {
    /// Returns the selected non-secret implementation identity.
    #[must_use]
    pub const fn kind(&self) -> InProcessChallengeKind {
        match self {
            Self::Http01(_) => InProcessChallengeKind::Http01,
            Self::Rfc2136(_) => InProcessChallengeKind::Rfc2136,
            Self::Cloudflare(_) => InProcessChallengeKind::Cloudflare,
            Self::Webhook(_) => InProcessChallengeKind::Webhook,
            Self::ManualDns(_) => InProcessChallengeKind::ManualDns,
        }
    }
}

impl<A, O, R, C> ComponentLifecycle for InProcessCertificateChallenge<A, O, R, C>
where
    Http01Challenge: ComponentLifecycle,
    Rfc2136Challenge<R, C>: ComponentLifecycle,
    CloudflareChallenge<O>: ComponentLifecycle,
    WebhookChallenge<O>: ComponentLifecycle,
    ManualChallenge<A, O, C>: ComponentLifecycle,
{
    fn describe(&self) -> ImplementationDescriptor {
        match self {
            Self::Http01(value) => value.describe(),
            Self::Rfc2136(value) => value.describe(),
            Self::Cloudflare(value) => value.describe(),
            Self::Webhook(value) => value.describe(),
            Self::ManualDns(value) => value.describe(),
        }
    }

    fn validate_configuration(
        &self,
        configuration: &ComponentConfiguration,
    ) -> Result<(), ContractError> {
        match self {
            Self::Http01(value) => value.validate_configuration(configuration),
            Self::Rfc2136(value) => value.validate_configuration(configuration),
            Self::Cloudflare(value) => value.validate_configuration(configuration),
            Self::Webhook(value) => value.validate_configuration(configuration),
            Self::ManualDns(value) => value.validate_configuration(configuration),
        }
    }

    fn prepare(
        &mut self,
        configuration: &ComponentConfiguration,
    ) -> Result<ComponentTransition, ContractError> {
        match self {
            Self::Http01(value) => value.prepare(configuration),
            Self::Rfc2136(value) => value.prepare(configuration),
            Self::Cloudflare(value) => value.prepare(configuration),
            Self::Webhook(value) => value.prepare(configuration),
            Self::ManualDns(value) => value.prepare(configuration),
        }
    }

    fn activate(
        &mut self,
        desired_revision: Revision,
    ) -> Result<ComponentTransition, ContractError> {
        match self {
            Self::Http01(value) => value.activate(desired_revision),
            Self::Rfc2136(value) => value.activate(desired_revision),
            Self::Cloudflare(value) => value.activate(desired_revision),
            Self::Webhook(value) => value.activate(desired_revision),
            Self::ManualDns(value) => value.activate(desired_revision),
        }
    }

    fn drain(&mut self, deadline: UnixMicros) -> Result<ComponentTransition, ContractError> {
        match self {
            Self::Http01(value) => value.drain(deadline),
            Self::Rfc2136(value) => value.drain(deadline),
            Self::Cloudflare(value) => value.drain(deadline),
            Self::Webhook(value) => value.drain(deadline),
            Self::ManualDns(value) => value.drain(deadline),
        }
    }

    fn retire(&mut self, desired_revision: Revision) -> Result<ComponentTransition, ContractError> {
        match self {
            Self::Http01(value) => value.retire(desired_revision),
            Self::Rfc2136(value) => value.retire(desired_revision),
            Self::Cloudflare(value) => value.retire(desired_revision),
            Self::Webhook(value) => value.retire(desired_revision),
            Self::ManualDns(value) => value.retire(desired_revision),
        }
    }

    fn observe(&self, observed_at: UnixMicros) -> ComponentObservation {
        match self {
            Self::Http01(value) => value.observe(observed_at),
            Self::Rfc2136(value) => value.observe(observed_at),
            Self::Cloudflare(value) => value.observe(observed_at),
            Self::Webhook(value) => value.observe(observed_at),
            Self::ManualDns(value) => value.observe(observed_at),
        }
    }
}

impl<A, O, R, C> CertificateChallenge for InProcessCertificateChallenge<A, O, R, C>
where
    A: ManualDnsTaskCommitAuthority + Send + Sync,
    O: AuthoritativeTxtObserver + Send + Sync,
    R: RandomSource + Send,
    C: Clock + Send + Sync,
{
    async fn publish(
        &mut self,
        request: &CertificateChallengeRequest,
    ) -> Result<CertificateChallengeReceipt, ContractError> {
        match self {
            Self::Http01(value) => value.publish(request).await,
            Self::Rfc2136(value) => value.publish(request).await,
            Self::Cloudflare(value) => value.publish(request).await,
            Self::Webhook(value) => value.publish(request).await,
            Self::ManualDns(value) => value.publish(request).await,
        }
    }

    async fn is_visible(
        &self,
        request: &CertificateChallengeRequest,
        receipt: CertificateChallengeReceipt,
    ) -> Result<bool, ContractError> {
        match self {
            Self::Http01(value) => value.is_visible(request, receipt).await,
            Self::Rfc2136(value) => value.is_visible(request, receipt).await,
            Self::Cloudflare(value) => value.is_visible(request, receipt).await,
            Self::Webhook(value) => value.is_visible(request, receipt).await,
            Self::ManualDns(value) => value.is_visible(request, receipt).await,
        }
    }

    async fn cleanup(
        &mut self,
        request: &CertificateChallengeRequest,
        receipt: CertificateChallengeReceipt,
    ) -> Result<CertificateChallengeCleanup, ContractError> {
        match self {
            Self::Http01(value) => value.cleanup(request, receipt).await,
            Self::Rfc2136(value) => value.cleanup(request, receipt).await,
            Self::Cloudflare(value) => value.cleanup(request, receipt).await,
            Self::Webhook(value) => value.cleanup(request, receipt).await,
            Self::ManualDns(value) => value.cleanup(request, receipt).await,
        }
    }
}

/// Finite transport and DNS-publication limits shared by the concrete factory.
#[derive(Clone, Copy, Debug)]
pub struct InProcessCertificateRuntimePolicy {
    connect_timeout: Duration,
    request_timeout: Duration,
    dns_ttl_seconds: u32,
    rfc2136: Rfc2136ProviderPolicy,
}

impl InProcessCertificateRuntimePolicy {
    /// Creates explicit bounds for every outbound ACME and DNS-provider request.
    ///
    /// # Errors
    ///
    /// Rejects invalid timeouts and DNS TTLs before an order contacts any remote service.
    pub fn new(
        connect_timeout: Duration,
        request_timeout: Duration,
        dns_ttl_seconds: u32,
        rfc2136: Rfc2136ProviderPolicy,
    ) -> Result<Self, CertificateExecutionFactoryError> {
        if connect_timeout.is_zero()
            || request_timeout.is_zero()
            || connect_timeout > Duration::from_mins(5)
            || request_timeout > Duration::from_mins(5)
            || dns_ttl_seconds != 1 && !(60..=86_400).contains(&dns_ttl_seconds)
        {
            return Err(CertificateExecutionFactoryError::InvalidConfiguration);
        }
        Ok(Self {
            connect_timeout,
            request_timeout,
            dns_ttl_seconds,
            rfc2136,
        })
    }
}

/// Concrete in-process execution factory for all supported ACME challenge modes.
pub struct InProcessCertificateExecutionFactory<A, O, R, C> {
    authority: A,
    observer: O,
    random: R,
    clock: C,
    tls: Arc<ClientConfig>,
    http01: Http01Challenge,
    policy: InProcessCertificateRuntimePolicy,
}

/// Owned inputs needed to construct one provider-selecting factory.
pub struct InProcessCertificateRuntimeComponents<A, O, R, C> {
    /// Consensus-backed authority used only by durable manual DNS tasks.
    pub authority: A,
    /// Exact authoritative DNS observer used by non-RFC2136 modes.
    pub observer: O,
    /// Cryptographic DNS transaction entropy.
    pub random: R,
    /// Authority-aligned time.
    pub clock: C,
    /// Public CA and provider HTTPS trust configuration.
    pub tls: Arc<ClientConfig>,
    /// Shared HTTP-01 catalogue served by eligible gateways.
    pub http01: Http01Challenge,
    /// Finite transport and provider policy.
    pub policy: InProcessCertificateRuntimePolicy,
}

impl<A, O, R, C> InProcessCertificateExecutionFactory<A, O, R, C> {
    /// Composes the built-in challenge implementations without contacting any remote endpoint.
    #[must_use]
    pub fn new(components: InProcessCertificateRuntimeComponents<A, O, R, C>) -> Self {
        Self {
            authority: components.authority,
            observer: components.observer,
            random: components.random,
            clock: components.clock,
            tls: components.tls,
            http01: components.http01,
            policy: components.policy,
        }
    }

    fn transport(&self) -> Result<RustlsAcmeTransport, CertificateExecutionFactoryError> {
        RustlsAcmeTransport::new(
            self.tls.clone(),
            self.policy.connect_timeout,
            self.policy.request_timeout,
        )
        .map_err(|_| CertificateExecutionFactoryError::InvalidConfiguration)
    }

    fn challenge(
        &self,
        prepared: &mut PreparedCertificateOrder,
    ) -> Result<InProcessCertificateChallenge<A, O, R, C>, CertificateExecutionFactoryError>
    where
        A: Clone,
        O: Clone,
        R: Clone,
        C: Clone,
    {
        match prepared.assignment.configuration.challenge_kind {
            AcmeChallengeKind::Http01 => {
                if prepared.challenge_settings.is_some() {
                    return Err(CertificateExecutionFactoryError::InvalidConfiguration);
                }
                Ok(InProcessCertificateChallenge::Http01(self.http01.clone()))
            }
            AcmeChallengeKind::Dns01 => self.dns_challenge(prepared),
        }
    }

    fn dns_challenge(
        &self,
        prepared: &mut PreparedCertificateOrder,
    ) -> Result<InProcessCertificateChallenge<A, O, R, C>, CertificateExecutionFactoryError>
    where
        A: Clone,
        O: Clone,
        R: Clone,
        C: Clone,
    {
        let Some(settings) = prepared.challenge_settings.take() else {
            let claim = prepared
                .assignment
                .order
                .claim
                .ok_or(CertificateExecutionFactoryError::InvalidConfiguration)?;
            let authority = ConsensusManualDnsTaskAuthority::new(
                self.authority.clone(),
                self.clock.clone(),
                prepared.assignment.order.order_id,
                claim,
                prepared.assignment.configuration.configured_by,
            );
            return Ok(InProcessCertificateChallenge::ManualDns(
                ManualDns01Challenge::new(authority, self.observer.clone()),
            ));
        };
        match DnsProviderSettings::decode(settings.expose())
            .map_err(|_| CertificateExecutionFactoryError::InvalidConfiguration)?
        {
            DnsProviderSettings::Rfc2136(settings) => {
                let provider = Rfc2136DnsProvider::new(
                    settings,
                    self.random.clone(),
                    self.clock.clone(),
                    self.policy.rfc2136,
                )
                .map_err(|_| CertificateExecutionFactoryError::InvalidConfiguration)?;
                Ok(InProcessCertificateChallenge::Rfc2136(Dns01Challenge::new(
                    provider,
                )))
            }
            DnsProviderSettings::Cloudflare(settings) => {
                let transport = RustlsCloudflareHttpTransport::new(
                    self.tls.clone(),
                    self.policy.connect_timeout,
                    self.policy.request_timeout,
                )
                .map_err(|_| CertificateExecutionFactoryError::InvalidConfiguration)?;
                let provider = CloudflareDnsProvider::new(
                    settings,
                    CloudflareV4Api::new(transport),
                    self.observer.clone(),
                    self.policy.dns_ttl_seconds,
                )
                .map_err(|_| CertificateExecutionFactoryError::InvalidConfiguration)?;
                Ok(InProcessCertificateChallenge::Cloudflare(
                    Dns01Challenge::new(provider),
                ))
            }
            DnsProviderSettings::Webhook(settings) => {
                let transport = RustlsWebhookHttpTransport::new(
                    self.tls.clone(),
                    self.policy.connect_timeout,
                    self.policy.request_timeout,
                )
                .map_err(|_| CertificateExecutionFactoryError::InvalidConfiguration)?;
                let provider = WebhookDnsProvider::new(
                    settings,
                    WebhookV1Api::new(transport),
                    self.observer.clone(),
                );
                Ok(InProcessCertificateChallenge::Webhook(Dns01Challenge::new(
                    provider,
                )))
            }
        }
    }
}

impl<A, O, R, C> CertificateExecutionFactory for InProcessCertificateExecutionFactory<A, O, R, C>
where
    A: Clone + ManualDnsTaskCommitAuthority + Send + Sync,
    O: Clone + AuthoritativeTxtObserver + Send + Sync,
    R: Clone + RandomSource + Send,
    C: Clone + Clock + Send + Sync,
{
    type Transport = RustlsAcmeTransport;
    type Challenge = InProcessCertificateChallenge<A, O, R, C>;

    fn create_execution(
        &mut self,
        mut prepared: PreparedCertificateOrder,
    ) -> Result<
        CertificateOrderExecution<Self::Transport, Self::Challenge>,
        CertificateExecutionFactoryError,
    > {
        let transport = self.transport()?;
        let challenge = self.challenge(&mut prepared)?;
        Ok(CertificateOrderExecution::new(
            prepared, transport, challenge,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{future, net::SocketAddr};

    use meshspan_acme::{
        AcmeAccountKey, AcmeChallengePreference, AcmeOrderMachine, AcmeOrderRequest,
        CloudflareDnsSettings, DnsProviderSettings, Rfc2136DnsSettings, Rfc2136TsigAlgorithm,
        WebhookDnsSettings,
    };
    use meshspan_certificates::ExternalCertificateRequestKey;
    use meshspan_domain::{
        AcmeConfigurationId, CertificateOrderId, EntropyError, NodeId, OperationId,
    };
    use meshspan_metadata::{
        AcmeConfigurationRecord, CertificateOrderClaim, CertificateOrderRecord,
        CertificateOrderState, CommandContext, CommandReceipt, SecretGenerationReference,
    };
    use meshspan_secret_envelope::SecretPlaintext;
    use rustls::RootCertStore;

    use super::*;
    use crate::CertificateOrderAssignment;

    #[test]
    fn selects_every_built_in_challenge_from_exact_prepared_configuration()
    -> Result<(), Box<dyn std::error::Error>> {
        let factory = factory()?;
        let cases = [
            (
                AcmeChallengeKind::Http01,
                None,
                InProcessChallengeKind::Http01,
            ),
            (
                AcmeChallengeKind::Dns01,
                Some(rfc2136_settings()?),
                InProcessChallengeKind::Rfc2136,
            ),
            (
                AcmeChallengeKind::Dns01,
                Some(cloudflare_settings()?),
                InProcessChallengeKind::Cloudflare,
            ),
            (
                AcmeChallengeKind::Dns01,
                Some(webhook_settings()?),
                InProcessChallengeKind::Webhook,
            ),
            (
                AcmeChallengeKind::Dns01,
                None,
                InProcessChallengeKind::ManualDns,
            ),
        ];
        for (index, (kind, settings, expected)) in cases.into_iter().enumerate() {
            let mut prepared = prepared(kind, settings, u8::try_from(index + 1)?)?;
            assert_eq!(factory.challenge(&mut prepared)?.kind(), expected);
            assert!(prepared.challenge_settings.is_none());
        }
        Ok(())
    }

    #[test]
    fn rejects_settings_on_http_and_malformed_dns_before_remote_io()
    -> Result<(), Box<dyn std::error::Error>> {
        let factory = factory()?;
        let mut http = prepared(
            AcmeChallengeKind::Http01,
            Some(SecretPlaintext::from_bytes(vec![1])?),
            1,
        )?;
        assert!(matches!(
            factory.challenge(&mut http),
            Err(CertificateExecutionFactoryError::InvalidConfiguration)
        ));
        let mut dns = prepared(
            AcmeChallengeKind::Dns01,
            Some(SecretPlaintext::from_bytes(vec![1])?),
            2,
        )?;
        assert!(matches!(
            factory.challenge(&mut dns),
            Err(CertificateExecutionFactoryError::InvalidConfiguration)
        ));
        Ok(())
    }

    fn factory() -> Result<Factory, Box<dyn std::error::Error>> {
        let provider = Arc::new(meshspan_rustls_provider::provider());
        let tls = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let rfc2136 = Rfc2136ProviderPolicy::new(Duration::from_secs(1), 60, 30)?;
        let policy = InProcessCertificateRuntimePolicy::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            60,
            rfc2136,
        )?;
        Ok(InProcessCertificateExecutionFactory::new(
            InProcessCertificateRuntimeComponents {
                authority: NeverAuthority,
                observer: NeverObserver,
                random: FixedRandom,
                clock: FixedClock,
                tls: Arc::new(tls),
                http01: Http01Challenge::new(),
                policy,
            },
        ))
    }

    type Factory = InProcessCertificateExecutionFactory<
        NeverAuthority,
        NeverObserver,
        FixedRandom,
        FixedClock,
    >;

    fn prepared(
        kind: AcmeChallengeKind,
        challenge_settings: Option<SecretPlaintext>,
        identity: u8,
    ) -> Result<PreparedCertificateOrder, Box<dyn std::error::Error>> {
        let config_id = AcmeConfigurationId::from_bytes([identity; 16])?;
        let order_id = CertificateOrderId::from_bytes([identity.saturating_add(20); 16])?;
        let claim = CertificateOrderClaim {
            generation: 1,
            worker_node_id: NodeId::from_bytes([8; 16])?,
            worker_incarnation: 2,
            fence: 3,
            lease_expires_at: UnixMicros::new(100),
        };
        let names = vec!["files.example.test".to_owned()];
        let preference = match kind {
            AcmeChallengeKind::Http01 => AcmeChallengePreference::Http01,
            AcmeChallengeKind::Dns01 => AcmeChallengePreference::Dns01,
        };
        let machine = AcmeOrderMachine::new(
            "https://ca.example.test/directory".to_owned(),
            AcmeOrderRequest::new(names.clone())?,
            preference,
            claim.fence,
        )?;
        let certificate_key = ExternalCertificateRequestKey::generate()?;
        let csr_der = certificate_key.certificate_signing_request(&names)?;
        Ok(PreparedCertificateOrder {
            assignment: CertificateOrderAssignment {
                order: CertificateOrderRecord {
                    order_id,
                    config_id,
                    state: CertificateOrderState::Claimed,
                    next_attempt_at: UnixMicros::new(1),
                    attempt_count: 1,
                    certificate: None,
                    claim: Some(claim),
                    revision: Revision::new(2),
                },
                configuration: AcmeConfigurationRecord {
                    provisioning_intent_digest: None,
                    config_id,
                    directory_url: "https://ca.example.test/directory".to_owned(),
                    account_key: SecretGenerationReference {
                        secret_id: [4; 16],
                        generation: 1,
                    },
                    challenge_kind: kind,
                    challenge_settings: challenge_settings.as_ref().map(|_| {
                        SecretGenerationReference {
                            secret_id: [5; 16],
                            generation: 1,
                        }
                    }),
                    certificate_names: names,
                    configured_by: meshspan_domain::PrincipalId::from_bytes([9; 16])?,
                    revision: Revision::new(3),
                },
                checkpoint: None,
            },
            machine,
            account_key: account_key()?,
            challenge_settings,
            certificate_key,
            csr_der,
            certificate_key_reference: SecretGenerationReference {
                secret_id: order_id.as_bytes(),
                generation: 1,
            },
        })
    }

    fn account_key() -> Result<AcmeAccountKey, Box<dyn std::error::Error>> {
        let mut scalar = [0_u8; 32];
        scalar[31] = 1;
        Ok(AcmeAccountKey::from_secret_bytes(&scalar)?)
    }

    fn secret(
        settings: &DnsProviderSettings,
    ) -> Result<SecretPlaintext, Box<dyn std::error::Error>> {
        Ok(SecretPlaintext::from_bytes(settings.encode()?.to_vec())?)
    }

    fn rfc2136_settings() -> Result<SecretPlaintext, Box<dyn std::error::Error>> {
        secret(&DnsProviderSettings::Rfc2136(Rfc2136DnsSettings::new(
            "127.0.0.1:53".parse::<SocketAddr>()?,
            "example.test".to_owned(),
            "meshspan-key.example.test".to_owned(),
            Rfc2136TsigAlgorithm::HmacSha256,
            vec![1; 32],
        )?))
    }

    fn cloudflare_settings() -> Result<SecretPlaintext, Box<dyn std::error::Error>> {
        secret(&DnsProviderSettings::Cloudflare(
            CloudflareDnsSettings::new(
                "0123456789abcdef0123456789abcdef".to_owned(),
                b"cloudflare-token-value".to_vec(),
            )?,
        ))
    }

    fn webhook_settings() -> Result<SecretPlaintext, Box<dyn std::error::Error>> {
        secret(&DnsProviderSettings::Webhook(WebhookDnsSettings::new(
            "https://dns.example.test/meshspan".to_owned(),
            b"webhook-bearer-token".to_vec(),
        )?))
    }

    #[derive(Clone, Copy)]
    struct FixedRandom;

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(1);
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> UnixMicros {
            UnixMicros::new(10)
        }
    }

    #[derive(Clone, Copy)]
    struct NeverObserver;

    impl AuthoritativeTxtObserver for NeverObserver {
        fn contains_txt(
            &self,
            _name: &str,
            _value: &[u8],
        ) -> impl std::future::Future<Output = Result<bool, ContractError>> + Send {
            future::ready(Err(ContractError::Unavailable))
        }
    }

    #[derive(Clone, Copy)]
    struct NeverAuthority;

    impl ManualDnsTaskCommitAuthority for NeverAuthority {
        fn resolve_manual_dns_task(
            &self,
            _operation_id: OperationId,
        ) -> Result<Option<CommandReceipt>, ContractError> {
            Err(ContractError::Unavailable)
        }

        fn commit_manual_dns_task(
            &self,
            _context: CommandContext,
            _command: &meshspan_metadata::AuthoritativeCommand,
        ) -> Result<CommandReceipt, ContractError> {
            Err(ContractError::Unavailable)
        }
    }
}
