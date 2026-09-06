// SPDX-License-Identifier: GPL-2.0-only

//! In-process, bounded ACME challenge primitives with no external runtime service dependency.

mod account_key;
mod challenge_payload;
mod cloudflare_provider;
#[cfg(test)]
mod cloudflare_provider_tests;
mod cloudflare_transport;
mod cloudflare_v4;
#[cfg(test)]
mod cloudflare_v4_tests;
mod component;
mod dns01;
mod dns_provider_settings;
#[cfg(test)]
mod dns_provider_settings_tests;
mod executor;
mod http01;
mod jws;
mod manual_dns01;
#[cfg(test)]
mod manual_dns01_tests;
mod order_machine;
mod publication;
mod retry_after;
mod rfc2136_provider;
#[cfg(test)]
mod rfc2136_provider_tests;
#[cfg(test)]
mod rfc2136_test_server;
mod rustls_http;
mod strict_json;
mod transport;
mod webhook_provider;
#[cfg(test)]
mod webhook_provider_tests;
mod webhook_transport;
mod webhook_v1;
#[cfg(test)]
mod webhook_v1_tests;
mod wire;

pub use account_key::{AcmeAccountKey, AcmeAccountKeyError};
pub use challenge_payload::{Dns01Payload, Http01Payload, PayloadError};
pub use cloudflare_provider::{
    AuthoritativeTxtObserver, CloudflareDnsApi, CloudflareDnsProvider, CloudflareTxtRecord,
};
pub use cloudflare_transport::RustlsCloudflareHttpTransport;
pub use cloudflare_v4::{
    CloudflareHttpMethod, CloudflareHttpRequest, CloudflareHttpResponse, CloudflareHttpTransport,
    CloudflareV4Api,
};
pub use dns_provider_settings::{
    CloudflareDnsSettings, DnsProviderSettings, DnsProviderSettingsError, Rfc2136DnsSettings,
    Rfc2136TsigAlgorithm, WebhookDnsSettings,
};
pub use dns01::{Dns01Challenge, DnsTxtProvider, DnsTxtReceipt};
pub use executor::{
    AcmeChallengeExecution, AcmeHttpMethod, AcmeStepExecutor, AcmeStepOutcome, AcmeTransport,
    AcmeTransportError, AcmeTransportRequest, AcmeWorkerError,
};
pub use http01::Http01Challenge;
pub use jws::{AcmeAccountBinding, AcmeJwsSigner, AcmePublicJwk, AcmeSignedRequest};
pub use manual_dns01::{
    ManualDns01Challenge, ManualDnsTask, ManualDnsTaskAuthority, ManualDnsTaskPhase,
};
pub use order_machine::{
    AcmeChallengePreference, AcmeMachineAction, AcmeMachineError, AcmeMachineEvent,
    AcmeOrderMachine,
};
pub use publication::AcmeChallengePublication;
pub use retry_after::AcmeRetryAfter;
pub use rfc2136_provider::{Rfc2136DnsProvider, Rfc2136ProviderPolicy};
pub use transport::RustlsAcmeTransport;
pub use webhook_provider::{WebhookDnsAction, WebhookDnsApi, WebhookDnsProvider, WebhookDnsRecord};
pub use webhook_transport::RustlsWebhookHttpTransport;
pub use webhook_v1::{WebhookHttpRequest, WebhookHttpResponse, WebhookHttpTransport, WebhookV1Api};
pub use wire::{
    AcmeAuthorization, AcmeBadNonceRetry, AcmeChallengeRecord, AcmeDirectory, AcmeHttpResponse,
    AcmeOrder, AcmeOrderRequest, AcmeProblem, AcmeProtocolError, AcmeResourceStatus,
    AcmeResponseHeaders, AcmeWire,
};

#[cfg(test)]
mod executor_tests;
#[cfg(test)]
mod order_machine_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wire_tests;
