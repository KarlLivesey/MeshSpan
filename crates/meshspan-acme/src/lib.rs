// SPDX-License-Identifier: GPL-2.0-only

//! In-process, bounded ACME challenge primitives with no external runtime service dependency.

mod account_key;
mod challenge_payload;
mod component;
mod dns01;
mod dns_provider_settings;
#[cfg(test)]
mod dns_provider_settings_tests;
mod executor;
mod http01;
mod jws;
mod order_machine;
mod strict_json;
mod transport;
mod wire;

pub use account_key::{AcmeAccountKey, AcmeAccountKeyError};
pub use challenge_payload::{Dns01Payload, Http01Payload, PayloadError};
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
pub use order_machine::{
    AcmeChallengePreference, AcmeMachineAction, AcmeMachineError, AcmeMachineEvent,
    AcmeOrderMachine,
};
pub use transport::RustlsAcmeTransport;
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
