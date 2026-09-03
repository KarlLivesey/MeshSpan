// SPDX-License-Identifier: GPL-2.0-only

//! In-process, bounded ACME challenge primitives with no external runtime service dependency.

mod challenge_payload;
mod component;
mod dns01;
mod http01;
mod jws;
mod order_machine;
mod strict_json;
mod wire;

pub use challenge_payload::{Dns01Payload, Http01Payload, PayloadError};
pub use dns01::{Dns01Challenge, DnsTxtProvider, DnsTxtReceipt};
pub use http01::Http01Challenge;
pub use jws::{AcmeAccountBinding, AcmeJwsSigner, AcmePublicJwk, AcmeSignedRequest};
pub use order_machine::{
    AcmeChallengePreference, AcmeMachineAction, AcmeMachineError, AcmeMachineEvent,
    AcmeOrderMachine,
};
pub use wire::{
    AcmeAuthorization, AcmeBadNonceRetry, AcmeChallengeRecord, AcmeDirectory, AcmeHttpResponse,
    AcmeOrder, AcmeOrderRequest, AcmeProblem, AcmeProtocolError, AcmeResourceStatus,
    AcmeResponseHeaders, AcmeWire,
};

#[cfg(test)]
mod order_machine_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod wire_tests;
