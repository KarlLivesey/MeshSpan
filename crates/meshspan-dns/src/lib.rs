// SPDX-License-Identifier: GPL-2.0-only

//! Bounded DNS wire primitives for authoritative ACME DNS-01 publication and probing.

mod authoritative_probe;
#[cfg(test)]
mod authoritative_probe_tests;
mod rfc2136;
#[cfg(test)]
mod rfc2136_tests;
mod wire;
#[cfg(test)]
mod wire_tests;

pub use authoritative_probe::{AuthoritativeDnsError, AuthoritativeTxtProbe};
pub use rfc2136::{
    Rfc2136Request, Rfc2136RequestError, Rfc2136TsigKey, SignedRfc2136Request, TsigAlgorithm,
    TxtUpdate,
};
pub use wire::{DnsName, DnsQuery, DnsWireError, TxtValue};
