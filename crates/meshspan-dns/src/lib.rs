// SPDX-License-Identifier: GPL-2.0-only

//! Bounded DNS wire primitives for authoritative ACME DNS-01 publication and probing.

mod authoritative_probe;
#[cfg(test)]
mod authoritative_probe_tests;
mod wire;
#[cfg(test)]
mod wire_tests;

pub use authoritative_probe::{AuthoritativeDnsError, AuthoritativeTxtProbe};
pub use wire::{DnsName, DnsQuery, DnsWireError, TxtValue};
