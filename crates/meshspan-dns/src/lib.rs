// SPDX-License-Identifier: GPL-2.0-only

//! Bounded DNS wire primitives for authoritative ACME DNS-01 publication and probing.

mod wire;
#[cfg(test)]
mod wire_tests;

pub use wire::{DnsName, DnsQuery, DnsWireError, TxtValue};
