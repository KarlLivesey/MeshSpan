// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic sources for time and entropy.

use thiserror::Error;

use crate::UnixMicros;

/// Supplies authoritative time without reading a process-global clock in domain code.
pub trait Clock {
    /// Returns the current authoritative instant for one domain decision.
    fn now(&self) -> UnixMicros;
}

/// Supplies cryptographic random bytes through an injectable boundary.
pub trait RandomSource {
    /// Fills the complete destination or returns a typed failure.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyError`] when secure bytes cannot be obtained.
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError>;
}

/// Failure to obtain the requested secure random bytes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("secure entropy is unavailable")]
pub struct EntropyError;
