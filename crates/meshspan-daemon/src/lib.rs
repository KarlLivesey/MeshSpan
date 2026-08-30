// SPDX-License-Identifier: GPL-2.0-only

//! Daemon process composition, configuration and local secret presentation.

mod claim_file;

pub use claim_file::{ClaimFile, ClaimFileError};

use meshspan_domain::{EntropyError, RandomSource};

/// Operating-system cryptographic entropy used by daemon-owned secret material.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperatingSystemRandom;

impl RandomSource for OperatingSystemRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(destination).map_err(|_| EntropyError)
    }
}
