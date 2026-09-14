// SPDX-License-Identifier: GPL-2.0-only

//! Headless installer report. The coordinator trusts only its independently verified signature.

use crate::BoundaryError;
use serde::{Deserialize, Serialize};

#[cfg(test)]
#[path = "recovery_installation_tests.rs"]
mod tests;

/// Bounded installer output shared by node installation and offline receipt collection.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryInstallationReport {
    /// Local publication completed; this remains an untrusted caller claim during collection.
    pub installed: bool,
    /// Installation alone must never start service.
    pub service_started: bool,
    /// Human-readable limitation of the installation claim.
    pub scope: String,
    /// Decimal certificate generation.
    pub node_certificate_generation: String,
    /// Decimal certificate expiry in Unix seconds.
    pub node_certificate_not_after_unix_seconds: String,
    /// Lowercase hexadecimal digest of the installed encrypted bundle.
    pub sha256: String,
    /// Decimal count of verified encrypted generations.
    pub verified_secret_generations: String,
    /// Hexadecimal signed message; the coordinator reconstructs rather than trusts this field.
    pub installation_message: String,
    /// DER P-256 signature in canonical lowercase hexadecimal.
    pub installation_signature: String,
}

/// Extracts a bounded signature from original JSON, rejecting duplicate/unknown fields and coercion.
/// Other report claims are never authority and must not be echoed as verified by a collector.
/// # Errors
/// Rejects excessive or malformed reports, unsuccessful installation and invalid signature encoding.
pub fn decode_recovery_installation_signature(bytes: &[u8]) -> Result<Vec<u8>, BoundaryError> {
    if bytes.len() > 16 * 1024 {
        return Err(BoundaryError::BodyTooLarge { limit: 16 * 1024 });
    }
    let report: RecoveryInstallationReport =
        serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    let encoded = report.installation_signature.as_bytes();
    if !report.installed
        || report.service_started
        || !(16..=144).contains(&encoded.len())
        || !encoded.len().is_multiple_of(2)
        || !encoded
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(BoundaryError::DecodeMismatch);
    }
    encoded
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| BoundaryError::DecodeMismatch)?,
                16,
            )
            .map_err(|_| BoundaryError::DecodeMismatch)
        })
        .collect()
}
