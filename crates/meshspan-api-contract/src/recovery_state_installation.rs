// SPDX-License-Identifier: GPL-2.0-only

//! Strict state installer output. Displayed fields never choose the coordinator's package.

use crate::BoundaryError;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    installed: bool,
    service_started: bool,
    admission_ready: bool,
    node_id: String,
    state_sha256: String,
    installation_message: String,
    installation_signature: String,
    scope: String,
}

/// Extracts a bounded signature only after display fields match the independently expected output.
/// Rust signature verification must still reconstruct the message from the expected signed transfer.
/// # Errors
/// Rejects duplicate/unknown fields, coercion, excessive input, false scope and mismatched claims.
pub fn decode_recovery_state_installation_signature(
    bytes: &[u8],
    node: &str,
    state_digest: &str,
    message: &str,
) -> Result<Vec<u8>, BoundaryError> {
    if bytes.len() > 16 * 1024 {
        return Err(BoundaryError::BodyTooLarge { limit: 16 * 1024 });
    }
    let report: Report = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    let signature = report.installation_signature.as_bytes();
    if !report.installed
        || report.service_started
        || report.admission_ready
        || report.node_id != node
        || report.state_sha256 != state_digest
        || report.installation_message != message
        || report.scope.len() > 512
        || !(16..=144).contains(&signature.len())
        || !signature.len().is_multiple_of(2)
        || !signature
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(BoundaryError::DecodeMismatch);
    }
    signature
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_state_report_requires_exact_closed_expected_claims()
    -> Result<(), Box<dyn std::error::Error>> {
        let report = serde_json::json!({"installed": true, "service_started": false,
            "admission_ready": false, "node_id": "expected node", "state_sha256": "expected digest",
            "installation_message": "expected message", "installation_signature": "ab".repeat(8), "scope": "installation only"});
        let decode = |bytes: &[u8]| {
            decode_recovery_state_installation_signature(
                bytes,
                "expected node",
                "expected digest",
                "expected message",
            )
        };
        assert_eq!(decode(&serde_json::to_vec(&report)?)?, [171; 8]);
        for (field, value) in [
            ("node_id", serde_json::json!("other")),
            ("state_sha256", serde_json::json!("old")),
            ("installation_message", serde_json::json!("key-only")),
            ("admission_ready", serde_json::json!(true)),
            ("installed", serde_json::json!("true")),
            ("extra", serde_json::json!(true)),
            ("installation_signature", serde_json::json!("AB".repeat(8))),
            ("scope", serde_json::json!("x".repeat(513))),
        ] {
            let mut bad = report.clone();
            bad[field] = value;
            assert!(decode(&serde_json::to_vec(&bad)?).is_err(), "{field}");
        }
        assert!(
            decode(
                serde_json::to_string(&report)?
                    .replacen('{', "{\"installed\":true,", 1)
                    .as_bytes()
            )
            .is_err()
        );
        assert!(decode(&vec![b' '; 16 * 1024 + 1]).is_err());
        Ok(())
    }
}
