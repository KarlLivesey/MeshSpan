// SPDX-License-Identifier: GPL-2.0-only

//! Bounded node restoration output; decoded claims still require independent verification.

use crate::BoundaryError;
use serde::Deserialize;

/// Parsed transport fields, never verification of the node signature or stored shards.
pub struct RecoveryRestorationAttestation {
    /// Closed binary signing message to decode against the independently trusted root.
    pub message: Vec<u8>,
    /// Bounded DER node signature over the exact message.
    pub signature: Vec<u8>,
    /// Untrusted displayed receipt count; must equal the signed message and observed stream.
    pub receipt_count: u64,
    /// Untrusted displayed byte sum; must equal the signed message and observed stream.
    pub encrypted_bytes: u64,
    /// Untrusted displayed stream digest; must equal signed and independently computed values.
    pub receipts_digest: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    restored: bool,
    service_started: bool,
    admission_ready: bool,
    receipt_count: String,
    encrypted_bytes: String,
    receipts_sha256: String,
    installation_message: String,
    installation_signature: String,
    scope: String,
}

/// Decodes original JSON without duplicate/unknown fields, coercion or unbounded allocation.
/// No displayed claim is authoritative until the coordinator checks the signed message/archive.
/// # Errors
/// Rejects oversized reports, unsuccessful or service-admitting claims and malformed fields.
pub fn decode_recovery_restoration_attestation(
    bytes: &[u8],
) -> Result<RecoveryRestorationAttestation, BoundaryError> {
    if bytes.len() > 16 * 1024 {
        return Err(BoundaryError::BodyTooLarge { limit: 16 * 1024 });
    }
    let report: Report = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    if !report.restored
        || report.service_started
        || report.admission_ready
        || report.scope.len() > 512
    {
        return Err(BoundaryError::DecodeMismatch);
    }
    Ok(RecoveryRestorationAttestation {
        message: hex(&report.installation_message, 1, 1024)?,
        signature: hex(&report.installation_signature, 8, 72)?,
        receipt_count: decimal(&report.receipt_count)?,
        encrypted_bytes: decimal(&report.encrypted_bytes)?,
        receipts_digest: hex(&report.receipts_sha256, 32, 32)?
            .try_into()
            .map_err(|_| BoundaryError::DecodeMismatch)?,
    })
}

fn decimal(value: &str) -> Result<u64, BoundaryError> {
    let decoded = value
        .parse::<u64>()
        .map_err(|_| BoundaryError::DecodeMismatch)?;
    if decoded.to_string() != value {
        return Err(BoundaryError::DecodeMismatch);
    }
    Ok(decoded)
}

fn hex(value: &str, minimum: usize, maximum: usize) -> Result<Vec<u8>, BoundaryError> {
    if !(minimum * 2..=maximum * 2).contains(&value.len())
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BoundaryError::DecodeMismatch);
    }
    value
        .as_bytes()
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

    fn report() -> serde_json::Value {
        serde_json::json!({
            "restored": true, "service_started": false, "admission_ready": false,
            "receipt_count": "1", "encrypted_bytes": "126",
            "receipts_sha256": "ab".repeat(32), "installation_message": "01",
            "installation_signature": "02".repeat(8), "scope": "evidence only"
        })
    }

    #[test]
    fn recovery_restoration_decodes_fields_without_claiming_verification()
    -> Result<(), Box<dyn std::error::Error>> {
        let parsed = decode_recovery_restoration_attestation(&serde_json::to_vec(&report())?)?;
        assert_eq!(parsed.message, [1]);
        assert_eq!(parsed.signature, [2; 8]);
        assert_eq!(parsed.receipt_count, 1);
        assert_eq!(parsed.encrypted_bytes, 126);
        assert_eq!(parsed.receipts_digest, [171; 32]);
        Ok(())
    }

    #[test]
    fn recovery_restoration_rejects_ambiguous_or_unbounded_reports()
    -> Result<(), Box<dyn std::error::Error>> {
        for (field, invalid) in [
            ("restored", serde_json::json!(false)),
            ("service_started", serde_json::json!(true)),
            ("admission_ready", serde_json::json!(true)),
            ("receipt_count", serde_json::json!(1)),
            ("receipt_count", serde_json::json!("01")),
            ("encrypted_bytes", serde_json::json!("18446744073709551616")),
            ("installation_message", serde_json::json!("AB")),
            ("installation_message", serde_json::json!("a")),
            ("installation_message", serde_json::json!("01".repeat(1025))),
            ("installation_signature", serde_json::json!("01".repeat(73))),
            ("installation_signature", serde_json::json!("01".repeat(7))),
            ("receipts_sha256", serde_json::json!("01".repeat(31))),
            ("scope", serde_json::json!("x".repeat(513))),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut candidate = report();
            candidate[field] = invalid;
            assert!(
                decode_recovery_restoration_attestation(&serde_json::to_vec(&candidate)?).is_err(),
                "{field}"
            );
        }
        let original = serde_json::to_string(&report())?;
        let duplicate = original.replacen('{', "{\"restored\":true,", 1);
        assert!(decode_recovery_restoration_attestation(duplicate.as_bytes()).is_err());
        assert!(matches!(
            decode_recovery_restoration_attestation(&vec![b' '; 16 * 1024 + 1]),
            Err(BoundaryError::BodyTooLarge { .. })
        ));
        Ok(())
    }
}
