// SPDX-License-Identifier: GPL-2.0-only

use super::decode_recovery_installation_signature;
use serde_json::{Value, json};

#[test]
fn recovery_installation_signature_requires_exact_bounded_report_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let value = report();
    // Structural decoding is not cryptographic verification; the coordinator must verify DER.
    assert_eq!(
        decode_recovery_installation_signature(&serde_json::to_vec(&value)?)?,
        vec![0xab; 64]
    );
    for (field, replacement) in [
        ("installed", json!(false)),
        ("service_started", json!(true)),
        ("installed", json!("true")),
        ("sha256", Value::Null),
        ("installation_signature", json!("ab")),
        ("installation_signature", json!("AB".repeat(64))),
        ("installation_signature", json!("ab".repeat(73))),
        ("installation_signature", json!("a".repeat(127))),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        assert!(
            decode_recovery_installation_signature(&serde_json::to_vec(&changed)?).is_err(),
            "{field}"
        );
    }
    let mut extra = value.clone();
    extra["activate"] = json!(true);
    assert!(decode_recovery_installation_signature(&serde_json::to_vec(&extra)?).is_err());
    let encoded = serde_json::to_string(&value)?;
    let duplicate = encoded.replacen('{', "{\"installed\":true,", 1);
    assert!(decode_recovery_installation_signature(duplicate.as_bytes()).is_err());
    assert!(decode_recovery_installation_signature(&vec![b' '; 16 * 1024 + 1]).is_err());
    Ok(())
}

#[test]
fn recovery_installation_display_claims_are_not_signature_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut value = report();
    value["installation_message"] = json!("untrusted");
    value["sha256"] = json!("untrusted");
    value["verified_secret_generations"] = json!("untrusted");
    assert_eq!(
        decode_recovery_installation_signature(&serde_json::to_vec(&value)?)?,
        vec![0xab; 64]
    );
    Ok(())
}

fn report() -> Value {
    json!({
        "installed": true, "service_started": false, "scope": "Keys only",
        "node_certificate_generation": "1", "node_certificate_not_after_unix_seconds": "100",
        "sha256": "11".repeat(32), "verified_secret_generations": "2",
        "installation_message": "ab", "installation_signature": "ab".repeat(64),
    })
}
