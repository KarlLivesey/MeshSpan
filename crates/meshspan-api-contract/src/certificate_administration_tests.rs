// SPDX-License-Identifier: GPL-2.0-only

use crate::{BoundaryError, CertificateChallenge, decode_provision_certificate_request};

#[test]
fn provisioning_accepts_every_challenge_family_and_redacts_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    for challenge in [
        serde_json::json!({"kind": "http01"}),
        serde_json::json!({"kind": "dns01_manual"}),
        serde_json::json!({
            "kind": "dns01_rfc2136",
            "server": "192.0.2.10:53",
            "zone": "example.test",
            "key_name": "meshspan.example.test",
            "algorithm": "hmac_sha256",
            "secret": "0123456789abcdef"
        }),
        serde_json::json!({
            "kind": "dns01_cloudflare",
            "zone_id": "0123456789abcdef0123456789abcdef",
            "api_token": "0123456789abcdef"
        }),
        serde_json::json!({
            "kind": "dns01_webhook",
            "endpoint": "https://dns.example.test/meshspan",
            "bearer_token": "0123456789abcdef"
        }),
    ] {
        let value = request(&challenge);
        let decoded = decode_provision_certificate_request(&serde_json::to_vec(&value)?)?;
        if let CertificateChallenge::Dns01Cloudflare { api_token, .. } = decoded.challenge {
            assert_eq!(format!("{api_token:?}"), "ProtectedText([redacted])");
        }
    }
    Ok(())
}

#[test]
fn provisioning_rejects_unknown_fields_bad_secrets_and_ambiguous_name_order()
-> Result<(), Box<dyn std::error::Error>> {
    let mut unknown = request(&serde_json::json!({"kind": "http01"}));
    unknown["guess"] = serde_json::json!(true);
    assert!(decode_provision_certificate_request(&serde_json::to_vec(&unknown)?).is_err());

    let short_secret = request(&serde_json::json!({
        "kind": "dns01_cloudflare",
        "zone_id": "0123456789abcdef0123456789abcdef",
        "api_token": "short"
    }));
    assert!(matches!(
        decode_provision_certificate_request(&serde_json::to_vec(&short_secret)?),
        Err(BoundaryError::Invalid { .. })
    ));

    let mut reversed = request(&serde_json::json!({"kind": "http01"}));
    reversed["certificate_names"] = serde_json::json!(["www.example.test", "files.example.test"]);
    assert!(matches!(
        decode_provision_certificate_request(&serde_json::to_vec(&reversed)?),
        Err(BoundaryError::DecodeMismatch)
    ));
    Ok(())
}

fn request(challenge: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000001",
        "directory_url": "https://acme.example.test/directory",
        "certificate_names": ["files.example.test", "www.example.test"],
        "challenge": challenge
    })
}
