// SPDX-License-Identifier: GPL-2.0-only

use crate::{
    BoundaryError, CertificateChallenge, CertificateGeneration, ExternalCertificatePublicationId,
    OperationId, PublicCertificateId, PublishExternalCertificateResponse,
    decode_provision_certificate_request, decode_publish_external_certificate_request,
    encode_publish_external_certificate_response,
};

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

#[test]
fn external_publication_is_bounded_canonical_and_redacts_its_key()
-> Result<(), Box<dyn std::error::Error>> {
    let value = external_publication_request();
    let decoded = decode_publish_external_certificate_request(&serde_json::to_vec(&value)?)?;

    assert_eq!(decoded.generation.value(), Some(7));
    assert_eq!(
        format!("{:?}", decoded.private_key_pkcs8_pem),
        "ExternalCertificatePrivateKeyPem([redacted])"
    );

    let mut unknown = value.clone();
    unknown["local_path"] = serde_json::json!("/private/key.pem");
    assert!(decode_publish_external_certificate_request(&serde_json::to_vec(&unknown)?).is_err());

    let mut unsafe_generation = value;
    unsafe_generation["generation"] = serde_json::json!("07");
    assert!(matches!(
        decode_publish_external_certificate_request(&serde_json::to_vec(&unsafe_generation)?),
        Err(BoundaryError::Invalid { .. })
    ));
    Ok(())
}

#[test]
fn external_publication_response_is_secret_free_and_validated()
-> Result<(), Box<dyn std::error::Error>> {
    let response = PublishExternalCertificateResponse {
        operation_id: OperationId::from_uuid_bytes([
            1, 1, 1, 1, 1, 1, 0x41, 1, 0x81, 1, 1, 1, 1, 1, 1, 1,
        ])
        .ok_or("operation")?,
        publication_id: ExternalCertificatePublicationId::from_uuid_bytes([
            2, 2, 2, 2, 2, 2, 0x42, 2, 0x82, 2, 2, 2, 2, 2, 2, 2,
        ])
        .ok_or("publication")?,
        certificate_id: PublicCertificateId::from_uuid_bytes([
            3, 3, 3, 3, 3, 3, 0x43, 3, 0x83, 3, 3, 3, 3, 3, 3, 3,
        ])
        .ok_or("certificate")?,
        generation: CertificateGeneration::from_value(7).ok_or("generation")?,
        certificate_names: vec!["files.example.test".to_owned()],
        public_key_fingerprint: "a".repeat(64),
        not_before_epoch_micros: 1,
        not_after_epoch_micros: 2,
        revision: 3,
    };
    let encoded = encode_publish_external_certificate_response(&response)?;
    let text = std::str::from_utf8(&encoded)?;

    assert!(!text.contains("PRIVATE KEY"));
    assert!(text.contains("public_key_fingerprint"));
    Ok(())
}

fn external_publication_request() -> serde_json::Value {
    serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000001",
        "generation": "7",
        "certificate_names": ["files.example.test", "www.example.test"],
        "certificate_chain_pem": concat!(
            "-----BEGIN CERTIFICATE-----\n",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
            "-----END CERTIFICATE-----\n"
        ),
        "private_key_pkcs8_pem": concat!(
            "-----BEGIN PRIVATE KEY-----\n",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
            "-----END PRIVATE KEY-----\n"
        )
    })
}
