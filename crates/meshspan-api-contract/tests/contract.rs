// SPDX-License-Identifier: GPL-2.0-only

//! Cross-language public API contract fixtures and generation invariants.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "contract fixtures must stop at the first malformed checked-in vector"
)]

use meshspan_api_contract::{
    ApiError, ApiErrorCode, ApiKeyId, ApiKeyScope, AuthenticationMethodId, BoundaryError,
    CreateApiKeyResponse, CreateMeshSetupResponse, CreatePasskeyChallengeResponse,
    CreatePasskeyRegistrationChallengeResponse, CreatePasskeyRegistrationResponse,
    CreateRecoveryCodesResponse, CreateSessionResponse, CreateTotpRegistrationChallengeResponse,
    CreateTotpRegistrationResponse, DirectoryEntryKind, FileVersionId, GetObjectQuery,
    GetObjectResponse, ListDirectoryQuery, ListDirectoryResponse, NamespaceCommitId, NamespacePath,
    NullableField, ObjectId, ObjectMetadataResponse, ObjectRevisionId, OperationId,
    PasskeyAttestation, PasskeyChallengeId, PasskeyCredentialDescriptor,
    PasskeyCredentialParameter, PasskeyCredentialType, PasskeyResidentKey, PasskeyUserVerification,
    ReadFileQuery, RecoveryCode, RevokeAuthenticationMethodResponse, RevokeCurrentSessionResponse,
    SessionId, SetupState, SetupStatusResponse, TotpRegistrationAlgorithm,
    TotpRegistrationChallengeId, VolumeId, decode_create_api_key_request,
    decode_create_mesh_setup_request, decode_create_passkey_challenge_request,
    decode_create_passkey_registration_challenge_request,
    decode_create_passkey_registration_request, decode_create_recovery_codes_request,
    decode_create_session_request, decode_create_totp_registration_challenge_request,
    decode_create_totp_registration_request, decode_revoke_authentication_method_request,
    decode_revoke_current_session_request, decode_step_up_current_session_request,
    encode_api_error, encode_create_api_key_response, encode_create_mesh_setup_response,
    encode_create_passkey_challenge_response,
    encode_create_passkey_registration_challenge_response,
    encode_create_passkey_registration_response, encode_create_recovery_codes_response,
    encode_create_session_response, encode_create_totp_registration_challenge_response,
    encode_create_totp_registration_response, encode_get_object_response,
    encode_list_directory_response, encode_revoke_authentication_method_response,
    encode_revoke_current_session_response, encode_setup_status_response, generate_openapi,
    validate_create_mesh_setup_request_value, validate_create_passkey_challenge_request_value,
    validate_create_passkey_challenge_response_value,
    validate_create_passkey_registration_request_value, validate_create_session_request_value,
    validate_create_session_response_value, validate_get_object_query,
    validate_get_object_query_value, validate_list_directory_query,
    validate_list_directory_query_value, validate_read_file_query, validate_read_file_query_value,
    validate_setup_status_response_value, validate_step_up_current_session_request_value,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureDocument {
    license: String,
    cases: Vec<FixtureCase>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Direction {
    Request,
    Response,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    name: String,
    direction: Direction,
    accepted: bool,
    value: Value,
}

#[test]
fn shared_fixtures_match_rust_request_and_response_boundaries() {
    let fixture = fixture_document();
    assert_eq!(fixture.license, "GPL-2.0-only");

    for case in fixture.cases {
        let result = match case.direction {
            Direction::Request => validate_create_session_request_value(&case.value),
            Direction::Response => validate_create_session_response_value(&case.value),
        };
        assert_eq!(result.is_ok(), case.accepted, "fixture: {}", case.name);
    }
}

#[test]
fn request_decoder_preserves_missing_and_explicit_null() {
    let missing = decode_request(&json!({
        "operation_id": "018f1d20-7b4c-7a1e-9d22-39a1558b4c61",
        "authentication": {
            "method": "api_key",
            "secret": "meshspan_api_7hR9vQ2mK4xP8nT6wY3cF5aJ"
        },
        "remember": false
    }));
    let explicit_null = decode_request(&json!({
        "operation_id": "018f1d20-7b4c-7a1e-9d22-39a1558b4c61",
        "authentication": {
            "method": "api_key",
            "secret": "meshspan_api_7hR9vQ2mK4xP8nT6wY3cF5aJ"
        },
        "client_label": null,
        "remember": false
    }));

    assert_eq!(missing.client_label, NullableField::Missing);
    assert_eq!(explicit_null.client_label, NullableField::Null);
}

#[test]
fn accepted_response_passes_the_outgoing_encoder() {
    let value = json!({
        "operation_id": "018f1d20-7b4c-7a1e-9d22-39a1558b4c61",
        "session_id": "018f1d21-9319-7b98-8538-5af5b47bd0bc",
        "expires_at_epoch_micros": 1_800_000_000_000_000_i64,
        "assurance": "multi_factor"
    });
    let response = serde_json::from_value::<CreateSessionResponse>(value.clone())
        .expect("the checked fixture must deserialize");
    let encoded = encode_create_session_response(&response)
        .expect("the checked fixture must pass outgoing validation");
    let encoded_value =
        serde_json::from_slice::<Value>(&encoded).expect("the outgoing encoder must produce JSON");
    assert_eq!(encoded_value, value);
}

#[test]
fn public_error_passes_the_same_outgoing_contract_gate() {
    let error = ApiError {
        code: ApiErrorCode::InvalidRequest,
        message: "request does not satisfy the public contract".to_owned(),
        request_id: "00000000-0000-4000-8000-000000000001".to_owned(),
        operation_id: None,
        issues: vec![],
    };
    let encoded = encode_api_error(&error).expect("public error must validate");
    assert_eq!(
        serde_json::from_slice::<ApiError>(&encoded).expect("public error must decode"),
        error
    );
}

#[test]
fn decoder_rejects_malformed_and_oversized_bodies_before_domain_work() {
    assert!(decode_create_session_request(b"{").is_err());
    assert!(decode_create_session_request(&vec![b' '; 2_049]).is_err());
}

#[test]
fn step_up_contract_accepts_only_one_fresh_additional_factor() {
    let operation = "018f1d20-7b4c-7a1e-9d22-39a1558b4c61";
    for additional_factor in [
        json!({ "method": "totp", "code": "123456" }),
        json!({
            "method": "recovery_code",
            "code": format!("meshspan-recovery-v1.{}.{}", "1".repeat(32), "2".repeat(64))
        }),
    ] {
        let bytes = serde_json::to_vec(&json!({
            "operation_id": operation,
            "additional_factor": additional_factor
        }))
        .expect("step-up fixture must encode");
        assert!(decode_step_up_current_session_request(&bytes).is_ok());
    }
    for rejected in [
        json!({ "operation_id": operation }),
        json!({
            "operation_id": operation,
            "additional_factor": { "method": "totp", "code": "123456" },
            "authentication": { "method": "api_key", "secret": "must-not-be-accepted" }
        }),
        json!({
            "operation_id": operation,
            "additional_factor": { "method": "api_key", "secret": "must-not-be-accepted" }
        }),
    ] {
        assert!(validate_step_up_current_session_request_value(&rejected).is_err());
    }
    assert!(decode_step_up_current_session_request(&vec![b' '; 513]).is_err());

    let document = generate_openapi().expect("step-up contract must generate");
    assert_eq!(
        document.value()["paths"]["/sessions/current/step-ups"]["post"]["x-meshspan-access"],
        "authenticated-csrf"
    );
}

#[test]
fn passkey_challenge_contract_is_exact_bounded_and_validated_both_ways() {
    let operation = "018f1d20-7b4c-7a1e-9d22-39a1558b4c61";
    let request_bytes = serde_json::to_vec(&json!({ "operation_id": operation }))
        .expect("request fixture must encode");
    let request = decode_create_passkey_challenge_request(&request_bytes)
        .expect("exact challenge request must decode");
    assert_eq!(request.operation_id.as_str(), operation);
    let unknown = json!({
        "operation_id": operation,
        "user_name": "must-not-enable-account-enumeration"
    });
    let Err(BoundaryError::Invalid { issues }) =
        validate_create_passkey_challenge_request_value(&unknown)
    else {
        panic!("unknown field must be a structural request failure");
    };
    assert_eq!(issues[0].constraint, "additional_property");
    assert!(
        decode_create_passkey_challenge_request(
            &serde_json::to_vec(&unknown).expect("rejection fixture must encode")
        )
        .is_err()
    );
    assert!(decode_create_passkey_challenge_request(&vec![b' '; 257]).is_err());

    let response = CreatePasskeyChallengeResponse {
        operation_id: serde_json::from_value(json!(operation))
            .expect("operation fixture must be valid"),
        challenge_id: PasskeyChallengeId::from_uuid_bytes(versioned(3))
            .expect("challenge fixture must be valid"),
        challenge: "A".repeat(43),
        relying_party_id: "storage.example.test".to_owned(),
        timeout_milliseconds: 120_000,
        user_verification: PasskeyUserVerification::Required,
    };
    let encoded = encode_create_passkey_challenge_response(&response)
        .expect("valid challenge response must encode");
    let value = serde_json::from_slice::<Value>(&encoded).expect("response must be JSON");
    assert_eq!(value["challenge"], "A".repeat(43));

    let mut malformed = value;
    malformed["challenge"] = json!("contains padding=");
    assert!(validate_create_passkey_challenge_response_value(&malformed).is_err());
}

#[test]
fn passkey_registration_contract_is_authenticated_bounded_and_validated_both_ways() {
    let operation = "018f1d20-7b4c-7a1e-9d22-39a1558b4c61";
    let challenge_request = serde_json::to_vec(&json!({ "operation_id": operation }))
        .expect("challenge request must encode");
    assert!(decode_create_passkey_registration_challenge_request(&challenge_request).is_ok());
    let challenge_response = CreatePasskeyRegistrationChallengeResponse {
        operation_id: serde_json::from_value(json!(operation))
            .expect("operation fixture must be valid"),
        challenge_id: PasskeyChallengeId::from_uuid_bytes(versioned(8))
            .expect("challenge fixture must be valid"),
        challenge: "A".repeat(43),
        relying_party_id: "storage.example.test".to_owned(),
        relying_party_name: "MeshSpan".to_owned(),
        user_id: "A".repeat(22),
        user_name: "administrator".to_owned(),
        user_display_name: "Administrator".to_owned(),
        timeout_milliseconds: 120_000,
        user_verification: PasskeyUserVerification::Required,
        resident_key: PasskeyResidentKey::Required,
        attestation: PasskeyAttestation::None,
        public_key_parameters: vec![PasskeyCredentialParameter {
            credential_type: PasskeyCredentialType::PublicKey,
            algorithm: -7,
        }],
        exclude_credentials: vec![PasskeyCredentialDescriptor {
            credential_type: PasskeyCredentialType::PublicKey,
            id: "Y3JlZGVudGlhbA".to_owned(),
        }],
    };
    assert!(encode_create_passkey_registration_challenge_response(&challenge_response).is_ok());

    let completion = json!({
        "operation_id": operation,
        "challenge_id": "018f1d20-7b4c-7a1e-9d22-39a1558b4c62",
        "label": "Laptop passkey",
        "credential_id": "Y3JlZGVudGlhbA",
        "client_data_json": "e30",
        "attestation_object": "oA",
        "transports": ["internal", "hybrid"]
    });
    let decoded = decode_create_passkey_registration_request(
        &serde_json::to_vec(&completion).expect("completion fixture must encode"),
    )
    .expect("completion fixture must decode");
    assert_eq!(decoded.label.as_str(), "Laptop passkey");
    assert!(decode_create_passkey_registration_request(&vec![b'A'; 30_001]).is_err());
    let mut duplicate_shape = completion;
    duplicate_shape["unknown"] = json!(true);
    assert!(validate_create_passkey_registration_request_value(&duplicate_shape).is_err());

    let response = CreatePasskeyRegistrationResponse {
        operation_id: serde_json::from_value(json!(operation))
            .expect("operation fixture must be valid"),
        method_id: AuthenticationMethodId::from_uuid_bytes(versioned(9))
            .expect("method fixture must be valid"),
        created_at_epoch_micros: 1_800_000_000_000_000,
    };
    assert!(encode_create_passkey_registration_response(&response).is_ok());

    let document = generate_openapi().expect("contract must generate");
    let challenge_path = &document.value()["paths"]["/users/current/authentication-methods/passkeys/registration-challenges"]
        ["post"];
    assert_eq!(challenge_path["x-meshspan-access"], "authenticated-csrf");
    let completion_path =
        &document.value()["paths"]["/users/current/authentication-methods/passkeys"]["post"];
    assert_eq!(completion_path["operationId"], "createCurrentUserPasskey");
    assert_eq!(completion_path["x-meshspan-access"], "authenticated-csrf");
}

#[test]
fn totp_registration_contract_is_secret_safe_exact_and_validated_both_ways() {
    let operation = "018f1d20-7b4c-7a1e-9d22-39a1558b4c61";
    let challenge_request = json!({
        "operation_id": operation,
        "label": "Primary authenticator"
    });
    let decoded = decode_create_totp_registration_challenge_request(
        &serde_json::to_vec(&challenge_request).expect("challenge request must encode"),
    )
    .expect("exact challenge request must decode");
    assert_eq!(decoded.label.as_str(), "Primary authenticator");

    let mut unknown = challenge_request;
    unknown["issuer"] = json!("client must not choose security parameters");
    assert!(
        decode_create_totp_registration_challenge_request(
            &serde_json::to_vec(&unknown).expect("rejection fixture must encode")
        )
        .is_err()
    );
    assert!(decode_create_totp_registration_challenge_request(&vec![b' '; 513]).is_err());

    let challenge_id = TotpRegistrationChallengeId::from_uuid_bytes(versioned(15))
        .expect("challenge fixture must be valid");
    let challenge_response = CreateTotpRegistrationChallengeResponse {
        operation_id: serde_json::from_value(json!(operation))
            .expect("operation fixture must be valid"),
        challenge_id: challenge_id.clone(),
        secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".to_owned(),
        provisioning_uri: concat!(
            "otpauth://totp/MeshSpan%3Aadministrator?",
            "secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&",
            "issuer=MeshSpan&algorithm=SHA1&digits=6&period=30"
        )
        .to_owned(),
        algorithm: TotpRegistrationAlgorithm::Sha1,
        digits: 6,
        period_seconds: 30,
        expires_at_epoch_micros: 1_800_000_000_000_000,
    };
    let encoded = encode_create_totp_registration_challenge_response(&challenge_response)
        .expect("valid secret-bearing challenge response must encode");
    let encoded_value = serde_json::from_slice::<Value>(&encoded).expect("response must be JSON");
    assert_eq!(encoded_value["secret"], challenge_response.secret);

    let completion = json!({
        "operation_id": "018f1d20-7b4c-7a1e-9d22-39a1558b4c63",
        "challenge_id": challenge_id.as_str(),
        "code": "012345"
    });
    let confirmation = decode_create_totp_registration_request(
        &serde_json::to_vec(&completion).expect("confirmation fixture must encode"),
    )
    .expect("exact confirmation must decode");
    assert_eq!(confirmation.code, "012345");
    for malformed in ["12345", "1234567", "12a456"] {
        let mut invalid = completion.clone();
        invalid["code"] = json!(malformed);
        assert!(
            decode_create_totp_registration_request(
                &serde_json::to_vec(&invalid).expect("rejection fixture must encode")
            )
            .is_err()
        );
    }

    let response = CreateTotpRegistrationResponse {
        operation_id: confirmation.operation_id,
        method_id: AuthenticationMethodId::from_uuid_bytes(versioned(16))
            .expect("method fixture must be valid"),
        created_at_epoch_micros: 1_800_000_000_000_000,
    };
    encode_create_totp_registration_response(&response)
        .expect("committed registration response must encode");

    let document = generate_openapi().expect("contract must generate");
    let challenge_path = &document.value()["paths"]["/users/current/authentication-methods/totp/registration-challenges"]
        ["post"];
    assert_eq!(
        challenge_path["operationId"],
        "createCurrentUserTotpRegistrationChallenge"
    );
    assert_eq!(challenge_path["x-meshspan-access"], "authenticated-csrf");
    let completion_path =
        &document.value()["paths"]["/users/current/authentication-methods/totp"]["post"];
    assert_eq!(completion_path["operationId"], "createCurrentUserTotp");
    assert_eq!(completion_path["x-meshspan-access"], "authenticated-csrf");
}

#[test]
fn api_key_issuance_preserves_expiry_intent_and_validates_secret_output() {
    let operation = "018f1d20-7b4c-7a1e-9d22-39a1558b4c61";
    let base = json!({
        "operation_id": operation,
        "label": "Laptop automation",
        "scopes": ["https_session", "headless_api"]
    });
    let missing = decode_create_api_key_request(
        &serde_json::to_vec(&base).expect("request fixture must encode"),
    )
    .expect("missing-expiry request must decode");
    assert_eq!(missing.expires_at_epoch_micros, NullableField::Missing);
    let mut null = base.clone();
    null["expires_at_epoch_micros"] = Value::Null;
    let null = decode_create_api_key_request(
        &serde_json::to_vec(&null).expect("null fixture must encode"),
    )
    .expect("explicit-null request must decode");
    assert_eq!(null.expires_at_epoch_micros, NullableField::Null);
    let mut explicit = base;
    explicit["expires_at_epoch_micros"] = json!(1_900_000_000_000_000_i64);
    let explicit = decode_create_api_key_request(
        &serde_json::to_vec(&explicit).expect("expiry fixture must encode"),
    )
    .expect("explicit-expiry request must decode");
    assert!(matches!(
        explicit.expires_at_epoch_micros,
        NullableField::Value(_)
    ));

    let response = CreateApiKeyResponse {
        operation_id: serde_json::from_value(json!(operation))
            .expect("operation fixture must be valid"),
        method_id: AuthenticationMethodId::from_uuid_bytes(versioned(12))
            .expect("method fixture must be valid"),
        key_id: ApiKeyId::from_uuid_bytes(versioned(13)).expect("key fixture must be valid"),
        secret: concat!(
            "meshspan-key-v1.",
            "0d0d0d0d0d0d4d0d8d0d0d0d0d0d0d0d.",
            "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"
        )
        .to_owned(),
        scopes: vec![ApiKeyScope::HttpsSession, ApiKeyScope::HeadlessApi],
        created_at_epoch_micros: 1_800_000_000_000_000,
        valid_from_epoch_micros: 1_800_000_000_000_000,
        expires_at_epoch_micros: Some(1_900_000_000_000_000),
    };
    encode_create_api_key_response(&response).expect("valid API-key response must encode");
    let document = generate_openapi().expect("contract must generate");
    let path = &document.value()["paths"]["/users/current/authentication-methods/api-keys"]["post"];
    assert_eq!(path["operationId"], "createCurrentUserApiKey");
    assert_eq!(path["x-meshspan-access"], "authenticated-csrf");
}

#[test]
fn recovery_code_issuance_is_fixed_bounded_secret_safe_and_validated_both_ways() {
    let operation = "018f1d20-7b4c-7a1e-9d22-39a1558b4c61";
    let request = serde_json::to_vec(&json!({
        "operation_id": operation,
        "label": "Emergency recovery"
    }))
    .expect("recovery-code request must encode");
    let decoded = decode_create_recovery_codes_request(&request)
        .expect("valid recovery-code request must decode");
    assert_eq!(decoded.label.as_str(), "Emergency recovery");
    assert!(
        decode_create_recovery_codes_request(
            &serde_json::to_vec(&json!({
                "operation_id": operation,
                "label": "Emergency recovery",
                "count": 1
            }))
            .expect("unknown-field fixture must encode")
        )
        .is_err()
    );
    assert!(decode_create_recovery_codes_request(&vec![b' '; 1_025]).is_err());

    let codes = (1..=10)
        .map(|sequence| {
            RecoveryCode::from_canonical(format!(
                "meshspan-recovery-v1.{sequence:032x}.{}",
                "a".repeat(64)
            ))
        })
        .collect();
    let response = CreateRecoveryCodesResponse {
        operation_id: serde_json::from_value(json!(operation))
            .expect("operation fixture must be valid"),
        method_id: AuthenticationMethodId::from_uuid_bytes(versioned(19))
            .expect("method fixture must be valid"),
        codes,
        created_at_epoch_micros: 100,
    };
    let encoded = encode_create_recovery_codes_response(&response)
        .expect("valid recovery-code response must encode");
    let value = serde_json::from_slice::<Value>(&encoded).expect("response must be JSON");
    assert_eq!(value["codes"].as_array().map(Vec::len), Some(10));

    let invalid = CreateRecoveryCodesResponse {
        codes: vec![RecoveryCode::from_canonical("not-a-code".to_owned())],
        ..response
    };
    assert!(encode_create_recovery_codes_response(&invalid).is_err());
    let document = generate_openapi().expect("OpenAPI generation must work");
    let path =
        &document.value()["paths"]["/users/current/authentication-methods/recovery-codes"]["post"];
    assert_eq!(path["operationId"], "createCurrentUserRecoveryCodes");
    assert_eq!(path["x-meshspan-access"], "authenticated-csrf");
}

#[test]
fn authentication_method_revocation_is_bounded_owned_and_generated_once() {
    let operation = "018f1d20-7b4c-7a1e-9d22-39a1558b4c61";
    let method = AuthenticationMethodId::from_uuid_bytes(versioned(14))
        .expect("method fixture must be valid");
    let request = decode_revoke_authentication_method_request(
        &serde_json::to_vec(&json!({
            "operation_id": operation,
            "reason": "Rotating the automation credential"
        }))
        .expect("request fixture must encode"),
    )
    .expect("exact revocation request must decode");
    assert_eq!(
        request.reason.as_str(),
        "Rotating the automation credential"
    );
    for invalid in [" leading", "trailing ", "contains\ncontrol"] {
        assert!(
            decode_revoke_authentication_method_request(
                &serde_json::to_vec(&json!({
                    "operation_id": operation,
                    "reason": invalid
                }))
                .expect("rejection fixture must encode")
            )
            .is_err()
        );
    }
    let response = RevokeAuthenticationMethodResponse {
        operation_id: request.operation_id,
        method_id: method,
        revoked_at_epoch_micros: 1_800_000_000_000_000,
    };
    assert!(encode_revoke_authentication_method_response(&response).is_ok());

    let document = generate_openapi().expect("contract must generate");
    let path = &document.value()["paths"]["/users/current/authentication-methods/{method_id}/revocations"]
        ["post"];
    assert_eq!(path["operationId"], "revokeCurrentUserAuthenticationMethod");
    assert_eq!(path["x-meshspan-access"], "authenticated-csrf");
    assert_eq!(path["parameters"][0]["name"], "method_id");
}

#[test]
fn current_session_revocation_is_exact_bounded_and_validated_both_ways() {
    let operation = "018f1d20-7b4c-7a1e-9d22-39a1558b4c61";
    let request = decode_revoke_current_session_request(
        &serde_json::to_vec(&json!({ "operation_id": operation }))
            .expect("request fixture must encode"),
    )
    .expect("exact revocation request must decode");
    assert_eq!(request.operation_id.as_str(), operation);
    assert!(
        decode_revoke_current_session_request(
            &serde_json::to_vec(&json!({
                "operation_id": operation,
                "unexpected": true
            }))
            .expect("rejection fixture must encode")
        )
        .is_err()
    );
    let response = RevokeCurrentSessionResponse {
        operation_id: serde_json::from_value(json!(operation))
            .expect("operation fixture must be valid"),
        session_id: SessionId::from_uuid_bytes(versioned(2))
            .expect("session fixture must be valid"),
        revoked_at_epoch_micros: 1_800_000_000_000_000,
    };
    assert!(encode_revoke_current_session_response(&response).is_ok());
}

#[test]
fn anonymous_setup_status_has_only_the_closed_lifecycle_state() {
    let encoded = encode_setup_status_response(&SetupStatusResponse {
        state: SetupState::ClaimRequired,
    })
    .expect("setup state must encode");
    assert_eq!(
        serde_json::from_slice::<Value>(&encoded).expect("setup response must be JSON"),
        json!({ "state": "claim_required" })
    );
    assert!(
        validate_setup_status_response_value(&json!({
            "state": "claim_required",
            "claim_id": "must-not-leak"
        }))
        .is_err()
    );
}

#[test]
fn first_mesh_setup_is_exact_bounded_and_keeps_claim_out_of_debug_boundaries() {
    let operation = "00000000-0000-4000-8000-000000000001";
    let claim = format!("meshspan-claim-v1.{}.{}", "1".repeat(32), "2".repeat(64));
    let request = json!({
        "operation_id": operation,
        "claim": claim,
        "mesh_name": "Home storage",
        "administrator_name": "Administrator",
        "host_name": "Hall cupboard",
        "node_name": "Storage node"
    });
    let request_bytes = serde_json::to_vec(&request).expect("setup request must encode");
    let decoded =
        decode_create_mesh_setup_request(&request_bytes).expect("valid setup request must decode");
    assert_eq!(decoded.mesh_name.as_str(), "Home storage");
    assert!(
        decoded
            .claim
            .expose_for_verification()
            .starts_with("meshspan-claim-v1.")
    );

    let mut leaked = request.clone();
    leaked["unexpected"] = json!(true);
    assert!(validate_create_mesh_setup_request_value(&leaked).is_err());
    let mut uppercase_claim = request;
    uppercase_claim["claim"] = json!(format!(
        "meshspan-claim-v1.{}.{}",
        "A".repeat(32),
        "2".repeat(64)
    ));
    assert!(validate_create_mesh_setup_request_value(&uppercase_claim).is_err());

    let response = CreateMeshSetupResponse {
        operation_id: serde_json::from_value::<OperationId>(json!(operation))
            .expect("operation identifier must decode"),
        mesh_id: "00000000-0000-4000-8000-000000000002".to_owned(),
        node_id: "00000000-0000-4000-8000-000000000003".to_owned(),
        api_key: format!("meshspan-key-v1.{}.{}", "4".repeat(32), "5".repeat(64)),
    };
    let encoded = encode_create_mesh_setup_response(&response).expect("response must validate");
    assert_eq!(
        serde_json::from_slice::<Value>(&encoded).expect("setup response must decode")["api_key"],
        json!(response.api_key)
    );
    assert!(decode_create_mesh_setup_request(&vec![b' '; 2_049]).is_err());
}

#[test]
fn openapi_document_is_31_licensed_bounded_and_deterministic() {
    let first = generate_openapi().expect("the Rust contract must generate");
    let second = generate_openapi().expect("repeated generation must succeed");

    assert_eq!(first.value()["openapi"], "3.1.0");
    assert_eq!(
        first.value()["info"]["license"]["identifier"],
        "GPL-2.0-only"
    );
    assert_eq!(first.value(), second.value());
    assert_eq!(first.digest(), second.digest());
    assert!(first.digest().starts_with("sha256:"));
    assert_eq!(first.digest().len(), 71);
    assert_eq!(
        first.value()["components"]["schemas"]["CreateSessionRequest"]["additionalProperties"],
        false
    );
    let session_headers =
        &first.value()["paths"]["/sessions"]["post"]["responses"]["201"]["headers"];
    assert_eq!(session_headers["Set-Cookie"]["required"], true);
    assert_eq!(
        session_headers["MeshSpan-CSRF-Token"]["schema"]["pattern"],
        r"^meshspan-csrf-v1\.[0-9a-f]{32}\.[0-9a-f]{64}$"
    );
    let step_up_headers = &first.value()["paths"]["/sessions/current/step-ups"]["post"]["responses"]
        ["201"]["headers"];
    assert_eq!(step_up_headers, session_headers);
    let challenge = &first.value()["paths"]["/sessions/passkey/challenges"]["post"];
    assert_eq!(challenge["operationId"], "createPasskeyChallenge");
    assert_eq!(challenge["x-meshspan-access"], "anonymous");
    assert_eq!(
        challenge["responses"]["201"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/CreatePasskeyChallengeResponse"
    );
}

#[test]
fn directory_listing_is_bounded_complete_and_ready_to_continue() {
    let query: ListDirectoryQuery = serde_json::from_value(json!({
        "path": "reports/2026",
        "cursor": "v1.opaque-continuation",
        "limit": 80
    }))
    .expect("directory query fixture must decode");
    validate_list_directory_query(&query).expect("canonical relative path must validate");
    assert!(
        validate_list_directory_query_value(&json!({
            "path": "reports",
            "limit": 80,
            "unexpected": true
        }))
        .is_err()
    );
    let traversal: ListDirectoryQuery =
        serde_json::from_value(json!({ "path": "reports/../private" }))
            .expect("structural query decoding is separate from path semantics");
    assert!(validate_list_directory_query(&traversal).is_err());

    let response = ListDirectoryResponse {
        volume_id: VolumeId::from_uuid_bytes(versioned(1)).expect("volume id must be valid"),
        path: Some(
            serde_json::from_value::<NamespacePath>(json!("reports/2026"))
                .expect("path fixture must decode"),
        ),
        namespace_commit_id: NamespaceCommitId::from_uuid_bytes(versioned(2))
            .expect("commit id must be valid"),
        directory_object_id: ObjectId::from_uuid_bytes(versioned(3))
            .expect("directory id must be valid"),
        directory_object_revision_id: ObjectRevisionId::from_uuid_bytes(versioned(4))
            .expect("directory revision must be valid"),
        entries: vec![ObjectMetadataResponse {
            name: "accounts.csv".to_owned(),
            object_id: ObjectId::from_uuid_bytes(versioned(5)).expect("object id must be valid"),
            object_revision_id: ObjectRevisionId::from_uuid_bytes(versioned(6))
                .expect("object revision must be valid"),
            entry_generation: 9,
            kind: DirectoryEntryKind::File,
            file_version_id: Some(
                FileVersionId::from_uuid_bytes(versioned(7)).expect("version id must be valid"),
            ),
            logical_length: Some(1_024),
        }],
        next_page_url: Some(
            "/api/latest/volumes/01010101-0101-4101-8101-010101010101/directory-entries?path=reports%2F2026&limit=80&cursor=v1.next"
                .to_owned(),
        ),
    };
    let encoded = encode_list_directory_response(&response)
        .expect("complete file metadata and continuation must validate");
    let value: Value = serde_json::from_slice(&encoded).expect("response must be JSON");
    assert_eq!(value["entries"][0]["logical_length"], 1_024);
    assert!(value["next_page_url"].as_str().is_some());

    let invalid_directory = ListDirectoryResponse {
        entries: vec![ObjectMetadataResponse {
            name: "invalid-directory".to_owned(),
            object_id: ObjectId::from_uuid_bytes(versioned(8)).expect("object id must be valid"),
            object_revision_id: ObjectRevisionId::from_uuid_bytes(versioned(9))
                .expect("object revision must be valid"),
            entry_generation: 1,
            kind: DirectoryEntryKind::Directory,
            file_version_id: None,
            logical_length: Some(0),
        }],
        ..response
    };
    assert!(encode_list_directory_response(&invalid_directory).is_err());

    let document = generate_openapi().expect("directory contract must generate");
    let operation = &document.value()["paths"]["/volumes/{volume_id}/directory-entries"]["get"];
    assert_eq!(operation["operationId"], "listDirectory");
    assert_eq!(operation["x-meshspan-access"], "authenticated");
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/ListDirectoryResponse"
    );
}

#[test]
fn object_metadata_contract_is_path_bound_and_internally_consistent() {
    let query: GetObjectQuery = serde_json::from_value(json!({
        "path": "reports/accounts.csv"
    }))
    .expect("object query fixture must decode");
    validate_get_object_query(&query).expect("canonical object path must validate");
    assert!(
        validate_get_object_query_value(&json!({
            "path": "reports/accounts.csv",
            "unexpected": true
        }))
        .is_err()
    );
    let traversal: GetObjectQuery = serde_json::from_value(json!({ "path": "reports/../private" }))
        .expect("structural decoding is separate from path semantics");
    assert!(validate_get_object_query(&traversal).is_err());

    let response = GetObjectResponse {
        volume_id: VolumeId::from_uuid_bytes(versioned(1)).expect("volume id must be valid"),
        path: query.path,
        namespace_commit_id: NamespaceCommitId::from_uuid_bytes(versioned(2))
            .expect("commit id must be valid"),
        object: ObjectMetadataResponse {
            name: "accounts.csv".to_owned(),
            object_id: ObjectId::from_uuid_bytes(versioned(3)).expect("object id must be valid"),
            object_revision_id: ObjectRevisionId::from_uuid_bytes(versioned(4))
                .expect("object revision must be valid"),
            entry_generation: 1,
            kind: DirectoryEntryKind::File,
            file_version_id: Some(
                FileVersionId::from_uuid_bytes(versioned(5)).expect("file version must be valid"),
            ),
            logical_length: Some(1_024),
        },
    };
    assert!(encode_get_object_response(&response).is_ok());
    let inconsistent = GetObjectResponse {
        object: ObjectMetadataResponse {
            kind: DirectoryEntryKind::Directory,
            file_version_id: None,
            logical_length: Some(0),
            ..response.object.clone()
        },
        ..response
    };
    assert!(encode_get_object_response(&inconsistent).is_err());

    let document = generate_openapi().expect("object metadata contract must generate");
    let operation = &document.value()["paths"]["/volumes/{volume_id}/objects"]["get"];
    assert_eq!(operation["operationId"], "getObject");
    assert_eq!(operation["x-meshspan-access"], "authenticated");
}

#[test]
fn file_read_contract_is_bounded_binary_and_safe_for_generated_clients() {
    let query: ReadFileQuery = serde_json::from_value(json!({
        "path": "reports/accounts.csv",
        "offset": 1024,
        "length": 65536
    }))
    .expect("file read query fixture must decode");
    validate_read_file_query(&query).expect("bounded canonical file range must validate");
    assert!(
        validate_read_file_query_value(&json!({
            "path": "reports/accounts.csv",
            "offset": 0,
            "length": 8_388_609
        }))
        .is_err()
    );
    assert!(
        validate_read_file_query_value(&json!({
            "path": "reports/accounts.csv",
            "unexpected": true
        }))
        .is_err()
    );
    let traversal: ReadFileQuery = serde_json::from_value(json!({
        "path": "reports/../private",
        "length": 1
    }))
    .expect("structural decoding is separate from path semantics");
    assert!(validate_read_file_query(&traversal).is_err());

    let document = generate_openapi().expect("file read contract must generate");
    let operation = &document.value()["paths"]["/volumes/{volume_id}/file-content"]["get"];
    assert_eq!(operation["operationId"], "readFile");
    assert_eq!(operation["x-meshspan-access"], "authenticated");
    assert_eq!(
        operation["responses"]["200"]["content"]["application/octet-stream"]["schema"]["format"],
        "binary"
    );
    assert_eq!(
        operation["responses"]["200"]["headers"]["MeshSpan-File-Version"]["required"],
        true
    );
}

#[test]
fn native_upload_contract_is_resumable_bounded_and_explicitly_committed() {
    let document = generate_openapi().expect("native upload contract must generate");
    let paths = &document.value()["paths"];
    assert_eq!(
        paths["/volumes/{volume_id}/uploads"]["post"]["operationId"],
        "beginUpload"
    );
    assert_eq!(
        paths["/uploads/{upload_id}"]["get"]["operationId"],
        "getUpload"
    );
    assert_eq!(
        paths["/uploads/{upload_id}/ranges"]["get"]["operationId"],
        "listUploadRanges"
    );
    let write = &paths["/uploads/{upload_id}/ranges/{offset}"]["put"];
    assert_eq!(write["operationId"], "writeUploadRange");
    assert_eq!(
        write["requestBody"]["content"]["application/octet-stream"]["schema"]["maxLength"],
        8_388_608
    );
    let headers = write["parameters"]
        .as_array()
        .expect("upload write parameters must be an array");
    for name in [
        "MeshSpan-Operation-Id",
        "MeshSpan-Stage-Fence",
        "MeshSpan-Content-BLAKE3",
    ] {
        assert!(
            headers
                .iter()
                .any(|parameter| parameter["name"] == name && parameter["required"] == true),
            "missing required {name}"
        );
    }
    assert_eq!(
        paths["/uploads/{upload_id}/commits"]["post"]["operationId"],
        "commitUpload"
    );
    assert_eq!(
        paths["/uploads/{upload_id}/aborts"]["post"]["operationId"],
        "abortUpload"
    );
}

#[test]
fn every_documented_operation_declares_access_and_an_operation_id() {
    let document = generate_openapi().expect("the Rust contract must generate");
    let paths = document.value()["paths"]
        .as_object()
        .expect("OpenAPI paths must be an object");

    for (route, path_item) in paths {
        let operations = path_item
            .as_object()
            .expect("each OpenAPI path item must be an object");
        for (method, operation) in operations {
            assert!(operation["operationId"].is_string(), "{method} {route}");
            assert!(
                operation["x-meshspan-access"].is_string(),
                "{method} {route}"
            );
        }
    }
}

fn fixture_document() -> FixtureDocument {
    serde_json::from_str(include_str!(
        "../../../contracts/fixtures/create-session.json"
    ))
    .expect("checked-in contract fixtures must be valid JSON")
}

fn decode_request(value: &Value) -> meshspan_api_contract::CreateSessionRequest {
    let bytes = serde_json::to_vec(&value).expect("fixture must serialize");
    decode_create_session_request(&bytes).expect("fixture must decode")
}

fn versioned(value: u8) -> [u8; 16] {
    let mut bytes = [value; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
