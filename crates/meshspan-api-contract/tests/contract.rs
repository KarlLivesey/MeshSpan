// SPDX-License-Identifier: GPL-2.0-only

//! Cross-language public API contract fixtures and generation invariants.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "contract fixtures must stop at the first malformed checked-in vector"
)]

use meshspan_api_contract::{
    ApiError, ApiErrorCode, CreateMeshSetupResponse, CreateSessionResponse, NullableField,
    OperationId, RevokeCurrentSessionResponse, SessionId, SetupState, SetupStatusResponse,
    decode_create_mesh_setup_request, decode_create_session_request,
    decode_revoke_current_session_request, encode_api_error, encode_create_mesh_setup_response,
    encode_create_session_response, encode_revoke_current_session_response,
    encode_setup_status_response, generate_openapi, validate_create_mesh_setup_request_value,
    validate_create_session_request_value, validate_create_session_response_value,
    validate_setup_status_response_value,
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
