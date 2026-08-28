// SPDX-License-Identifier: GPL-2.0-only

//! Cross-language public API contract fixtures and generation invariants.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "contract fixtures must stop at the first malformed checked-in vector"
)]

use meshspan_api_contract::{
    CreateSessionResponse, NullableField, decode_create_session_request,
    encode_create_session_response, generate_openapi, validate_create_session_request_value,
    validate_create_session_response_value,
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
        "login_name": "ada@example.test",
        "password": "not-a-real-password",
        "remember": false
    }));
    let explicit_null = decode_request(&json!({
        "operation_id": "018f1d20-7b4c-7a1e-9d22-39a1558b4c61",
        "login_name": "ada@example.test",
        "password": "not-a-real-password",
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
fn decoder_rejects_malformed_and_oversized_bodies_before_domain_work() {
    assert!(decode_create_session_request(b"{").is_err());
    assert!(decode_create_session_request(&vec![b' '; 2_049]).is_err());
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
