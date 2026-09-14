// SPDX-License-Identifier: GPL-2.0-only

//! Native first-credential capability routes; the capability is never a login secret.

use super::{json_request, json_response, optional_csrf_parameter};
use serde_json::{Value, json};

pub(super) fn paths() -> [(String, Value); 3] {
    [
        (
            "/admin/identities/users/{principal_id}/enrollments".to_owned(),
            manager_operation(
                "issueUserEnrollment",
                "Issue short-lived first-credential consent",
                (
                    "principal_id",
                    json!(crate::schema::request_schema::<crate::PrincipalId>()),
                ),
                ("IssueUserEnrollmentRequest", "IssueUserEnrollmentResponse"),
            ),
        ),
        (
            "/admin/identities/user-enrollments/{enrollment_operation_id}/revocations".to_owned(),
            manager_operation(
                "revokeUserEnrollment",
                "Cancel invitation use and secret recovery",
                (
                    "enrollment_operation_id",
                    json!(crate::schema::request_schema::<crate::OperationId>()),
                ),
                (
                    "RevokeUserEnrollmentRequest",
                    "RevokeUserEnrollmentResponse",
                ),
            ),
        ),
        (
            "/user-enrollments/api-keys".to_owned(),
            json!({"post": {
                "operationId": "redeemUserEnrollmentApiKey",
                "summary": "Enroll a user's first ordinary HTTPS/headless credential",
                "description": "Explicit body capability authorizes only the named recipient's first primary method. No session or resource authority is conferred by the invitation. Atomic consumption creates one independently revocable API key. Only the identical operation and request can recover its secret, while the invitation and recipient consent remain live. Retain the exact request on connection loss; its outcome is unknown.",
                "x-meshspan-access": "anonymous",
                "x-meshspan-max-request-bytes": crate::MAX_USER_ENROLLMENT_REQUEST_BYTES,
                "requestBody": json_request("Exact one-use capability redemption", "#/components/schemas/RedeemUserEnrollmentApiKeyRequest"),
                "responses": responses("CreateApiKeyResponse")
            }}),
        ),
    ]
}

fn manager_operation(
    operation: &str,
    summary: &str,
    parameter: (&str, Value),
    schemas: (&str, &str),
) -> Value {
    let (parameter, parameter_schema) = parameter;
    let (request, response) = schemas;
    json!({"post": {
        "operationId": operation, "summary": summary,
        "description": "Requires a current system manager browser session, mutation CSRF proof and recent step-up. Exact operation identity binds target, consent revision and all request fields. Invitation lifetime is at most 24 hours. Revocation stops capability use and secret recovery; an already-created method has its own lifecycle.",
        "x-meshspan-access": "system-manager-csrf",
        "x-meshspan-required-assurance": "recent_step_up",
        "x-meshspan-max-request-bytes": crate::MAX_USER_ENROLLMENT_REQUEST_BYTES,
        "parameters": [optional_csrf_parameter(), {"name": parameter, "in": "path", "required": true, "schema": parameter_schema}],
        "requestBody": json_request("Exact manager consent mutation", &format!("#/components/schemas/{request}")),
        "responses": responses(response)
    }})
}

fn responses(schema: &str) -> Value {
    json!({
        "200": json_response("Verified committed result", &format!("#/components/schemas/{schema}")),
        "400": json_response("Invalid bounded request", "#/components/schemas/ApiError"),
        "401": json_response("Current authentication required", "#/components/schemas/ApiError"),
        "403": json_response("Current consent or authentication rejected", "#/components/schemas/ApiError"),
        "409": json_response("Changed retry or stale authoritative state", "#/components/schemas/ApiError"),
        "413": json_response("Request exceeds its bound", "#/components/schemas/ApiError"),
        "415": json_response("JSON required", "#/components/schemas/ApiError"),
        "500": json_response("Invalid authoritative evidence", "#/components/schemas/ApiError"),
        "503": json_response("Authority unavailable; retain the exact operation", "#/components/schemas/ApiError")
    })
}
