// SPDX-License-Identifier: GPL-2.0-only

use super::{json_request, json_response, optional_csrf_parameter};
use serde_json::{Value, json};

pub(super) fn artifact_path() -> Value {
    json!({"put": {
        "operationId": "stageUpdateArtifact", "summary": "Stream a signed candidate executable to this node",
        "description": "Requires current system-manager authority before body consumption and again before source publication/output. Select the signed manifest first. Streams at most the exact signed length with a 30-minute deadline, verifying its signed SHA-256 before atomic owner-only local publication. Then commits the source advertisement through consensus. No executable bytes enter the consensus log. The receipt confirms this source, not installation or all-node staging. Keep the operation ID and bytes unchanged on retry. Unavailable responses may have committed; query operation status or retry. Requires application/octet-stream, exact Content-Length, no query or Content-Encoding. Two owned transfer workers per gateway; excess work returns 503 without reading the body.",
        "x-meshspan-access":"system-manager", "x-meshspan-max-request-bytes":crate::MAX_UPDATE_ARTIFACT_BYTES,
        "parameters":[
            {"name":"rollout_id","in":"path","required":true,"schema":{"type":"string","minLength":36,"maxLength":36,
                "pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"}},
            {"name":"target","in":"path","required":true,"schema":{"type":"string","minLength":1,"maxLength":64,
                "pattern":"^(aarch64|x86_64)-(apple-darwin|unknown-linux-musl)$"}},
            {"name":"MeshSpan-Operation-Id","in":"header","required":true,"schema":crate::schema::request_schema::<crate::OperationId>()},
            {"name":"Content-Length","in":"header","required":true,"schema":{"type":"string","pattern":"^[1-9][0-9]{0,9}$"}},
            optional_csrf_parameter()
        ],
        "requestBody":{"required":true,"content":{"application/octet-stream":{"schema":{"type":"string","format":"binary"}}}},
        "responses": {
            "200":json_response("Verified source and original authoritative publication receipt","#/components/schemas/StageUpdateArtifactResponse"),
            "400":json_response("Invalid envelope or executable","#/components/schemas/ApiError"),
            "401":json_response("Authentication required","#/components/schemas/ApiError"),
            "403":json_response("Manager authority required","#/components/schemas/ApiError"),
            "409":json_response("Candidate, trust or operation conflict","#/components/schemas/ApiError"),
            "413":json_response("Body exceeds signed length","#/components/schemas/ApiError"),
            "415":json_response("Raw executable bytes required","#/components/schemas/ApiError"),
            "500":json_response("Invalid stored or outgoing evidence","#/components/schemas/ApiError"),
            "503":json_response("Unavailable or outcome unresolved","#/components/schemas/ApiError")
        }
    }})
}

pub(super) fn path() -> Value {
    json!({
        "get": {
            "operationId": "getUpdates", "summary": "Read publisher trust and rollout progress",
            "x-meshspan-access": "system-manager",
            "description": "No body. Omit rollout_id for active work, or supply one canonical UUID to inspect retained work. Unknown identities return rollout null. Progress is a local metadata observation; current authority is checked before collection and output. installation_available is independent of candidate admission.",
            "parameters": [{"name": "rollout_id", "in": "query", "required": false,
                "schema": {"type": "string", "minLength": 36, "maxLength": 36,
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"}}],
            "responses": {
                "200": json_response("Public trust and durable progress", "#/components/schemas/UpdatesResponse"),
                "400": json_response("Invalid query or unexpected body", "#/components/schemas/ApiError"),
                "401": json_response("Authentication required", "#/components/schemas/ApiError"),
                "403": json_response("Manager authority required", "#/components/schemas/ApiError"),
                "500": json_response("Invalid stored or outgoing evidence", "#/components/schemas/ApiError"),
                "503": json_response("Authority unavailable", "#/components/schemas/ApiError")
            }
        },
        "put": {
            "operationId": "manageUpdate", "summary": "Configure publisher trust, select a candidate or control a rollout",
            "description": "Authenticates before reading the bounded JSON body. Public keys must be obtained independently of the candidate. Exact retries return the original command receipt, not current rollout progress or installation success. Selecting a manifest does not transfer binaries. Cancellation never rolls back installed nodes and is rejected while a restart outcome is unresolved. A lost response or 503 means outcome unknown: retry the unchanged operation. Clients cannot submit readiness or installation claims through this endpoint.",
            "x-meshspan-access": "system-manager",
            "x-meshspan-max-request-bytes": crate::MAX_MANAGE_UPDATE_BYTES,
            "parameters": [optional_csrf_parameter()],
            "requestBody": json_request("One explicit manager action", "#/components/schemas/ManageUpdateRequest"),
            "responses": {
                "200": json_response("Original committed command receipt", "#/components/schemas/ManageUpdateResponse"),
                "400": json_response("Invalid input", "#/components/schemas/ApiError"),
                "401": json_response("Authentication required", "#/components/schemas/ApiError"),
                "403": json_response("Manager authority required", "#/components/schemas/ApiError"),
                "409": json_response("Rejected command, stale sequence or changed retry", "#/components/schemas/ApiError"),
                "413": json_response("Body exceeds its bound", "#/components/schemas/ApiError"),
                "415": json_response("JSON required", "#/components/schemas/ApiError"),
                "500": json_response("Invalid outgoing evidence", "#/components/schemas/ApiError"),
                "503": json_response("Authority unavailable or outcome unresolved", "#/components/schemas/ApiError")
            }
        }
    })
}
