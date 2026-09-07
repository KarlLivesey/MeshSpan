// SPDX-License-Identifier: GPL-2.0-only

use super::{json_request, json_response, optional_csrf_parameter};
use serde_json::{Value, json};

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
