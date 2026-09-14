// SPDX-License-Identifier: GPL-2.0-only

use super::{json_request, json_response, optional_csrf_parameter};
use serde_json::{Value, json};

pub(crate) fn path() -> Value {
    json!({
        "get": {
            "operationId": "getFederationStorageGrant",
            "summary": "Inspect one provider-owned storage offer and its current metadata revision",
            "description": "Current manager authority is checked before lookup. This is an exact lookup, not a collection. Null means the identity is unused. A grant's lifecycle is separate from its validity interval, relationship state and actual stored protection.",
            "x-meshspan-access": "system-manager",
            "x-meshspan-max-request-bytes": crate::MAX_FEDERATION_STORAGE_GRANT_BYTES,
            "parameters": [{"name": "grant_id", "in": "query", "required": true,
                "schema": {"$ref": "#/components/schemas/FederationStorageGrantQuery/properties/grant_id"}}],
            "responses": {
                "200": json_response("Current offer or null; no-store", "#/components/schemas/FederationStorageGrantResponse"),
                "400": json_response("Invalid query", "#/components/schemas/ApiError"),
                "401": json_response("Authentication required", "#/components/schemas/ApiError"),
                "403": json_response("Current manager or local provider authority required", "#/components/schemas/ApiError"),
                "409": json_response("Metadata changed during lookup; retry", "#/components/schemas/ApiError"),
                "500": json_response("Invalid retained or outgoing evidence", "#/components/schemas/ApiError"),
                "503": json_response("Authority unavailable", "#/components/schemas/ApiError")
            }
        },
        "post": {
            "operationId": "configureFederationStorageGrant",
            "summary": "Issue, replace or withdraw a provider-owned storage offer",
            "description": "Current manager authority and CSRF, where applicable, are checked before body parsing and again before commit. The observed root-metadata revision fences new mutations; exact retries retain their original receipt. Issuance offers provider capacity only: it neither configures consumer backups nor grants access to consumer files. Consumer restrictions remain independent. Replacement retains peer restrictions and allocation lineage; revocation does not erase retained encrypted objects. Missing lifetime defaults to 30 days; null explicitly means indefinite.",
            "x-meshspan-access": "system-manager",
            "x-meshspan-idempotency": "operation-id-and-canonical-request-digest",
            "x-meshspan-max-request-bytes": crate::MAX_FEDERATION_STORAGE_GRANT_BYTES,
            "parameters": [optional_csrf_parameter()],
            "requestBody": json_request("Exact operation, observed revision and storage offer change", "#/components/schemas/ConfigureFederationStorageGrantRequest"),
            "responses": {
                "200": json_response("Original durable mutation receipt", "#/components/schemas/ConfigureFederationStorageGrantResponse"),
                "400": json_response("Invalid request", "#/components/schemas/ApiError"),
                "401": json_response("Authentication required", "#/components/schemas/ApiError"),
                "403": json_response("Current manager or local provider authority required", "#/components/schemas/ApiError"),
                "409": json_response("Stale revision, changed retry or conflicting grant", "#/components/schemas/ApiError"),
                "413": json_response("Body exceeds its bound", "#/components/schemas/ApiError"),
                "415": json_response("JSON required", "#/components/schemas/ApiError"),
                "500": json_response("Invalid retained or outgoing evidence", "#/components/schemas/ApiError"),
                "503": json_response("Authority unavailable; outcome may be unknown", "#/components/schemas/ApiError")
            }
        }
    })
}
