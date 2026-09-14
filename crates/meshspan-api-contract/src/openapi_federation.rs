// SPDX-License-Identifier: GPL-2.0-only

use super::{json_request, json_response, optional_csrf_parameter};
use serde_json::{Value, json};

#[path = "openapi_federation_storage.rs"]
pub(super) mod storage;

pub(super) fn connection_path() -> Value {
    json!({"post": {
        "operationId": "connectFederation",
        "summary": "Connect to another autonomous swarm using its administrator's invitation",
        "description": "Current manager authority is checked before body parsing and after pinned HTTPS exchange. Exact public intent is committed before contacting the peer. A successful response means both sides approved the relationship, not that data grants or a live transport session exist. An interrupted exchange has an unknown outcome: retry the exact operation and input before the invitation expires.",
        "x-meshspan-access": "system-manager",
        "x-meshspan-idempotency": "operation-id-and-canonical-request-digest",
        "x-meshspan-max-request-bytes": crate::MAX_FEDERATION_CONNECTION_BYTES,
        "parameters": [optional_csrf_parameter()],
        "requestBody": json_request("Invitation and reachable local origin", "#/components/schemas/ConnectFederationRequest"),
        "responses": {
            "201": json_response("Durable local approval following remote approval; no-store", "#/components/schemas/ConnectFederationResponse"),
            "400": json_response("Invalid input or peer reply", "#/components/schemas/ApiError"),
            "401": json_response("Authentication required", "#/components/schemas/ApiError"),
            "403": json_response("Current manager authority required", "#/components/schemas/ApiError"),
            "409": json_response("Changed intent or relationship state", "#/components/schemas/ApiError"),
            "413": json_response("Body exceeds its bound", "#/components/schemas/ApiError"),
            "415": json_response("JSON required", "#/components/schemas/ApiError"),
            "500": json_response("Invalid retained or outgoing evidence", "#/components/schemas/ApiError"),
            "503": json_response("Authority or peer unavailable; outcome may be unknown", "#/components/schemas/ApiError")
        }
    }})
}

pub(super) fn acceptance_path() -> Value {
    json!({"post": {
        "operationId": "acceptFederationPairing",
        "summary": "Consume an administrator's invitation and approve one autonomous peer",
        "description": "The short-lived MeshSpan-Pairing Authorization credential is verified before body parsing, including the issuer's current manager authority. Exact retries retain the original peer and approval receipt. This approves only the issuing side: it does not enrol nodes, grant data access or prove a live federation session.",
        "x-meshspan-access": "federation-pairing-invitation",
        "x-meshspan-idempotency": "operation-id-and-canonical-request-digest",
        "x-meshspan-max-request-bytes": crate::MAX_FEDERATION_CONNECTION_BYTES,
        "parameters": [{"name": "Authorization", "in": "header", "required": true,
            "schema": {"type": "string", "maxLength": 780, "pattern": "^MeshSpan-Pairing meshspan-federate-v1\\."}}],
        "requestBody": json_request("Exact operation and signed public peer record", "#/components/schemas/AcceptFederationPairingRequest"),
        "responses": {
            "201": json_response("Original local approval and signed peer; no-store", "#/components/schemas/AcceptFederationPairingResponse"),
            "400": json_response("Invalid peer or request", "#/components/schemas/ApiError"),
            "401": json_response("Missing, expired or withdrawn invitation", "#/components/schemas/ApiError"),
            "403": json_response("Issuer no longer has manager authority", "#/components/schemas/ApiError"),
            "409": json_response("Changed retry or relationship state", "#/components/schemas/ApiError"),
            "413": json_response("Body exceeds its bound", "#/components/schemas/ApiError"),
            "415": json_response("JSON required", "#/components/schemas/ApiError"),
            "500": json_response("Invalid retained or outgoing evidence", "#/components/schemas/ApiError"),
            "503": json_response("Authority unavailable; outcome may be unknown", "#/components/schemas/ApiError")
        }
    }})
}

pub(super) fn invitation_path() -> Value {
    json!({"post": {
        "operationId": "createFederationPairingInvitation",
        "summary": "Issue short-lived connection material for another autonomous swarm",
        "description": "Current system-manager approval before body parsing and again at commit. Exact retries return the original code and expiry. Codes do not enrol local nodes or grant file access. Peer acceptance is a separate operation.",
        "x-meshspan-access": "system-manager",
        "x-meshspan-idempotency": "operation-id-and-canonical-request-digest",
        "x-meshspan-max-request-bytes": crate::MAX_CREATE_FEDERATION_PAIRING_BYTES,
        "parameters": [optional_csrf_parameter()],
        "requestBody": json_request("Pinned origin and bounded lifetime", "#/components/schemas/CreateFederationPairingInvitationRequest"),
        "responses": {
            "201": json_response("Original committed secret-bearing invitation; no-store", "#/components/schemas/CreateFederationPairingInvitationResponse"),
            "400": json_response("Invalid request", "#/components/schemas/ApiError"),
            "401": json_response("Authentication required", "#/components/schemas/ApiError"),
            "403": json_response("Current manager authority required", "#/components/schemas/ApiError"),
            "409": json_response("Changed retry or cancelled invitation", "#/components/schemas/ApiError"),
            "413": json_response("Body exceeds its bound", "#/components/schemas/ApiError"),
            "415": json_response("JSON required", "#/components/schemas/ApiError"),
            "500": json_response("Invalid retained or outgoing evidence", "#/components/schemas/ApiError"),
            "503": json_response("Authority unavailable", "#/components/schemas/ApiError")
        }
    }})
}

pub(super) fn cancellation_path() -> Value {
    json!({"post": {
        "operationId": "cancelFederationPairingInvitation",
        "summary": "Withdraw unused federation connection material",
        "description": "Current system-manager authority is required before reading input and again at commit. Exact retries retain the original cancellation receipt. Does not revoke an established relationship.",
        "x-meshspan-access": "system-manager",
        "x-meshspan-idempotency": "operation-id-and-canonical-request-digest",
        "x-meshspan-max-request-bytes": crate::MAX_CREATE_FEDERATION_PAIRING_BYTES,
        "parameters": [optional_csrf_parameter()],
        "requestBody": json_request("Exact invitation revision and reason", "#/components/schemas/CancelFederationPairingInvitationRequest"),
        "responses": {
            "200": json_response("Durable original cancellation receipt", "#/components/schemas/CancelFederationPairingInvitationResponse"),
            "400": json_response("Invalid request", "#/components/schemas/ApiError"),
            "401": json_response("Authentication required", "#/components/schemas/ApiError"),
            "403": json_response("Current manager authority required", "#/components/schemas/ApiError"),
            "409": json_response("Changed retry or invitation no longer pending", "#/components/schemas/ApiError"),
            "413": json_response("Body exceeds its bound", "#/components/schemas/ApiError"),
            "415": json_response("JSON required", "#/components/schemas/ApiError"),
            "500": json_response("Invalid retained or outgoing evidence", "#/components/schemas/ApiError"),
            "503": json_response("Authority unavailable", "#/components/schemas/ApiError")
        }
    }})
}
