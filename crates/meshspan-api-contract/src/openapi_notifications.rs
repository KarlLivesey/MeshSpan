// SPDX-License-Identifier: GPL-2.0-only

use super::{json_request, json_response, optional_csrf_parameter};
use serde_json::{Value, json};

pub(super) fn path() -> Value {
    json!({
        "get": {
            "operationId": "getNotifications", "summary": "Read notification channels and local worker health",
            "x-meshspan-access": "system-manager",
            "responses": {
                "200": json_response("Redacted configuration; no credentials or destination URLs", "#/components/schemas/NotificationsResponse"),
                "400": json_response("Query or body not supported", "#/components/schemas/ApiError"),
                "401": json_response("Authentication required", "#/components/schemas/ApiError"),
                "403": json_response("Manager authority required", "#/components/schemas/ApiError"),
                "500": json_response("Invalid stored or outgoing evidence", "#/components/schemas/ApiError"),
                "503": json_response("Authority unavailable", "#/components/schemas/ApiError")
            }
        },
        "put": {
            "operationId": "configureNotification", "summary": "Create or replace an encrypted notification channel",
            "description": "Disabled unless explicitly enabled. At most 64 channels. Settings retention is explicit; secrets are never returned. Configuration and encrypted settings commit atomically. Exact retries return the original receipt. Replacing or disabling a configuration cancels queued/claimed deliveries; already transmitted messages cannot be recalled. External acceptance is not inbox delivery or exactly-once execution. Outcome events can include retries, not just success.",
            "x-meshspan-access": "system-manager",
            "x-meshspan-max-request-bytes": crate::MAX_CONFIGURE_NOTIFICATION_BYTES,
            "parameters": [optional_csrf_parameter()],
            "requestBody": json_request("Complete configuration and explicit destination update", "#/components/schemas/ConfigureNotificationRequest"),
            "responses": {
                "200": json_response("Original committed configuration receipt", "#/components/schemas/ConfigureNotificationResponse"),
                "400": json_response("Invalid configuration", "#/components/schemas/ApiError"),
                "401": json_response("Authentication required", "#/components/schemas/ApiError"),
                "403": json_response("Manager authority required", "#/components/schemas/ApiError"),
                "409": json_response("Stale sequence or changed retry", "#/components/schemas/ApiError"),
                "413": json_response("Body exceeds its bound", "#/components/schemas/ApiError"),
                "415": json_response("JSON required", "#/components/schemas/ApiError"),
                "500": json_response("Invalid outgoing evidence", "#/components/schemas/ApiError"),
                "503": json_response("Authority unavailable", "#/components/schemas/ApiError")
            }
        }
    })
}
