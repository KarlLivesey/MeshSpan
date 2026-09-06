// SPDX-License-Identifier: GPL-2.0-only

use super::{json_request, json_response, optional_csrf_parameter};
use serde_json::{Value, json};

pub(super) fn configuration_path() -> Value {
    json!({
        "get": {
            "operationId": "getMetricsExporter", "summary": "Read the current metrics exporter policy",
            "x-meshspan-access": "system-manager",
            "responses": {
                "200": json_response("Current policy, or null when disabled and never configured", "#/components/schemas/MetricsExporterResponse"),
                "400": json_response("Query or body not supported", "#/components/schemas/ApiError"),
                "401": json_response("Authentication required", "#/components/schemas/ApiError"),
                "403": json_response("Manager authority required", "#/components/schemas/ApiError"),
                "500": json_response("Invalid stored or outgoing evidence", "#/components/schemas/ApiError"),
                "503": json_response("Current authority unavailable", "#/components/schemas/ApiError")
            }
        },
        "put": {
            "operationId": "configureMetricsExporter", "summary": "Replace the exporter opt-in and exact user allow-list",
            "description": "Replicated and audited. Missing configuration is disabled. Consumer identities are canonicalised in ascending order, duplicates rejected. Scrape consumers use current HTTPS-capable API keys and need no administrator role. This is a pull exporter, not a telemetry push destination. Exact retries return the original receipt.",
            "x-meshspan-access": "system-manager",
            "x-meshspan-max-request-bytes": crate::MAX_CONFIGURE_METRICS_EXPORTER_BYTES,
            "parameters": [optional_csrf_parameter()],
            "requestBody": json_request("Complete policy, observed sequence and exact-retry identity", "#/components/schemas/ConfigureMetricsExporterRequest"),
            "responses": {
                "200": json_response("Original committed policy receipt", "#/components/schemas/ConfigureMetricsExporterResponse"),
                "400": json_response("Invalid policy, query or consumer", "#/components/schemas/ApiError"),
                "401": json_response("Authentication required", "#/components/schemas/ApiError"),
                "403": json_response("Manager authority required", "#/components/schemas/ApiError"),
                "409": json_response("Stale sequence or changed retry", "#/components/schemas/ApiError"),
                "413": json_response("Body exceeds its bound", "#/components/schemas/ApiError"),
                "415": json_response("JSON content type required", "#/components/schemas/ApiError"),
                "500": json_response("Invalid stored or outgoing evidence", "#/components/schemas/ApiError"),
                "503": json_response("Current authority unavailable", "#/components/schemas/ApiError")
            }
        }
    })
}

pub(super) fn scrape_path() -> Value {
    json!({ "get": {
        "operationId": "scrapeMetrics", "summary": "Scrape explicitly enabled process-local OpenMetrics observations",
        "description": "Requires a current HTTPS-capable API key whose user is on the current exporter allow-list. Cookies, queries and bodies are not accepted. Disabled or missing policy grants no access. Collection never performs provider IO or initiates maintenance. Observations are not authority or durability proof.",
        "x-meshspan-access": "metrics-consumer",
        "x-meshspan-max-response-bytes": crate::MAX_METRICS_EXPORT_BYTES,
        "responses": {
            "200": { "description": "Bounded OpenMetrics 1.0 text with explicit EOF", "content": {
                "application/openmetrics-text; version=1.0.0; charset=utf-8": { "schema": { "type": "string", "maxLength": crate::MAX_METRICS_EXPORT_BYTES } }
            } },
            "400": json_response("Query or body not supported", "#/components/schemas/ApiError"),
            "401": json_response("API-key authentication required", "#/components/schemas/ApiError"),
            "403": json_response("Disabled exporter or consumer not allowed", "#/components/schemas/ApiError"),
            "500": json_response("Invalid source evidence", "#/components/schemas/ApiError"),
            "503": json_response("Current authority or measurements unavailable", "#/components/schemas/ApiError")
        }
    } })
}
