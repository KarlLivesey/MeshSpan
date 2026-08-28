-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE handle_write_admissions (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    handle_id BLOB NOT NULL REFERENCES open_handles(handle_id)
        CHECK (length(handle_id) = 16),
    handle_fence INTEGER NOT NULL CHECK (handle_fence > 0),
    principal_id BLOB NOT NULL CHECK (length(principal_id) = 16),
    authorization_revision INTEGER NOT NULL CHECK (authorization_revision > 0),
    gateway_node_id BLOB NOT NULL CHECK (length(gateway_node_id) = 16),
    byte_start INTEGER NOT NULL CHECK (byte_start >= 0),
    byte_length INTEGER NOT NULL CHECK (byte_length > 0),
    content_digest BLOB NOT NULL CHECK (length(content_digest) = 32),
    admitted_at INTEGER NOT NULL,
    receipt_digest BLOB NOT NULL CHECK (length(receipt_digest) = 32),
    CHECK (byte_start <= 9223372036854775807 - byte_length)
) STRICT;

CREATE INDEX handle_write_admissions_by_handle
ON handle_write_admissions(handle_id, handle_fence, admitted_at, operation_id);
