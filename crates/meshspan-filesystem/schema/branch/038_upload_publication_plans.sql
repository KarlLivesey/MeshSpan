-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE upload_publication_plans (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    upload_id BLOB NOT NULL UNIQUE CHECK (length(upload_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    encoded_plan BLOB NOT NULL CHECK (length(encoded_plan) BETWEEN 1 AND 131072),
    result_digest BLOB NOT NULL CHECK (length(result_digest) = 32)
) STRICT;
