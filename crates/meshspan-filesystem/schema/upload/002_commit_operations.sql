-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE upload_sessions
ADD COLUMN commit_operation_id BLOB CHECK (
    commit_operation_id IS NULL OR length(commit_operation_id) = 16
);

ALTER TABLE upload_sessions
ADD COLUMN commit_request_digest BLOB CHECK (
    commit_request_digest IS NULL OR length(commit_request_digest) = 32
);

ALTER TABLE upload_sessions
ADD COLUMN committed_object_id BLOB CHECK (
    committed_object_id IS NULL OR length(committed_object_id) = 16
);

ALTER TABLE upload_sessions
ADD COLUMN committed_version_id BLOB CHECK (
    committed_version_id IS NULL OR length(committed_version_id) = 16
);

ALTER TABLE upload_sessions ADD COLUMN committed_at INTEGER;

CREATE UNIQUE INDEX upload_commit_operations
ON upload_sessions(commit_operation_id)
WHERE commit_operation_id IS NOT NULL;
