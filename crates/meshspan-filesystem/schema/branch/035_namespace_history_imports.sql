-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE namespace_history_imports (
    session_id BLOB PRIMARY KEY CHECK (length(session_id) = 32),
    scope_binding BLOB NOT NULL CHECK (length(scope_binding) = 32),
    export_token BLOB CHECK (export_token IS NULL OR length(export_token) = 32),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    current_cursor BLOB NOT NULL CHECK (length(current_cursor) <= 256),
    terminal INTEGER NOT NULL CHECK (terminal IN (0, 1)),
    maximum_heads INTEGER NOT NULL CHECK (maximum_heads > 0),
    maximum_commits INTEGER NOT NULL CHECK (maximum_commits > 0),
    maximum_immutable_records INTEGER NOT NULL CHECK (maximum_immutable_records > 0),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    completed_at INTEGER,
    imported_commits INTEGER CHECK (imported_commits IS NULL OR imported_commits >= 0),
    supplied_commits INTEGER CHECK (supplied_commits IS NULL OR supplied_commits >= 0),
    immutable_records INTEGER CHECK (immutable_records IS NULL OR immutable_records >= 0),
    CHECK ((completed_at IS NULL) = (imported_commits IS NULL)),
    CHECK ((completed_at IS NULL) = (supplied_commits IS NULL)),
    CHECK ((completed_at IS NULL) = (immutable_records IS NULL))
) STRICT;

CREATE TABLE namespace_history_import_heads (
    session_id BLOB NOT NULL REFERENCES namespace_history_imports(session_id)
        ON DELETE CASCADE CHECK (length(session_id) = 32),
    head_ordinal INTEGER NOT NULL CHECK (head_ordinal >= 0),
    namespace_commit_id BLOB NOT NULL CHECK (length(namespace_commit_id) = 16),
    PRIMARY KEY (session_id, head_ordinal),
    UNIQUE (session_id, namespace_commit_id)
) STRICT;

CREATE TABLE namespace_history_import_pages (
    session_id BLOB NOT NULL REFERENCES namespace_history_imports(session_id)
        ON DELETE CASCADE CHECK (length(session_id) = 32),
    input_cursor BLOB NOT NULL CHECK (length(input_cursor) <= 256),
    page_digest BLOB NOT NULL CHECK (length(page_digest) = 32),
    output_cursor BLOB NOT NULL CHECK (length(output_cursor) <= 256),
    PRIMARY KEY (session_id, input_cursor)
) STRICT;

CREATE TABLE namespace_history_import_records (
    session_id BLOB NOT NULL REFERENCES namespace_history_imports(session_id)
        ON DELETE CASCADE CHECK (length(session_id) = 32),
    record_ordinal INTEGER NOT NULL CHECK (record_ordinal >= 0),
    record_kind INTEGER NOT NULL CHECK (record_kind IN (1, 2)),
    record_digest BLOB NOT NULL CHECK (length(record_digest) = 32),
    canonical_bytes BLOB,
    PRIMARY KEY (session_id, record_ordinal),
    UNIQUE (session_id, record_kind, record_digest),
    CHECK ((record_kind = 1 AND canonical_bytes IS NOT NULL) OR record_kind = 2)
) STRICT;

CREATE INDEX namespace_history_import_missing_objects
ON namespace_history_import_records(session_id, record_kind, canonical_bytes);
