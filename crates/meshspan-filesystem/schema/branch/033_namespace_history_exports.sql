-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE namespace_history_exports (
    request_digest BLOB PRIMARY KEY CHECK (length(request_digest) = 32),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    next_record_ordinal INTEGER NOT NULL CHECK (next_record_ordinal >= 0),
    complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at)
) STRICT;

CREATE TABLE namespace_history_export_known_commits (
    request_digest BLOB NOT NULL REFERENCES namespace_history_exports(request_digest)
        ON DELETE CASCADE CHECK (length(request_digest) = 32),
    namespace_commit_id BLOB NOT NULL CHECK (length(namespace_commit_id) = 16),
    PRIMARY KEY (request_digest, namespace_commit_id)
) STRICT;

CREATE TABLE namespace_history_export_work (
    request_digest BLOB NOT NULL REFERENCES namespace_history_exports(request_digest)
        ON DELETE CASCADE CHECK (length(request_digest) = 32),
    work_kind INTEGER NOT NULL CHECK (work_kind BETWEEN 1 AND 5),
    identity BLOB NOT NULL CHECK (length(identity) IN (16, 32)),
    processed INTEGER NOT NULL CHECK (processed IN (0, 1)),
    PRIMARY KEY (request_digest, work_kind, identity)
) STRICT;

CREATE INDEX namespace_history_export_pending
ON namespace_history_export_work(request_digest, processed, work_kind, identity);

CREATE TABLE namespace_history_export_records (
    request_digest BLOB NOT NULL REFERENCES namespace_history_exports(request_digest)
        ON DELETE CASCADE CHECK (length(request_digest) = 32),
    record_ordinal INTEGER NOT NULL CHECK (record_ordinal >= 0),
    record_kind INTEGER NOT NULL CHECK (record_kind IN (1, 2)),
    source_kind INTEGER NOT NULL CHECK (source_kind BETWEEN 1 AND 5),
    source_identity BLOB NOT NULL CHECK (length(source_identity) IN (16, 32)),
    transfer_digest BLOB NOT NULL CHECK (length(transfer_digest) = 32),
    PRIMARY KEY (request_digest, record_ordinal),
    UNIQUE (request_digest, record_kind, transfer_digest),
    UNIQUE (request_digest, source_kind, source_identity)
) STRICT;

CREATE TABLE namespace_history_export_cursors (
    request_digest BLOB NOT NULL REFERENCES namespace_history_exports(request_digest)
        ON DELETE CASCADE CHECK (length(request_digest) = 32),
    start_ordinal INTEGER NOT NULL CHECK (start_ordinal >= 0),
    PRIMARY KEY (request_digest, start_ordinal)
) STRICT;
