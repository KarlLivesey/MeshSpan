-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    migration_digest BLOB NOT NULL UNIQUE CHECK (length(migration_digest) = 32),
    applied_at INTEGER NOT NULL
) STRICT;

CREATE TABLE content_publications (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    manifest_id BLOB NOT NULL UNIQUE CHECK (length(manifest_id) = 16),
    format_version INTEGER NOT NULL CHECK (format_version > 0),
    logical_length INTEGER NOT NULL CHECK (logical_length >= 0),
    authorization_revision INTEGER NOT NULL CHECK (authorization_revision > 0),
    deadline INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    content_digest BLOB NULL CHECK (content_digest IS NULL OR length(content_digest) = 32),
    root_digest BLOB NULL CHECK (root_digest IS NULL OR length(root_digest) = 32),
    chunk_bytes INTEGER NULL CHECK (chunk_bytes IS NULL OR chunk_bytes > 0),
    chunk_count INTEGER NULL CHECK (chunk_count IS NULL OR chunk_count >= 0),
    key_generation INTEGER NULL CHECK (key_generation IS NULL OR key_generation > 0),
    key_nonce BLOB NULL CHECK (key_nonce IS NULL OR length(key_nonce) = 24),
    key_ciphertext BLOB NULL CHECK (key_ciphertext IS NULL OR length(key_ciphertext) = 48),
    key_envelope_digest BLOB NULL CHECK (
        key_envelope_digest IS NULL OR length(key_envelope_digest) = 32
    ),
    committed_at INTEGER NULL,
    CHECK (
        (state = 1 AND committed_at IS NULL)
        OR
        (state = 2 AND content_digest IS NOT NULL AND root_digest IS NOT NULL
         AND chunk_bytes IS NOT NULL AND chunk_count IS NOT NULL
         AND key_generation IS NOT NULL AND key_nonce IS NOT NULL
         AND key_ciphertext IS NOT NULL AND key_envelope_digest IS NOT NULL
         AND committed_at IS NOT NULL)
    )
) STRICT;

CREATE TABLE content_chunks (
    operation_id BLOB NOT NULL REFERENCES content_publications(operation_id),
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    plaintext_length INTEGER NOT NULL CHECK (plaintext_length > 0),
    plaintext_digest BLOB NOT NULL CHECK (length(plaintext_digest) = 32),
    ciphertext_length INTEGER NOT NULL CHECK (ciphertext_length > 16),
    ciphertext_digest BLOB NOT NULL CHECK (length(ciphertext_digest) = 32),
    provider_operation_id BLOB NOT NULL UNIQUE CHECK (length(provider_operation_id) = 16),
    receipt_target_id BLOB NULL CHECK (
        receipt_target_id IS NULL OR length(receipt_target_id) = 16
    ),
    receipt_target_generation INTEGER NULL CHECK (
        receipt_target_generation IS NULL OR receipt_target_generation > 0
    ),
    receipt_recorded_at INTEGER NULL,
    PRIMARY KEY (operation_id, chunk_index),
    CHECK (
        (receipt_target_id IS NULL AND receipt_target_generation IS NULL
         AND receipt_recorded_at IS NULL)
        OR
        (receipt_target_id IS NOT NULL AND receipt_target_generation IS NOT NULL
         AND receipt_recorded_at IS NOT NULL)
    )
) STRICT;

CREATE INDEX content_chunks_pending
ON content_chunks(operation_id, receipt_recorded_at, chunk_index);
