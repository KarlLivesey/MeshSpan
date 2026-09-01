-- SPDX-License-Identifier: GPL-2.0-only

-- A unified public recipient registry permits node-local and offline-recovery recipients without
-- weakening envelope validation or coupling secret rows to one recipient family.
CREATE TABLE secret_wrapping_recipients (
    key_fingerprint BLOB PRIMARY KEY CHECK (length(key_fingerprint) = 32),
    recipient_kind INTEGER NOT NULL CHECK (recipient_kind IN (1, 2)),
    owner_id BLOB NOT NULL CHECK (length(owner_id) = 16),
    generation INTEGER NOT NULL CHECK (generation > 0),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    registered_at INTEGER NOT NULL,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (recipient_kind, owner_id, generation),
    CHECK (state != 3 OR retired_at IS NOT NULL)
) STRICT;

INSERT INTO secret_wrapping_recipients(
    key_fingerprint, recipient_kind, owner_id, generation, public_key, state,
    registered_at, retired_at, revision
)
SELECT key_fingerprint, 1, node_id, generation, public_key, state,
       registered_at, retired_at, revision
FROM node_wrapping_keys;

CREATE TABLE secret_generations (
    secret_kind INTEGER NOT NULL CHECK (secret_kind BETWEEN 1 AND 65535),
    secret_id BLOB NOT NULL CHECK (length(secret_id) = 16),
    generation INTEGER NOT NULL CHECK (generation > 0),
    format_version INTEGER NOT NULL CHECK (format_version > 0),
    nonce BLOB NOT NULL CHECK (length(nonce) = 24),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 17 AND 65552),
    ciphertext_digest BLOB NOT NULL CHECK (length(ciphertext_digest) = 32),
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (secret_kind, secret_id, generation)
) STRICT;

CREATE TABLE secret_recipient_envelopes (
    secret_kind INTEGER NOT NULL,
    secret_id BLOB NOT NULL,
    secret_generation INTEGER NOT NULL,
    recipient_key_fingerprint BLOB NOT NULL
        REFERENCES secret_wrapping_recipients(key_fingerprint) ON DELETE RESTRICT,
    format_version INTEGER NOT NULL CHECK (format_version > 0),
    recipient_public_key BLOB NOT NULL CHECK (length(recipient_public_key) = 32),
    ephemeral_public_key BLOB NOT NULL CHECK (length(ephemeral_public_key) = 32),
    salt BLOB NOT NULL CHECK (length(salt) = 32),
    nonce BLOB NOT NULL CHECK (length(nonce) = 24),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) = 48),
    envelope_digest BLOB NOT NULL CHECK (length(envelope_digest) = 32),
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (
        secret_kind, secret_id, secret_generation, recipient_key_fingerprint
    ),
    FOREIGN KEY (secret_kind, secret_id, secret_generation)
        REFERENCES secret_generations(secret_kind, secret_id, generation) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER secret_envelope_recipient_must_match
BEFORE INSERT ON secret_recipient_envelopes
WHEN NOT EXISTS (
    SELECT 1 FROM secret_wrapping_recipients
    WHERE key_fingerprint = NEW.recipient_key_fingerprint
      AND public_key = NEW.recipient_public_key
      AND state = 1
      AND retired_at IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'secret envelope recipient is not current');
END;

CREATE TRIGGER secret_wrapping_recipients_immutable
BEFORE UPDATE ON secret_wrapping_recipients
BEGIN
    SELECT RAISE(ABORT, 'secret wrapping recipient generations are immutable');
END;

CREATE TRIGGER secret_generations_immutable
BEFORE UPDATE ON secret_generations
BEGIN
    SELECT RAISE(ABORT, 'secret generations are immutable');
END;

CREATE TRIGGER secret_recipient_envelopes_immutable
BEFORE UPDATE ON secret_recipient_envelopes
BEGIN
    SELECT RAISE(ABORT, 'secret recipient envelopes are immutable');
END;

CREATE TRIGGER secret_generations_not_deletable
BEFORE DELETE ON secret_generations
BEGIN
    SELECT RAISE(ABORT, 'secret generations cannot be deleted');
END;

CREATE TRIGGER secret_recipient_envelopes_not_deletable
BEFORE DELETE ON secret_recipient_envelopes
BEGIN
    SELECT RAISE(ABORT, 'secret recipient envelopes cannot be deleted');
END;
