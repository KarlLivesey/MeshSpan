-- SPDX-License-Identifier: GPL-2.0-only

-- Private material remains node-local. Replicated metadata retains every public generation so
-- historical secret envelopes remain attributable and decryptable during controlled rotation.
CREATE TABLE node_wrapping_keys (
    node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK (generation > 0),
    public_key BLOB NOT NULL CHECK (length(public_key) = 32),
    key_fingerprint BLOB NOT NULL CHECK (length(key_fingerprint) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    registered_at INTEGER NOT NULL,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (node_id, generation),
    UNIQUE (key_fingerprint),
    CHECK (state != 3 OR retired_at IS NOT NULL)
) STRICT;

CREATE UNIQUE INDEX one_live_node_wrapping_key
ON node_wrapping_keys(node_id)
WHERE state = 1;

CREATE TRIGGER node_wrapping_keys_require_active_node
BEFORE INSERT ON node_wrapping_keys
WHEN NOT EXISTS (
    SELECT 1 FROM nodes
    WHERE node_id = NEW.node_id AND state = 2 AND retired_at IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'node wrapping key owner is not active');
END;

CREATE TRIGGER node_wrapping_keys_immutable
BEFORE UPDATE ON node_wrapping_keys
BEGIN
    SELECT RAISE(ABORT, 'node wrapping key generations are immutable');
END;

CREATE TRIGGER node_wrapping_keys_not_deletable
BEFORE DELETE ON node_wrapping_keys
BEGIN
    SELECT RAISE(ABORT, 'node wrapping key generations cannot be deleted');
END;
