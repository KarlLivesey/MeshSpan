-- SPDX-License-Identifier: GPL-2.0-only

-- Cache source advertisements are not availability or installation acknowledgements.
CREATE TABLE update_artifact_sources (
    rollout_id BLOB NOT NULL REFERENCES update_rollouts(rollout_id),
    node_id BLOB NOT NULL REFERENCES nodes(node_id),
    incarnation INTEGER NOT NULL CHECK (incarnation > 0),
    target TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 64),
    byte_length INTEGER NOT NULL CHECK (byte_length BETWEEN 1 AND 8589934592),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (rollout_id, target, node_id)
) STRICT;
