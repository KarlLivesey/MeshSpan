-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE update_signers (
    signer_id BLOB PRIMARY KEY CHECK (length(signer_id) = 16),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    public_key BLOB NOT NULL CHECK (length(public_key) = 65),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE update_rollouts (
    rollout_id BLOB PRIMARY KEY CHECK (length(rollout_id) = 16),
    signer_id BLOB NOT NULL REFERENCES update_signers(signer_id),
    signer_sequence INTEGER NOT NULL CHECK (signer_sequence > 0),
    manifest BLOB NOT NULL CHECK (length(manifest) BETWEEN 1 AND 16384),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    signature BLOB NOT NULL CHECK (length(signature) BETWEEN 1 AND 72),
    allow_service_interruption INTEGER NOT NULL CHECK (allow_service_interruption IN (0, 1)),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    created_by BLOB NOT NULL REFERENCES principals(principal_id),
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

-- Running or paused work remains the one selected candidate until completion/cancellation.
CREATE UNIQUE INDEX update_rollouts_one_active ON update_rollouts((1)) WHERE state IN (1, 2);

CREATE TABLE update_rollout_nodes (
    rollout_id BLOB NOT NULL REFERENCES update_rollouts(rollout_id),
    node_id BLOB NOT NULL REFERENCES nodes(node_id),
    incarnation INTEGER NOT NULL CHECK (incarnation > 0),
    phase INTEGER NOT NULL CHECK (phase BETWEEN 1 AND 5),
    restart_pending INTEGER NOT NULL CHECK (restart_pending IN (0, 1)),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    target TEXT CHECK (target IS NULL OR length(target) BETWEEN 1 AND 64),
    evidence_digest BLOB CHECK (evidence_digest IS NULL OR length(evidence_digest) = 32),
    observed_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (rollout_id, node_id)
) STRICT;

CREATE INDEX update_rollout_nodes_by_phase ON update_rollout_nodes(rollout_id, phase, node_id);
CREATE UNIQUE INDEX update_rollout_nodes_one_restart ON update_rollout_nodes(rollout_id) WHERE restart_pending = 1;
