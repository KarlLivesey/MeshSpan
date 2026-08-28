-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE routing_signing_keys (
    node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK (generation > 0),
    verifying_key BLOB NOT NULL UNIQUE CHECK (length(verifying_key) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 2),
    created_at INTEGER NOT NULL,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (node_id, generation),
    CHECK (retired_at IS NULL OR retired_at >= created_at)
) STRICT;

CREATE TABLE partition_scopes (
    scope_id BLOB PRIMARY KEY CHECK (length(scope_id) = 16),
    partition_id BLOB NOT NULL REFERENCES metadata_partitions(partition_id) ON DELETE RESTRICT,
    ownership_epoch INTEGER NOT NULL CHECK (ownership_epoch > 0),
    routing_epoch INTEGER NOT NULL CHECK (routing_epoch > 0),
    handoff_state INTEGER NOT NULL CHECK (handoff_state BETWEEN 1 AND 3),
    destination_partition_id BLOB REFERENCES metadata_partitions(partition_id) ON DELETE RESTRICT,
    frozen_revision INTEGER CHECK (frozen_revision IS NULL OR frozen_revision > 0),
    snapshot_digest BLOB CHECK (snapshot_digest IS NULL OR length(snapshot_digest) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (
        (handoff_state = 1 AND destination_partition_id IS NULL
            AND frozen_revision IS NULL AND snapshot_digest IS NULL)
        OR (handoff_state = 2 AND destination_partition_id IS NOT NULL
            AND frozen_revision IS NULL AND snapshot_digest IS NULL)
        OR (handoff_state = 3 AND destination_partition_id IS NOT NULL
            AND frozen_revision IS NOT NULL AND snapshot_digest IS NOT NULL)
    ),
    CHECK (destination_partition_id IS NULL OR destination_partition_id <> partition_id)
) STRICT;

CREATE INDEX partition_scopes_by_partition
ON partition_scopes(partition_id, handoff_state, scope_id);

CREATE TABLE partition_routes (
    routing_epoch INTEGER NOT NULL CHECK (routing_epoch > 0),
    transition_sequence INTEGER NOT NULL CHECK (transition_sequence > 0),
    scope_id BLOB NOT NULL CHECK (length(scope_id) = 16),
    partition_id BLOB NOT NULL REFERENCES metadata_partitions(partition_id) ON DELETE RESTRICT,
    ownership_epoch INTEGER NOT NULL CHECK (ownership_epoch > 0),
    route_payload BLOB NOT NULL,
    route_digest BLOB NOT NULL CHECK (length(route_digest) = 32),
    signer_node_id BLOB NOT NULL CHECK (length(signer_node_id) = 16),
    signer_generation INTEGER NOT NULL CHECK (signer_generation > 0),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (routing_epoch, scope_id, transition_sequence),
    FOREIGN KEY (signer_node_id, signer_generation)
        REFERENCES routing_signing_keys(node_id, generation) ON DELETE RESTRICT
) STRICT;

CREATE INDEX partition_routes_latest
ON partition_routes(scope_id, routing_epoch DESC, transition_sequence DESC);
