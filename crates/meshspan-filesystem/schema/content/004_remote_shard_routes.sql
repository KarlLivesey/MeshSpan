-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE content_remote_shard_routes (
    operation_id BLOB NOT NULL,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    source_node_id BLOB NOT NULL CHECK (length(source_node_id) = 16),
    source_provider_operation_id BLOB NOT NULL CHECK (
        length(source_provider_operation_id) = 16
    ),
    target_id BLOB NOT NULL CHECK (length(target_id) = 16),
    target_generation INTEGER NOT NULL CHECK (target_generation > 0),
    recorded_at INTEGER NOT NULL,
    PRIMARY KEY (operation_id, chunk_index),
    FOREIGN KEY (operation_id, chunk_index)
        REFERENCES content_chunks(operation_id, chunk_index)
) STRICT;

CREATE INDEX content_remote_shard_routes_by_target
ON content_remote_shard_routes(target_id, target_generation, operation_id, chunk_index);
