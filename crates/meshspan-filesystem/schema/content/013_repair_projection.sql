-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE content_repair_projection_cursors (
    partition_id BLOB NOT NULL CHECK (length(partition_id) = 16),
    publication_operation_id BLOB NOT NULL REFERENCES content_publications(operation_id),
    revision INTEGER NOT NULL CHECK (revision > 0),
    effect_operation_id BLOB NOT NULL REFERENCES content_shard_repair_effects(effect_operation_id),
    PRIMARY KEY (partition_id, publication_operation_id)
) STRICT;

CREATE INDEX content_publications_repair_projection
ON content_publications(state, format_version, operation_id);
