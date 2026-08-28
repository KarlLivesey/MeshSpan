-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE volume_head_transitions (
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE CASCADE,
    head_sequence INTEGER NOT NULL CHECK (head_sequence > 0),
    previous_namespace_commit_id BLOB CHECK (
        previous_namespace_commit_id IS NULL OR length(previous_namespace_commit_id) = 16
    ),
    namespace_commit_id BLOB NOT NULL UNIQUE CHECK (length(namespace_commit_id) = 16),
    root_object_revision_id BLOB NOT NULL CHECK (length(root_object_revision_id) = 16),
    evidence_kind INTEGER NOT NULL CHECK (evidence_kind IN (1, 2)),
    source_operation_id BLOB NOT NULL UNIQUE CHECK (length(source_operation_id) = 16),
    source_request_digest BLOB NOT NULL CHECK (length(source_request_digest) = 32),
    causal_plan_digest BLOB CHECK (causal_plan_digest IS NULL OR length(causal_plan_digest) = 32),
    replay_plan_digest BLOB CHECK (replay_plan_digest IS NULL OR length(replay_plan_digest) = 32),
    source_result_digest BLOB NOT NULL CHECK (length(source_result_digest) = 32),
    metadata_operation_id BLOB NOT NULL UNIQUE
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED,
    committed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0),
    PRIMARY KEY (volume_id, head_sequence),
    CHECK ((head_sequence = 1) = (previous_namespace_commit_id IS NULL)),
    CHECK (previous_namespace_commit_id IS NULL OR previous_namespace_commit_id <> namespace_commit_id),
    CHECK (
        (evidence_kind = 1 AND causal_plan_digest IS NULL AND replay_plan_digest IS NULL)
        OR
        (evidence_kind = 2 AND causal_plan_digest IS NOT NULL AND replay_plan_digest IS NOT NULL)
    )
) STRICT;

CREATE INDEX volume_head_transitions_current
ON volume_head_transitions(volume_id, head_sequence DESC);
