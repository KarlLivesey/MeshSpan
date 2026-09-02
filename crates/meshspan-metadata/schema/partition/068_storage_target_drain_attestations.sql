-- SPDX-License-Identifier: GPL-2.0-only

-- Every gateway that could have acknowledged a route before drain admission must prove its
-- converged local catalogue no longer names the target. The participant set is immutable.
CREATE TABLE storage_target_drain_participants (
    work_id BLOB NOT NULL REFERENCES storage_target_drains(work_id) ON DELETE RESTRICT
        CHECK (length(work_id) = 16),
    node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT
        CHECK (length(node_id) = 16),
    node_incarnation INTEGER NOT NULL CHECK (node_incarnation > 0),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    attestation_operation_id BLOB UNIQUE
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (attestation_operation_id IS NULL OR length(attestation_operation_id) = 16),
    observed_authority_revision INTEGER,
    empty_catalogue_digest BLOB
        CHECK (empty_catalogue_digest IS NULL OR length(empty_catalogue_digest) = 32),
    attested_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (work_id, node_id),
    CHECK (
        (state = 1 AND attestation_operation_id IS NULL
            AND observed_authority_revision IS NULL AND empty_catalogue_digest IS NULL
            AND attested_at IS NULL)
        OR
        (state = 2 AND attestation_operation_id IS NOT NULL
            AND observed_authority_revision IS NOT NULL AND empty_catalogue_digest IS NOT NULL
            AND attested_at IS NOT NULL)
    )
) STRICT;

CREATE INDEX storage_target_drain_participants_pending
ON storage_target_drain_participants(work_id, state, node_id);

-- The final attestation atomically creates the only effect which can terminally complete a drain.
CREATE TABLE storage_target_drain_effects (
    effect_operation_id BLOB PRIMARY KEY
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
        CHECK (length(effect_operation_id) = 16),
    work_id BLOB NOT NULL UNIQUE REFERENCES storage_target_drains(work_id) ON DELETE RESTRICT
        CHECK (length(work_id) = 16),
    participant_count INTEGER NOT NULL CHECK (participant_count > 0),
    safety_evidence_digest BLOB NOT NULL CHECK (length(safety_evidence_digest) = 32),
    committed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;
