-- SPDX-License-Identifier: GPL-2.0-only

-- One schedule head exists per metadata partition. Immutable revisions preserve
-- the policy that produced each run, while the head provides a bounded due scan.
CREATE TABLE metadata_backup_schedule_revisions (
    partition_id BLOB NOT NULL REFERENCES metadata_partitions(partition_id) ON DELETE RESTRICT
        CHECK (length(partition_id) = 16),
    schedule_sequence INTEGER NOT NULL CHECK (schedule_sequence > 0),
    interval_micros INTEGER NOT NULL CHECK (interval_micros > 0),
    retained_generations INTEGER NOT NULL CHECK (retained_generations BETWEEN 1 AND 1024),
    minimum_verified_copies INTEGER NOT NULL
        CHECK (minimum_verified_copies BETWEEN 1 AND 255),
    minimum_independent_copies INTEGER NOT NULL CHECK (
        minimum_independent_copies BETWEEN 0 AND minimum_verified_copies
    ),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    next_due_at INTEGER NOT NULL,
    configured_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    configured_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (partition_id, schedule_sequence)
) WITHOUT ROWID, STRICT;

CREATE TABLE metadata_backup_schedule_heads (
    partition_id BLOB PRIMARY KEY REFERENCES metadata_partitions(partition_id) ON DELETE RESTRICT
        CHECK (length(partition_id) = 16),
    schedule_sequence INTEGER NOT NULL CHECK (schedule_sequence > 0),
    interval_micros INTEGER NOT NULL CHECK (interval_micros > 0),
    retained_generations INTEGER NOT NULL CHECK (retained_generations BETWEEN 1 AND 1024),
    minimum_verified_copies INTEGER NOT NULL
        CHECK (minimum_verified_copies BETWEEN 1 AND 255),
    minimum_independent_copies INTEGER NOT NULL CHECK (
        minimum_independent_copies BETWEEN 0 AND minimum_verified_copies
    ),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    next_due_at INTEGER NOT NULL,
    run_sequence INTEGER NOT NULL DEFAULT 0 CHECK (run_sequence >= 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    FOREIGN KEY (partition_id, schedule_sequence)
        REFERENCES metadata_backup_schedule_revisions(partition_id, schedule_sequence)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX metadata_backup_schedule_heads_due
ON metadata_backup_schedule_heads(enabled, next_due_at, partition_id);

-- A due occurrence is first made authoritative without claiming that any
-- snapshot or provider object exists. Later fenced execution advances this
-- state; one unfinished run prevents timer storms for a partition.
CREATE TABLE metadata_backup_runs (
    backup_id BLOB PRIMARY KEY CHECK (length(backup_id) = 16),
    partition_id BLOB NOT NULL REFERENCES metadata_partitions(partition_id) ON DELETE RESTRICT
        CHECK (length(partition_id) = 16),
    schedule_sequence INTEGER NOT NULL CHECK (schedule_sequence > 0),
    run_sequence INTEGER NOT NULL CHECK (run_sequence > 0),
    scheduled_for INTEGER NOT NULL,
    interval_micros INTEGER NOT NULL CHECK (interval_micros > 0),
    retained_generations INTEGER NOT NULL CHECK (retained_generations BETWEEN 1 AND 1024),
    minimum_verified_copies INTEGER NOT NULL
        CHECK (minimum_verified_copies BETWEEN 1 AND 255),
    minimum_independent_copies INTEGER NOT NULL CHECK (
        minimum_independent_copies BETWEEN 0 AND minimum_verified_copies
    ),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 5),
    operation_id BLOB NOT NULL UNIQUE CHECK (length(operation_id) = 16),
    created_at INTEGER NOT NULL,
    completed_at INTEGER,
    result_digest BLOB CHECK (result_digest IS NULL OR length(result_digest) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (partition_id, run_sequence),
    FOREIGN KEY (partition_id, schedule_sequence)
        REFERENCES metadata_backup_schedule_revisions(partition_id, schedule_sequence)
        ON DELETE RESTRICT,
    CHECK ((state IN (4, 5)) = (completed_at IS NOT NULL AND result_digest IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX one_unfinished_metadata_backup_run
ON metadata_backup_runs(partition_id)
WHERE state IN (1, 2, 3);

CREATE INDEX metadata_backup_runs_by_state
ON metadata_backup_runs(state, scheduled_for, backup_id);
