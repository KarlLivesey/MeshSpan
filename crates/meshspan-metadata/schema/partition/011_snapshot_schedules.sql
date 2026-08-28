-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE snapshot_schedule_revisions (
    schedule_id BLOB NOT NULL CHECK (length(schedule_id) = 16),
    schedule_sequence INTEGER NOT NULL CHECK (schedule_sequence > 0),
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE CASCADE,
    interval_micros INTEGER NOT NULL CHECK (interval_micros > 0),
    retention_count INTEGER CHECK (retention_count IS NULL OR retention_count > 0),
    retention_duration_micros INTEGER CHECK (
        retention_duration_micros IS NULL OR retention_duration_micros > 0
    ),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    next_due_at INTEGER NOT NULL,
    configured_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    configured_at INTEGER NOT NULL,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0),
    PRIMARY KEY (schedule_id, schedule_sequence)
) STRICT;

CREATE TABLE snapshot_schedule_heads (
    schedule_id BLOB PRIMARY KEY CHECK (length(schedule_id) = 16),
    schedule_sequence INTEGER NOT NULL CHECK (schedule_sequence > 0),
    volume_id BLOB NOT NULL REFERENCES volumes(volume_id) ON DELETE CASCADE,
    interval_micros INTEGER NOT NULL CHECK (interval_micros > 0),
    retention_count INTEGER CHECK (retention_count IS NULL OR retention_count > 0),
    retention_duration_micros INTEGER CHECK (
        retention_duration_micros IS NULL OR retention_duration_micros > 0
    ),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    next_due_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    FOREIGN KEY (schedule_id, schedule_sequence)
        REFERENCES snapshot_schedule_revisions(schedule_id, schedule_sequence)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX snapshot_schedule_heads_due
ON snapshot_schedule_heads(enabled, next_due_at, schedule_id);

CREATE TABLE snapshot_schedule_runs (
    schedule_id BLOB NOT NULL CHECK (length(schedule_id) = 16),
    schedule_sequence INTEGER NOT NULL CHECK (schedule_sequence > 0),
    scheduled_for INTEGER NOT NULL,
    snapshot_id BLOB NOT NULL UNIQUE
        REFERENCES volume_snapshots(snapshot_id) ON DELETE RESTRICT,
    operation_id BLOB NOT NULL UNIQUE
        REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL UNIQUE CHECK (revision > 0),
    PRIMARY KEY (schedule_id, scheduled_for),
    FOREIGN KEY (schedule_id, schedule_sequence)
        REFERENCES snapshot_schedule_revisions(schedule_id, schedule_sequence)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX snapshot_schedule_runs_newest
ON snapshot_schedule_runs(schedule_id, scheduled_for DESC);
