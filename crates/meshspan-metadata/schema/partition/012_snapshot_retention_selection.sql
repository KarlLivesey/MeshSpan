-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE snapshot_schedule_heads
ADD COLUMN run_sequence INTEGER NOT NULL DEFAULT 0 CHECK (run_sequence >= 0);

ALTER TABLE snapshot_schedule_runs
ADD COLUMN run_sequence INTEGER NOT NULL DEFAULT 0 CHECK (run_sequence >= 0);

UPDATE snapshot_schedule_runs AS current
SET run_sequence = (
    SELECT count(*)
    FROM snapshot_schedule_runs AS preceding
    WHERE preceding.schedule_id = current.schedule_id
      AND preceding.scheduled_for <= current.scheduled_for
);

UPDATE snapshot_schedule_heads
SET run_sequence = (
    SELECT count(*)
    FROM snapshot_schedule_runs
    WHERE snapshot_schedule_runs.schedule_id = snapshot_schedule_heads.schedule_id
);

CREATE UNIQUE INDEX snapshot_schedule_runs_by_sequence
ON snapshot_schedule_runs(schedule_id, run_sequence);

CREATE INDEX snapshot_expiry_by_revision
ON volume_snapshots(state, protected_from_expiry, revision, snapshot_id);
