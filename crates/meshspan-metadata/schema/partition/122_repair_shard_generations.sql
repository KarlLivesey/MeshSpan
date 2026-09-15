-- SPDX-License-Identifier: GPL-2.0-only

-- Existing effects used the same physical generation at both ends. Preserve those receipts;
-- subsequent replacements can advance their physical fence without changing immutable bytes.
ALTER TABLE maintenance_repair_effects ADD COLUMN replacement_shard_generation INTEGER NOT NULL DEFAULT 1
    CHECK (replacement_shard_generation BETWEEN 1 AND 4294967295);
UPDATE maintenance_repair_effects SET replacement_shard_generation = shard_generation;

CREATE TABLE maintenance_repair_attempts_v21 (
    work_id BLOB PRIMARY KEY REFERENCES maintenance_work_jobs(work_id) ON DELETE RESTRICT
        CHECK (length(work_id) = 16),
    provider_operation_id BLOB NOT NULL UNIQUE CHECK (length(provider_operation_id) = 16),
    effect_operation_id BLOB NOT NULL UNIQUE CHECK (length(effect_operation_id) = 16),
    completion_operation_id BLOB NOT NULL UNIQUE CHECK (length(completion_operation_id) = 16),
    plan_operation_id BLOB NOT NULL REFERENCES operations(operation_id)
        DEFERRABLE INITIALLY DEFERRED CHECK (length(plan_operation_id) = 16),
    command_version INTEGER NOT NULL CHECK (command_version IN (20, 21)),
    command_bytes BLOB NOT NULL CHECK (length(command_bytes) BETWEEN 1 AND 1024),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

INSERT INTO maintenance_repair_attempts_v21 SELECT * FROM maintenance_repair_attempts;
DROP TABLE maintenance_repair_attempts;
ALTER TABLE maintenance_repair_attempts_v21 RENAME TO maintenance_repair_attempts;
