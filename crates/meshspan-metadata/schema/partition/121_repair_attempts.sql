-- SPDX-License-Identifier: GPL-2.0-only

-- The typed, bounded command retains the original physical identity and the current
-- claim's exact control contexts. It is not evidence of a completed provider write.
CREATE TABLE maintenance_repair_attempts (
    work_id BLOB PRIMARY KEY REFERENCES maintenance_work_jobs(work_id) ON DELETE RESTRICT
        CHECK (length(work_id) = 16),
    provider_operation_id BLOB NOT NULL UNIQUE CHECK (length(provider_operation_id) = 16),
    effect_operation_id BLOB NOT NULL UNIQUE CHECK (length(effect_operation_id) = 16),
    completion_operation_id BLOB NOT NULL UNIQUE CHECK (length(completion_operation_id) = 16),
    plan_operation_id BLOB NOT NULL REFERENCES operations(operation_id)
        DEFERRABLE INITIALLY DEFERRED CHECK (length(plan_operation_id) = 16),
    command_version INTEGER NOT NULL CHECK (command_version = 20),
    command_bytes BLOB NOT NULL CHECK (length(command_bytes) BETWEEN 1 AND 1024),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;
