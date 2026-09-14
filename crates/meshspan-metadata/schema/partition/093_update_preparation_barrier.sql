-- SPDX-License-Identifier: GPL-2.0-only

-- Preparing is staged bytes plus an immutable applied-log barrier, not a process restart.
-- Keep the existing phase encoding and all in-flight reservations intact.
ALTER TABLE update_rollout_nodes ADD COLUMN preparation_log_index INTEGER
    CHECK (preparation_log_index IS NULL OR preparation_log_index > 0);
CREATE UNIQUE INDEX update_rollout_nodes_one_preparation_or_restart
    ON update_rollout_nodes(rollout_id)
    WHERE restart_pending = 1 OR (phase = 2 AND preparation_log_index IS NOT NULL);
