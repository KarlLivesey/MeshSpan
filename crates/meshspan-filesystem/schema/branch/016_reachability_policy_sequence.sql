-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE version_reachability_scans
ADD COLUMN retention_policy_sequence INTEGER CHECK (
    retention_policy_sequence IS NULL OR retention_policy_sequence > 0
);
