-- SPDX-License-Identifier: GPL-2.0-only

-- Existing locks retain independent deadlines. Only an explicit new acquisition
-- can bind its lifetime to the handle; equal timestamps never imply that grant.
ALTER TABLE range_locks ADD COLUMN acquired_lease_expires_at INTEGER NOT NULL DEFAULT 0;
UPDATE range_locks SET acquired_lease_expires_at = lease_expires_at;
ALTER TABLE range_locks ADD COLUMN lock_lifetime INTEGER NOT NULL DEFAULT 1
    CHECK (lock_lifetime IN (1, 2));
