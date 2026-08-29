-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE namespace_objects
ADD COLUMN stop_parent_grant_inheritance INTEGER NOT NULL DEFAULT 0
CHECK (stop_parent_grant_inheritance IN (0, 1));
