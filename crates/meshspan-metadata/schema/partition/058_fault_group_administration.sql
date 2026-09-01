-- SPDX-License-Identifier: GPL-2.0-only

-- The initial schema reserved canonical fault-group topology, but it predated
-- the administrator-facing display and lifecycle fields. Existing databases
-- cannot contain supported user-created rows because no command exposed them.
ALTER TABLE fault_group_classes ADD COLUMN display_name TEXT
    CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 128);
ALTER TABLE fault_group_classes ADD COLUMN class_kind INTEGER
    CHECK (class_kind IS NULL OR class_kind BETWEEN 1 AND 5);
ALTER TABLE fault_group_classes ADD COLUMN system_managed INTEGER
    CHECK (system_managed IS NULL OR system_managed IN (0, 1));

ALTER TABLE fault_groups ADD COLUMN display_name TEXT
    CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 256);
ALTER TABLE fault_groups ADD COLUMN state INTEGER
    CHECK (state IS NULL OR state BETWEEN 1 AND 3);

CREATE INDEX fault_groups_by_class_and_name
ON fault_groups(class_id, canonical_name, group_id);

CREATE INDEX host_fault_groups_by_host
ON host_fault_group_memberships(host_id, group_id);
