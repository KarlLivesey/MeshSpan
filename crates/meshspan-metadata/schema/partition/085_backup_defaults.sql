-- SPDX-License-Identifier: GPL-2.0-only

-- Existing configuration is always treated as an explicit administrator choice.
-- Only the defaults command marks a configuration as automatically managed.
ALTER TABLE backup_destinations ADD COLUMN configuration_origin INTEGER NOT NULL
    DEFAULT 2 CHECK (configuration_origin IN (1, 2));
ALTER TABLE metadata_backup_schedule_heads ADD COLUMN configuration_origin INTEGER NOT NULL
    DEFAULT 2 CHECK (configuration_origin IN (1, 2));

CREATE INDEX backup_destination_defaults
ON backup_destinations(configuration_origin, state, destination_id);
CREATE INDEX backup_destination_target_binding
ON backup_destinations(target_id, provider_generation, configuration_origin);
CREATE INDEX storage_targets_backup_selection
ON storage_targets(state, host_id, target_id);

CREATE TABLE metadata_backup_defaults (
    partition_id BLOB PRIMARY KEY REFERENCES metadata_partitions(partition_id) ON DELETE RESTRICT,
    topology_revision INTEGER NOT NULL CHECK (topology_revision > 0),
    dirty INTEGER NOT NULL CHECK (dirty IN (0, 1)),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;
