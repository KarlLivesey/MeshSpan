-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE adapter_file_create_plans
ADD COLUMN create_disposition INTEGER NOT NULL DEFAULT 2
CHECK (create_disposition IN (2, 3, 5));

ALTER TABLE adapter_file_create_plans
ADD COLUMN expected_existing_object_id BLOB NULL
CHECK (
    expected_existing_object_id IS NULL
    OR length(expected_existing_object_id) = 16
);
