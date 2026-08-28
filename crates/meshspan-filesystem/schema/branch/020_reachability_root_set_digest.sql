-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE version_reachability_scans
ADD COLUMN root_set_digest BLOB CHECK (
    root_set_digest IS NULL OR length(root_set_digest) = 32
);

CREATE INDEX version_cleanup_reference_fences_active_volume
ON version_cleanup_reference_fences(volume_id) WHERE state = 1;
