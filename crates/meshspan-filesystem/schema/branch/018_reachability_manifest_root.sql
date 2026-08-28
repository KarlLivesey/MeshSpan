-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE version_reachability_scans
ADD COLUMN manifest_root_digest BLOB CHECK (
    manifest_root_digest IS NULL OR length(manifest_root_digest) = 32
);
