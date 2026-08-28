-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE version_reachability_scans
ADD COLUMN subject_digest BLOB CHECK (
    subject_digest IS NULL OR length(subject_digest) = 32
);
