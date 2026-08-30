-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE content_publications
ADD COLUMN import_header_digest BLOB NULL
CHECK (import_header_digest IS NULL OR length(import_header_digest) = 32);

ALTER TABLE content_publications
ADD COLUMN import_expected_root_digest BLOB NULL
CHECK (
    import_expected_root_digest IS NULL
    OR length(import_expected_root_digest) = 32
);
