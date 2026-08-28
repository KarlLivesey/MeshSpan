-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE version_cleanup_intents
ADD COLUMN retained_root_set_digest BLOB CHECK (
    retained_root_set_digest IS NULL OR length(retained_root_set_digest) = 32
);
