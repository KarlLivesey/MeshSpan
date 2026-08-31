-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE upload_sessions
ADD COLUMN authority_object_id BLOB CHECK (
    authority_object_id IS NULL OR length(authority_object_id) = 16
);
