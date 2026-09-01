-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE content_publications
ADD COLUMN volume_id BLOB NULL CHECK (volume_id IS NULL OR length(volume_id) = 16);

CREATE INDEX content_publications_by_volume
ON content_publications(volume_id, operation_id);
